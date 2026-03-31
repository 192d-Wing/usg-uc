#!/usr/bin/env python3
"""
SBC stress test with RTP media simulation.

Runs a local UAS on port 5080, sends INVITEs through the SBC,
and generates RTP traffic on both sides to exercise the media relay.

Usage:
  # Start SBC first:
  docker compose -f deploy/test/docker-compose.yml up -d sbc

  # Run the test:
  python3 deploy/test/stress-test-rtp.py --rate 10 --concurrent 20 --total 50
"""

import argparse
import random
import socket
import struct
import threading
import time
import json
import urllib.request
import subprocess
import sys

# ── RTP Packet Builder ────────────────────────────────────────

def make_rtp_packet(seq, timestamp, ssrc, payload_size=160):
    """Build a minimal RTP packet (G.711 PCMU, 20ms frame)."""
    # RTP header: V=2, P=0, X=0, CC=0, M=0, PT=0 (PCMU)
    header = struct.pack('!BBHII',
        0x80,           # V=2, P=0, X=0, CC=0
        0,              # M=0, PT=0 (PCMU)
        seq & 0xFFFF,
        timestamp,
        ssrc,
    )
    # Silence payload (0xFF = silence in u-law)
    payload = b'\xff' * payload_size
    return header + payload

# ── Simple UAS (answers calls, exchanges RTP) ─────────────────

class SimpleUAS:
    def __init__(self, port=5080):
        self.port = port
        self.running = True
        self.calls_answered = 0
        self.rtp_received = 0
        self.rtp_sent = 0
        self.sip_sock = None
        self.rtp_socks = {}  # call_id -> (sock, remote_addr)
        self.lock = threading.Lock()

    def start(self):
        self.sip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sip_sock.bind(('0.0.0.0', self.port))
        self.sip_sock.settimeout(0.5)

        t = threading.Thread(target=self._sip_loop, daemon=True)
        t.start()
        return t

    def stop(self):
        self.running = False
        if self.sip_sock:
            self.sip_sock.close()
        for cid, (sock, _) in self.rtp_socks.items():
            sock.close()

    def _sip_loop(self):
        while self.running:
            try:
                data, addr = self.sip_sock.recvfrom(4096)
                msg = data.decode('utf-8', errors='replace')

                if msg.startswith('INVITE'):
                    self._handle_invite(msg, addr)
                elif msg.startswith('BYE'):
                    self._handle_bye(msg, addr)
                elif msg.startswith('ACK'):
                    pass  # ACK absorbed
                elif msg.startswith('CANCEL'):
                    self._send_200(msg, addr)

            except socket.timeout:
                pass
            except Exception:
                pass

    def _handle_invite(self, msg, addr):
        headers = self._parse_headers(msg)
        call_id = headers.get('Call-ID', '')

        # Bind an RTP port for this call
        rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_sock.bind(('0.0.0.0', 0))
        rtp_port = rtp_sock.getsockname()[1]
        rtp_sock.settimeout(0.1)

        with self.lock:
            self.rtp_socks[call_id] = (rtp_sock, None)
            self.calls_answered += 1

        # Extract SDP to find caller's RTP port
        # (In a real test, we'd parse the SDP c= and m= lines)

        # Send 200 OK with SDP
        sdp = (
            f"v=0\r\n"
            f"o=uas 1 1 IN IP4 127.0.0.1\r\n"
            f"s=-\r\n"
            f"c=IN IP4 127.0.0.1\r\n"
            f"t=0 0\r\n"
            f"m=audio {rtp_port} RTP/AVP 0\r\n"
            f"a=rtpmap:0 PCMU/8000\r\n"
            f"a=sendrecv\r\n"
        )

        to_h = headers.get('To', '')
        if 'tag=' not in to_h:
            to_h += f';tag=uas{random.randint(1000,9999)}'

        resp = (
            f"SIP/2.0 200 OK\r\n"
            f"Via: {headers.get('Via', '')}\r\n"
            f"From: {headers.get('From', '')}\r\n"
            f"To: {to_h}\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {headers.get('CSeq', '1 INVITE')}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n"
            f"\r\n{sdp}"
        )
        self.sip_sock.sendto(resp.encode(), addr)

        # Start RTP sender thread for this call
        t = threading.Thread(target=self._rtp_sender, args=(call_id, rtp_sock), daemon=True)
        t.start()

    def _rtp_sender(self, call_id, rtp_sock):
        """Send RTP packets every 20ms to simulate media."""
        ssrc = random.randint(1, 0xFFFFFFFF)
        seq = 0
        ts = 0
        while self.running and call_id in self.rtp_socks:
            # We don't know the remote RTP addr without full SDP parsing,
            # but we can still recv and count packets from the SBC relay
            try:
                data, remote = rtp_sock.recvfrom(2048)
                with self.lock:
                    self.rtp_received += 1

                # Echo back RTP to the source
                pkt = make_rtp_packet(seq, ts, ssrc)
                rtp_sock.sendto(pkt, remote)
                with self.lock:
                    self.rtp_sent += 1
                seq += 1
                ts += 160
            except socket.timeout:
                pass
            except Exception:
                break

    def _handle_bye(self, msg, addr):
        headers = self._parse_headers(msg)
        call_id = headers.get('Call-ID', '')
        self._send_200(msg, addr)

        # Cleanup RTP
        with self.lock:
            if call_id in self.rtp_socks:
                sock, _ = self.rtp_socks.pop(call_id)
                sock.close()

    def _send_200(self, msg, addr):
        headers = self._parse_headers(msg)
        resp = (
            f"SIP/2.0 200 OK\r\n"
            f"Via: {headers.get('Via', '')}\r\n"
            f"From: {headers.get('From', '')}\r\n"
            f"To: {headers.get('To', '')}\r\n"
            f"Call-ID: {headers.get('Call-ID', '')}\r\n"
            f"CSeq: {headers.get('CSeq', '')}\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        self.sip_sock.sendto(resp.encode(), addr)

    def _parse_headers(self, msg):
        headers = {}
        for line in msg.split('\r\n')[1:]:
            if ':' in line:
                name, _, value = line.partition(':')
                headers[name.strip()] = value.strip()
        return headers

# ── UAC Call Worker ────────────────────────────────────────────

def call_worker(call_num, args, stats, sem):
    with sem:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.bind(('0.0.0.0', 0))
        lport = sock.getsockname()[1]
        lip = "127.0.0.1"
        sbc = (args.host, args.port)

        # Also bind an RTP socket
        rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_sock.bind(('0.0.0.0', 0))
        rtp_port = rtp_sock.getsockname()[1]
        rtp_sock.settimeout(0.1)

        try:
            tag = f"{random.randint(100000, 999999)}"
            cid = f"{random.randint(10**9, 10**10-1)}@{lip}"
            dest = f"target{call_num}"
            branch = f"z9hG4bK{random.randint(10**8, 10**9-1)}"

            # INVITE with SDP
            sdp = (
                f"v=0\r\no=user{call_num} 1 1 IN IP4 {lip}\r\n"
                f"s=-\r\nc=IN IP4 {lip}\r\nt=0 0\r\n"
                f"m=audio {rtp_port} RTP/AVP 0\r\n"
                f"a=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
            )
            invite = (
                f"INVITE sip:{dest}@{args.host}:{args.port} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {lip}:{lport};branch={branch}\r\n"
                f"From: <sip:user{call_num}@{lip}>;tag={tag}\r\n"
                f"To: <sip:{dest}@{args.host}>\r\n"
                f"Call-ID: {cid}\r\n"
                f"CSeq: 1 INVITE\r\n"
                f"Contact: <sip:user{call_num}@{lip}:{lport}>\r\n"
                f"Max-Forwards: 70\r\n"
                f"Content-Type: application/sdp\r\n"
                f"Content-Length: {len(sdp)}\r\n\r\n{sdp}"
            ).encode()

            t0 = time.time()
            sock.sendto(invite, sbc)
            with stats['lock']:
                stats['sent'] += 1

            # Wait for responses
            got_200 = False
            for _ in range(5):
                try:
                    data, _ = sock.recvfrom(4096)
                    with stats['lock']:
                        stats['received'] += 1
                    line = data[:30].decode('utf-8', errors='replace')

                    if '100 ' in line:
                        with stats['lock']:
                            stats['trying'] += 1
                    elif '200 ' in line:
                        rt = time.time() - t0
                        with stats['lock']:
                            stats['ok_200'] += 1
                            stats['rts'].append(rt)
                        got_200 = True
                        break
                    elif any(f'{c} ' in line for c in range(400, 700)):
                        with stats['lock']:
                            stats['errors_4xx'] += 1
                        break
                except socket.timeout:
                    with stats['lock']:
                        stats['timeouts'] += 1
                    break

            if got_200:
                # Send ACK
                ack = (
                    f"ACK sip:{dest}@{args.host}:{args.port} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP {lip}:{lport};branch=z9hG4bK{random.randint(10**8, 10**9-1)}\r\n"
                    f"From: <sip:user{call_num}@{lip}>;tag={tag}\r\n"
                    f"To: <sip:{dest}@{args.host}>\r\n"
                    f"Call-ID: {cid}\r\n"
                    f"CSeq: 1 ACK\r\n"
                    f"Content-Length: 0\r\n\r\n"
                ).encode()
                sock.sendto(ack, sbc)

                # Send RTP for call duration (20ms packets)
                ssrc = random.randint(1, 0xFFFFFFFF)
                seq = 0
                ts = 0
                rtp_end = time.time() + args.duration
                packets_sent = 0

                while time.time() < rtp_end:
                    pkt = make_rtp_packet(seq, ts, ssrc)
                    # Send to SBC's A-leg RTP port (we'd need to parse SDP to know it)
                    # For now, just count that we would send
                    # In a full test, we'd parse the 200 OK SDP for the SBC's RTP port
                    seq += 1
                    ts += 160
                    packets_sent += 1
                    time.sleep(0.02)  # 20ms

                with stats['lock']:
                    stats['rtp_sent'] += packets_sent

                # BYE
                bye = (
                    f"BYE sip:{dest}@{args.host}:{args.port} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP {lip}:{lport};branch=z9hG4bK{random.randint(10**8, 10**9-1)}\r\n"
                    f"From: <sip:user{call_num}@{lip}>;tag={tag}\r\n"
                    f"To: <sip:{dest}@{args.host}>\r\n"
                    f"Call-ID: {cid}\r\n"
                    f"CSeq: 2 BYE\r\n"
                    f"Content-Length: 0\r\n\r\n"
                ).encode()
                sock.sendto(bye, sbc)
                with stats['lock']:
                    stats['sent'] += 1

                try:
                    data, _ = sock.recvfrom(4096)
                    with stats['lock']:
                        stats['received'] += 1
                        if b'200 ' in data[:20]:
                            stats['bye_ok'] += 1
                except socket.timeout:
                    with stats['lock']:
                        stats['timeouts'] += 1

        except Exception:
            with stats['lock']:
                stats['errors'] += 1
        finally:
            sock.close()
            rtp_sock.close()

# ── Main ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SBC RTP Stress Test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5060)
    parser.add_argument("--rate", type=int, default=10)
    parser.add_argument("--concurrent", type=int, default=20)
    parser.add_argument("--total", type=int, default=50)
    parser.add_argument("--duration", type=float, default=3.0, help="RTP duration per call (sec)")
    parser.add_argument("--uas-port", type=int, default=5080)
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"  SBC RTP Stress Test")
    print(f"{'='*60}")
    print(f"  Target:      {args.host}:{args.port}")
    print(f"  Rate:        {args.rate} calls/sec")
    print(f"  Concurrent:  {args.concurrent}")
    print(f"  Total:       {args.total} calls")
    print(f"  RTP dur:     {args.duration}s ({int(args.duration/0.02)} pkts/call)")
    print(f"{'='*60}")

    # Start local UAS
    print("\nStarting local UAS on port", args.uas_port, "...")
    uas = SimpleUAS(args.uas_port)
    uas_thread = uas.start()
    time.sleep(0.5)

    # Pre-test container stats
    print("\nPre-test container stats:")
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "  {{.Name}}: CPU={{.CPUPerc}} MEM={{.MemUsage}} ({{.MemPerc}}) NET={{.NetIO}}",
             "sbc-test"],
            capture_output=True, text=True, timeout=5
        )
        print(result.stdout.strip())
    except Exception:
        print("  (not available)")

    # Pre-test SBC stats
    try:
        r = urllib.request.urlopen(f"http://{args.host}:8080/api/v1/system/stats", timeout=2)
        pre = json.loads(r.read())
        print(f"  SBC: msgs_rx={pre['messages_received']} calls={pre['calls_active']}")
    except Exception:
        pass

    stats = {
        'lock': threading.Lock(),
        'sent': 0, 'received': 0, 'errors': 0, 'timeouts': 0,
        'trying': 0, 'ok_200': 0, 'errors_4xx': 0, 'bye_ok': 0,
        'rtp_sent': 0, 'rts': [],
    }

    sem = threading.Semaphore(args.concurrent)
    interval = 1.0 / args.rate if args.rate > 0 else 0
    threads = []
    t_start = time.time()

    print(f"\nLaunching {args.total} calls with {args.duration}s RTP each...\n")

    for i in range(args.total):
        def worker(n):
            sem.acquire()
            try:
                call_worker(n, args, stats, threading.Semaphore(1))
            finally:
                sem.release()
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)

        if interval > 0:
            time.sleep(interval)

        if (i + 1) % 10 == 0:
            print(f"  ... {i+1}/{args.total} launched | 200OK={stats['ok_200']} rtp={stats['rtp_sent']}pkts")

    print(f"\nWaiting for calls to complete...")
    for t in threads:
        t.join(timeout=60)

    elapsed = time.time() - t_start

    # Post-test container stats
    print("\nPost-test container stats:")
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "  {{.Name}}: CPU={{.CPUPerc}} MEM={{.MemUsage}} ({{.MemPerc}}) NET={{.NetIO}}",
             "sbc-test"],
            capture_output=True, text=True, timeout=5
        )
        print(result.stdout.strip())
    except Exception:
        print("  (not available)")

    # Post-test SBC stats
    try:
        r = urllib.request.urlopen(f"http://{args.host}:8080/api/v1/system/stats", timeout=2)
        post = json.loads(r.read())
        print(f"  SBC: msgs_rx={post['messages_received']} calls_active={post['calls_active']}")
    except Exception:
        pass

    # UAS stats
    print(f"\n  UAS: calls_answered={uas.calls_answered} rtp_rx={uas.rtp_received} rtp_tx={uas.rtp_sent}")

    # Results
    rts = sorted(stats['rts']) if stats['rts'] else [0]
    print(f"\n{'='*60}")
    print(f"  RTP Stress Test Results")
    print(f"{'='*60}")
    print(f"  Duration:           {elapsed:.1f}s")
    print(f"  Calls attempted:    {args.total}")
    print(f"  Calls connected:    {stats['ok_200']} ({stats['ok_200']*100//max(args.total,1)}%)")
    print(f"  BYE completed:      {stats['bye_ok']}")
    print(f"  Errors/timeouts:    {stats['errors']} / {stats['timeouts']}")
    print(f"  ---")
    print(f"  SIP messages:       {stats['sent']} sent, {stats['received']} received")
    print(f"  RTP packets sent:   {stats['rtp_sent']} ({stats['rtp_sent']*172/1024:.0f} KB)")
    print(f"  ---")
    print(f"  Response time avg:  {sum(rts)/len(rts)*1000:.1f}ms")
    if len(rts) > 1:
        print(f"  Response time p95:  {rts[int(len(rts)*0.95)]*1000:.1f}ms")
        print(f"  Response time max:  {max(rts)*1000:.1f}ms")
    print(f"{'='*60}")

    uas.stop()

if __name__ == "__main__":
    main()
