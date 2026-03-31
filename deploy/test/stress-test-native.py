#!/usr/bin/env python3
"""
Native SIP stress test for USG SBC.

Sends concurrent REGISTER and INVITE requests via UDP.
Works on any platform (no SIPp dependency).

Usage:
  python3 deploy/test/stress-test-native.py [OPTIONS]
"""

import argparse
import random
import socket
import threading
import time
import sys
import json
import urllib.request
import subprocess

# ── SIP Message Builders ──────────────────────────────────────

def gen_branch():
    return f"z9hG4bK{random.randint(100000000, 999999999)}"

def gen_tag():
    return f"{random.randint(100000, 999999)}"

def gen_call_id(local_ip):
    return f"{random.randint(1000000000, 9999999999)}@{local_ip}"

def make_register(uid, lip, lport, host, port, branch, tag, cid):
    return (
        f"REGISTER sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {lip}:{lport};branch={branch}\r\n"
        f"From: <sip:user{uid}@{lip}>;tag={tag}\r\n"
        f"To: <sip:user{uid}@{host}>\r\n"
        f"Call-ID: {cid}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:user{uid}@{lip}:{lport}>\r\n"
        f"Max-Forwards: 70\r\n"
        f"Expires: 3600\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()

def make_invite(uid, dest, lip, lport, host, port, branch, tag, cid):
    sdp = (
        f"v=0\r\n"
        f"o=user{uid} {random.randint(1000,9999)} {random.randint(1000,9999)} IN IP4 {lip}\r\n"
        f"s=-\r\nc=IN IP4 {lip}\r\nt=0 0\r\n"
        f"m=audio {random.randint(10000,15000)} RTP/AVP 0 8\r\n"
        f"a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n"
    )
    return (
        f"INVITE sip:{dest}@{host}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {lip}:{lport};branch={branch}\r\n"
        f"From: <sip:user{uid}@{lip}>;tag={tag}\r\n"
        f"To: <sip:{dest}@{host}>\r\n"
        f"Call-ID: {cid}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Contact: <sip:user{uid}@{lip}:{lport}>\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: {len(sdp)}\r\n\r\n{sdp}"
    ).encode()

def make_bye(uid, dest, lip, lport, host, port, branch, tag, cid):
    return (
        f"BYE sip:{dest}@{host}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {lip}:{lport};branch={branch}\r\n"
        f"From: <sip:user{uid}@{lip}>;tag={tag}\r\n"
        f"To: <sip:{dest}@{host}>\r\n"
        f"Call-ID: {cid}\r\n"
        f"CSeq: 2 BYE\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()

# ── Thread-safe Stats ──────────────────────────────────────────

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.sent = 0
        self.received = 0
        self.errors = 0
        self.reg_ok = 0
        self.inv_trying = 0
        self.inv_ok = 0
        self.inv_4xx = 0
        self.bye_ok = 0
        self.timeouts = 0
        self.response_times = []
        self.start = time.time()

    def add_rt(self, rt):
        with self.lock:
            self.response_times.append(rt)

    def inc(self, field, n=1):
        with self.lock:
            setattr(self, field, getattr(self, field) + n)

    def report(self):
        elapsed = time.time() - self.start
        rts = sorted(self.response_times) if self.response_times else [0]
        avg = sum(rts) / len(rts) * 1000
        p50 = rts[len(rts)//2] * 1000
        p95 = rts[int(len(rts)*0.95)] * 1000
        p99 = rts[int(len(rts)*0.99)] * 1000

        print(f"\n{'='*60}")
        print(f"  SBC Stress Test Results")
        print(f"{'='*60}")
        print(f"  Duration:           {elapsed:.1f}s")
        print(f"  Messages sent:      {self.sent}")
        print(f"  Responses received: {self.received}")
        print(f"  Timeouts:           {self.timeouts}")
        print(f"  Errors:             {self.errors}")
        print(f"  ---")
        print(f"  REGISTER 200 OK:    {self.reg_ok}")
        print(f"  INVITE 100 Trying:  {self.inv_trying}")
        print(f"  INVITE 200/4xx:     {self.inv_ok} / {self.inv_4xx}")
        print(f"  BYE 200 OK:         {self.bye_ok}")
        print(f"  ---")
        print(f"  Response time avg:  {avg:.1f}ms")
        print(f"  Response time p50:  {p50:.1f}ms")
        print(f"  Response time p95:  {p95:.1f}ms")
        print(f"  Response time p99:  {p99:.1f}ms")
        print(f"  Response time max:  {max(rts)*1000:.1f}ms")
        print(f"  Throughput:         {self.sent / elapsed:.1f} msg/s")
        print(f"{'='*60}")

# ── Call Worker ────────────────────────────────────────────────

def call_worker(call_num, args, stats):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    sock.bind(('0.0.0.0', 0))
    lport = sock.getsockname()[1]
    lip = "127.0.0.1"
    sbc = (args.host, args.port)

    try:
        tag = gen_tag()
        cid = gen_call_id(lip)
        dest = f"target{call_num}"

        # REGISTER
        if args.register:
            msg = make_register(call_num, lip, lport, args.host, args.port, gen_branch(), tag, f"reg-{cid}")
            sock.sendto(msg, sbc)
            stats.inc('sent')
            try:
                data, _ = sock.recvfrom(4096)
                stats.inc('received')
                if b"200 " in data[:20]:
                    stats.inc('reg_ok')
            except socket.timeout:
                stats.inc('timeouts')

        # INVITE
        t0 = time.time()
        msg = make_invite(call_num, dest, lip, lport, args.host, args.port, gen_branch(), tag, cid)
        sock.sendto(msg, sbc)
        stats.inc('sent')

        # Collect responses
        got_final = False
        for _ in range(5):
            try:
                data, _ = sock.recvfrom(4096)
                stats.inc('received')
                rt = time.time() - t0
                line = data[:30].decode('utf-8', errors='replace')

                if "100 " in line:
                    stats.inc('inv_trying')
                elif "200 " in line:
                    stats.inc('inv_ok')
                    stats.add_rt(rt)
                    got_final = True
                    break
                elif any(f"{c} " in line for c in range(400, 700)):
                    stats.inc('inv_4xx')
                    stats.add_rt(rt)
                    got_final = True
                    break
            except socket.timeout:
                stats.inc('timeouts')
                break

        # Hold + BYE
        if got_final:
            time.sleep(args.duration)
            msg = make_bye(call_num, dest, lip, lport, args.host, args.port, gen_branch(), tag, cid)
            sock.sendto(msg, sbc)
            stats.inc('sent')
            try:
                data, _ = sock.recvfrom(4096)
                stats.inc('received')
                if b"200 " in data[:20]:
                    stats.inc('bye_ok')
            except socket.timeout:
                stats.inc('timeouts')

    except Exception as e:
        stats.inc('errors')
    finally:
        sock.close()

# ── Main ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SBC SIP Stress Test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5060)
    parser.add_argument("--rate", type=int, default=10, help="Calls/sec")
    parser.add_argument("--concurrent", type=int, default=50, help="Max concurrent")
    parser.add_argument("--total", type=int, default=200, help="Total calls")
    parser.add_argument("--duration", type=float, default=2.0, help="Hold time (sec)")
    parser.add_argument("--register", action="store_true", help="REGISTER before INVITE")
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"  SBC Stress Test — {args.total} calls @ {args.rate} CPS")
    print(f"  Target: {args.host}:{args.port}  Concurrent: {args.concurrent}")
    print(f"  Hold: {args.duration}s  Register: {args.register}")
    print(f"{'='*60}")

    # Pre-test stats
    try:
        r = urllib.request.urlopen(f"http://{args.host}:8080/api/v1/system/stats", timeout=2)
        pre = json.loads(r.read())
        print(f"\nPre-test:  msgs_rx={pre['messages_received']}  calls={pre['calls_total']}  regs={pre['registrations_total']}")
    except Exception:
        print("\n  (stats endpoint not available)")

    stats = Stats()
    sem = threading.Semaphore(args.concurrent)
    interval = 1.0 / args.rate if args.rate > 0 else 0
    threads = []

    print(f"\nLaunching {args.total} calls...\n")

    for i in range(args.total):
        sem.acquire()
        def worker(n):
            try:
                call_worker(n, args, stats)
            finally:
                sem.release()
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)

        if interval > 0:
            time.sleep(interval)

        if (i + 1) % 50 == 0:
            print(f"  ... {i+1}/{args.total} launched | sent={stats.sent} rx={stats.received} err={stats.errors}")

    print(f"\nWaiting for {len(threads)} calls to finish...")
    for t in threads:
        t.join(timeout=30)

    # Post-test stats
    try:
        r = urllib.request.urlopen(f"http://{args.host}:8080/api/v1/system/stats", timeout=2)
        post = json.loads(r.read())
        print(f"\nPost-test: msgs_rx={post['messages_received']}  calls={post['calls_total']}  regs={post['registrations_total']}")
    except Exception:
        pass

    stats.report()

    # Container resource usage
    print("\nContainer resource usage:")
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.PIDs}}",
             "sbc-test"],
            capture_output=True, text=True, timeout=5
        )
        print(result.stdout)
    except Exception:
        print("  (docker stats unavailable)")

if __name__ == "__main__":
    main()
