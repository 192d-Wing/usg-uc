// Command srtp-test-peer is a DTLS-SRTP media endpoint used to test the SBC's
// DTLS-SRTP termination end to end. It completes a real DTLS-SRTP handshake with
// the SBC relay's media port (reusing the sidecar's dtlssession for the
// handshake + key export), then sends and receives SRTP media (via pion/srtp).
//
// It is a test tool, not part of the FIPS product — hence its own module, so
// pion/srtp stays out of the FIPS sidecar's dependency tree.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

// AEAD_AES_256_GCM SRTP transform (RFC 7714) and the RFC 5764 exported-keying
// length: client_write_key || server_write_key || client_write_salt ||
// server_write_salt = 32+32+12+12.
const (
	srtpMasterKeyLen  = 32
	srtpMasterSaltLen = 12
	exportedKeyingLen = 2 * (srtpMasterKeyLen + srtpMasterSaltLen)
)

// isDTLS reports whether a packet's first byte marks a DTLS record (RFC 7983).
func isDTLS(b byte) bool { return b >= 20 && b <= 63 }

// isRTCP reports whether a demuxed (non-DTLS) media packet is RTCP rather than
// RTP, per RFC 5761: the payload-type byte (marker bit masked) falls in 64..=95.
// The header is cleartext in both SRTP and SRTCP.
func isRTCP(p []byte) bool { return len(p) >= 2 && p[1]&0x7f >= 64 && p[1]&0x7f <= 95 }

// PeerResult reports what one peer observed.
type PeerResult struct {
	Fingerprint  string
	Sent         int
	Received     int
	SentRTCP     int
	ReceivedRTCP int
	Profile      uint16
}

// demuxConn is a net.PacketConn over a UDP socket that yields ONLY DTLS records
// via ReadFrom (SRTP is routed elsewhere by the read pump) and writes to the
// fixed remote. It gives dtlssession.Run a DTLS-only channel while the peer
// handles SRTP media on the same socket.
type demuxConn struct {
	sock   *net.UDPConn
	remote *net.UDPAddr
	dtlsIn chan []byte

	dlMu sync.Mutex
	rdDL time.Time
}

func (d *demuxConn) ReadFrom(p []byte) (int, net.Addr, error) {
	d.dlMu.Lock()
	dl := d.rdDL
	d.dlMu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case rec, ok := <-d.dtlsIn:
		if !ok {
			return 0, d.remote, net.ErrClosed
		}
		return copy(p, rec), d.remote, nil
	case <-timeout:
		return 0, d.remote, os.ErrDeadlineExceeded
	}
}

func (d *demuxConn) WriteTo(p []byte, _ net.Addr) (int, error) { return d.sock.WriteToUDP(p, d.remote) }
func (d *demuxConn) Close() error                              { return nil } // socket owned by RunPeer
func (d *demuxConn) LocalAddr() net.Addr                       { return d.sock.LocalAddr() }
func (d *demuxConn) SetWriteDeadline(t time.Time) error        { return d.sock.SetWriteDeadline(t) }
func (d *demuxConn) SetReadDeadline(t time.Time) error {
	d.dlMu.Lock()
	d.rdDL = t
	d.dlMu.Unlock()
	return nil
}
func (d *demuxConn) SetDeadline(t time.Time) error {
	_ = d.SetReadDeadline(t)
	return d.SetWriteDeadline(t)
}

// splitKeys splits RFC 5764 exported keying material into this peer's
// (outbound, inbound) SRTP master key material by DTLS role: the client
// protects with the client_write_* values, the server with server_write_*.
func splitKeys(exported []byte, isClient bool) (outKey, outSalt, inKey, inSalt []byte) {
	clientKey, serverKey := exported[0:32], exported[32:64]
	clientSalt, serverSalt := exported[64:76], exported[76:88]
	if isClient {
		return clientKey, clientSalt, serverKey, serverSalt
	}
	return serverKey, serverSalt, clientKey, clientSalt
}

// sendRTCP encrypts and sends one muxed SRTCP Receiver Report to remote, using
// this peer's outbound SRTP context.
func sendRTCP(sock *net.UDPConn, remote *net.UDPAddr, out *srtp.Context, ssrc uint32) error {
	raw, err := (&rtcp.ReceiverReport{SSRC: ssrc}).Marshal()
	if err != nil {
		return fmt.Errorf("marshal rtcp: %w", err)
	}
	enc, err := out.EncryptRTCP(nil, raw, nil)
	if err != nil {
		return fmt.Errorf("encrypt rtcp: %w", err)
	}
	if _, err := sock.WriteToUDP(enc, remote); err != nil {
		return err
	}
	return nil
}

// RunPeer completes a DTLS-SRTP handshake with `remote` (the SBC relay's media
// port), then sends `count` SRTP RTP packets and counts the SRTP packets it
// receives back over `settle`. `role` is this peer's DTLS role; `peerFP` is the
// far side's SDP fingerprint (verified during the handshake). RunPeer owns and
// closes `sock`.
func RunPeer(ctx context.Context, role dtlssession.Role, sock *net.UDPConn, remote *net.UDPAddr, id *dtlssession.Identity, peerFP string, count int, ssrc uint32, settle time.Duration) (*PeerResult, error) {
	dtlsIn := make(chan []byte, 64)
	srtpIn := make(chan []byte, 512)
	dc := &demuxConn{sock: sock, remote: remote, dtlsIn: dtlsIn}

	// Read pump: demux the socket into DTLS (handshake) vs SRTP (media).
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, 2048)
		for {
			n, _, err := sock.ReadFromUDP(buf)
			if err != nil {
				close(dtlsIn)
				return
			}
			if n == 0 {
				continue
			}
			rec := append([]byte(nil), buf[:n]...)
			if isDTLS(rec[0]) {
				select {
				case dtlsIn <- rec:
				default:
				}
			} else {
				select {
				case srtpIn <- rec:
				default:
				}
			}
		}
	}()

	res, err := dtlssession.Run(ctx, dc, remote, dtlssession.Params{
		Identity:        id,
		Role:            role,
		PeerFingerprint: peerFP,
	})
	if err != nil {
		_ = sock.Close()
		<-pumpDone
		return nil, fmt.Errorf("dtls handshake: %w", err)
	}
	defer res.Close()

	if len(res.SRTPKeys) != exportedKeyingLen {
		_ = sock.Close()
		<-pumpDone
		return nil, fmt.Errorf("exported keying material %d bytes, want %d", len(res.SRTPKeys), exportedKeyingLen)
	}

	outKey, outSalt, inKey, inSalt := splitKeys(res.SRTPKeys, role == dtlssession.RoleClient)
	outCtx, err := srtp.CreateContext(outKey, outSalt, srtp.ProtectionProfileAeadAes256Gcm)
	if err != nil {
		return nil, fmt.Errorf("srtp out context: %w", err)
	}
	inCtx, err := srtp.CreateContext(inKey, inSalt, srtp.ProtectionProfileAeadAes256Gcm)
	if err != nil {
		return nil, fmt.Errorf("srtp in context: %w", err)
	}

	result := &PeerResult{Fingerprint: id.Fingerprint(), Profile: uint16(res.Profile)}

	// Receiver: decrypt inbound media until the socket closes, demuxing SRTP
	// media from muxed SRTCP (RFC 5761) so each is unprotected with the right
	// transform — this is what validates the SBC's SRTCP re-protect.
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for rec := range srtpIn {
			if isRTCP(rec) {
				if _, derr := inCtx.DecryptRTCP(nil, rec, nil); derr == nil {
					result.ReceivedRTCP++
				}
			} else if _, derr := inCtx.DecryptRTP(nil, rec, nil); derr == nil {
				result.Received++
			}
		}
	}()

	// Sender: encrypt + send `count` RTP packets, paced so the relay can keep up.
	payload := []byte("SBC-DTLS-SRTP-terminate-audio-frame")
	for seq := 0; seq < count; seq++ {
		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    0,
				SequenceNumber: uint16(seq),
				Timestamp:      uint32(seq) * 160,
				SSRC:           ssrc,
			},
			Payload: payload,
		}
		raw, merr := pkt.Marshal()
		if merr != nil {
			return nil, merr
		}
		enc, eerr := outCtx.EncryptRTP(nil, raw, nil)
		if eerr != nil {
			return nil, fmt.Errorf("encrypt rtp: %w", eerr)
		}
		if _, werr := sock.WriteToUDP(enc, remote); werr != nil {
			return nil, werr
		}
		result.Sent++

		// Interleave a muxed SRTCP Receiver Report every 10 packets so the SBC's
		// SRTCP re-protect path (RFC 7714 §9.4) is exercised alongside SRTP.
		if seq%10 == 9 {
			if err := sendRTCP(sock, remote, outCtx, ssrc); err != nil {
				return nil, err
			}
			result.SentRTCP++
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Let the far side echo/relay, then tear down: closing the socket stops the
	// pump (which closes dtlsIn); then close srtpIn to end the receiver.
	select {
	case <-ctx.Done():
	case <-time.After(settle):
	}
	_ = sock.Close()
	<-pumpDone
	close(srtpIn)
	<-recvDone
	return result, nil
}
