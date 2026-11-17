// Package service is the runnable DTLS-SRTP terminator: it accepts per-leg
// sessions from the Rust media relay over an IPC channel (a Unix-domain
// socket), runs the DTLS handshake in the FIPS module, and returns the exported
// SRTP keys for the relay to install in its SRTP contexts.
//
// Wire protocol (framed by ipc.FrameTransport; each message is [type:1][body]):
//
//	sidecar → relay : Hello{fingerprint}        (once, on connect)
//	relay → sidecar : Start{role, peerFP}       (begin the leg)
//	both            : Dtls{record}              (DTLS records, whole session)
//	sidecar → relay : Ready{profile, srtpKeys}  (handshake complete)
//	sidecar → relay : Error{message}            (handshake failed, or the
//	                                             association ended after Ready)
//
// Ready does not end the session. The DTLS association lives until the relay
// closes the connection (the call is over), and Dtls frames keep flowing in
// both directions until then: see HandleSession.
package service

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
)

type msgType byte

// contentTypeAlert is the DTLS record type of an alert (RFC 6347 §4.1).
const contentTypeAlert = 21

const (
	msgHello msgType = 1 // sidecar→relay: our SDP fingerprint
	msgStart msgType = 2 // relay→sidecar: role + peer fingerprint
	msgDtls  msgType = 3 // both: one DTLS record
	msgReady msgType = 4 // sidecar→relay: profile + exported SRTP keys
	msgError msgType = 5 // sidecar→relay: failure message
)

func frame(t msgType, body []byte) []byte {
	f := make([]byte, 1+len(body))
	f[0] = byte(t)
	copy(f[1:], body)
	return f
}

func splitFrame(raw []byte) (msgType, []byte, error) {
	if len(raw) == 0 {
		return 0, nil, fmt.Errorf("empty IPC frame")
	}
	return msgType(raw[0]), raw[1:], nil
}

func encodeHello(fingerprint string) []byte { return frame(msgHello, []byte(fingerprint)) }

// Start body: role(1) + peer fingerprint (UTF-8).
func encodeStart(role dtlssession.Role, peerFP string) []byte {
	body := make([]byte, 1+len(peerFP))
	body[0] = byte(role)
	copy(body[1:], peerFP)
	return frame(msgStart, body)
}

func decodeStart(body []byte) (dtlssession.Role, string, error) {
	if len(body) < 1 {
		return 0, "", fmt.Errorf("short Start message")
	}
	return dtlssession.Role(body[0]), string(body[1:]), nil
}

// Ready body: profile(2, big-endian) + SRTP keying material. Built in one
// buffer, so that the caller can wipe the only copy made here.
func encodeReady(profile uint16, keys []byte) []byte {
	f := make([]byte, 3+len(keys))
	f[0] = byte(msgReady)
	binary.BigEndian.PutUint16(f[1:3], profile)
	copy(f[3:], keys)
	return f
}

func decodeReady(body []byte) (uint16, []byte, error) {
	if len(body) < 2 {
		return 0, nil, fmt.Errorf("short Ready message")
	}
	return binary.BigEndian.Uint16(body[:2]), body[2:], nil
}

func encodeError(msg string) []byte { return frame(msgError, []byte(msg)) }

// dtlsChannel adapts an ipc.FrameTransport to carry ONLY DTLS records, so
// ipc.NewPacketConn(&dtlsChannel{inner: ft}) drives DTLS over the same
// connection the control messages use: RecvFrame unwraps the next Dtls frame
// (any other frame from the relay after Start is a protocol error), SendFrame
// wraps a record as a Dtls frame. It implements ipc.FrameTransport.
//
// It also remembers that the relay's side of the connection ended, which is
// how the session tells "the relay closed the connection" from "the peer
// closed the association" (pion reports both as io.EOF).
type dtlsChannel struct {
	inner ipc.FrameTransport

	mu      sync.Mutex
	recvErr error // first error of RecvFrame other than a deadline

	// alerts counts the alert records sent (the content type is readable in
	// the record header also when the record is protected).
	alerts atomic.Uint64
}

func (d *dtlsChannel) RecvFrame() ([]byte, error) {
	body, err := d.recvDtls()
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		d.mu.Lock()
		if d.recvErr == nil {
			d.recvErr = err
		}
		d.mu.Unlock()
	}
	return body, err
}

func (d *dtlsChannel) recvDtls() ([]byte, error) {
	raw, err := d.inner.RecvFrame()
	if err != nil {
		return nil, err
	}
	t, body, err := splitFrame(raw)
	if err != nil {
		return nil, err
	}
	if t != msgDtls {
		return nil, fmt.Errorf("expected Dtls frame, got type %d", t)
	}
	return body, nil
}

// relayEnded returns the error that ended the relay's side of the connection
// (io.EOF when the relay closed it), or nil while it is still readable.
func (d *dtlsChannel) relayEnded() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.recvErr
}

func (d *dtlsChannel) SendFrame(p []byte) error {
	if len(p) > 0 && p[0] == contentTypeAlert {
		d.alerts.Add(1)
	}
	return d.inner.SendFrame(frame(msgDtls, p))
}

// alertsSent returns how many alert records the DTLS endpoint has sent.
func (d *dtlsChannel) alertsSent() uint64 { return d.alerts.Load() }

func (d *dtlsChannel) SetReadDeadline(t time.Time) error  { return d.inner.SetReadDeadline(t) }
func (d *dtlsChannel) SetWriteDeadline(t time.Time) error { return d.inner.SetWriteDeadline(t) }

// Close does nothing: the connection belongs to the session (HandleSession
// closes it on return), not to the DTLS endpoint. pion closes its transport
// when a handshake fails and when the peer ends the association; in both
// cases the session still has a frame to send to the relay (Error), and at
// the end of a call the close_notify.
func (d *dtlsChannel) Close() error { return nil }
