// Package service is the runnable DTLS-SRTP terminator: it accepts per-leg
// sessions from the Rust media relay over an IPC channel (a Unix-domain
// socket), runs the DTLS handshake in the FIPS module, and returns the exported
// SRTP keys for the relay to install in its SRTP contexts.
//
// Wire protocol (framed by ipc.FrameTransport; each message is [type:1][body]):
//
//	sidecar → relay : Hello{fingerprint}        (once, on connect)
//	relay → sidecar : Start{role, peerFP}       (begin the leg)
//	both            : Dtls{record}              (DTLS handshake records)
//	sidecar → relay : Ready{profile, srtpKeys}  (handshake complete)
//	sidecar → relay : Error{message}            (on failure)
package service

import (
	"encoding/binary"
	"fmt"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
)

type msgType byte

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

// Ready body: profile(2, big-endian) + SRTP keying material.
func encodeReady(profile uint16, keys []byte) []byte {
	body := make([]byte, 2+len(keys))
	binary.BigEndian.PutUint16(body[:2], profile)
	copy(body[2:], keys)
	return frame(msgReady, body)
}

func decodeReady(body []byte) (uint16, []byte, error) {
	if len(body) < 2 {
		return 0, nil, fmt.Errorf("short Ready message")
	}
	return binary.BigEndian.Uint16(body[:2]), body[2:], nil
}

func encodeError(msg string) []byte { return frame(msgError, []byte(msg)) }

// dtlsChannel adapts an ipc.FrameTransport to carry ONLY DTLS records, so
// ipc.NewPacketConn(dtlsChannel{ft}) drives the handshake over the same
// connection the control messages use: RecvFrame unwraps the next Dtls frame
// (a non-Dtls frame mid-handshake is a protocol error), SendFrame wraps a
// record as a Dtls frame. It implements ipc.FrameTransport.
type dtlsChannel struct{ inner ipc.FrameTransport }

func (d dtlsChannel) RecvFrame() ([]byte, error) {
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

func (d dtlsChannel) SendFrame(p []byte) error           { return d.inner.SendFrame(frame(msgDtls, p)) }
func (d dtlsChannel) SetReadDeadline(t time.Time) error  { return d.inner.SetReadDeadline(t) }
func (d dtlsChannel) SetWriteDeadline(t time.Time) error { return d.inner.SetWriteDeadline(t) }
func (d dtlsChannel) Close() error                       { return d.inner.Close() }
