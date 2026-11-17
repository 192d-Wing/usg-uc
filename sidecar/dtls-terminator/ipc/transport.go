// Package ipc adapts the DTLS terminator's net.PacketConn to an inter-process
// channel to the Rust media relay. The relay owns the media UDP socket and
// demuxes DTLS records (first byte 20–63) onto this channel; the sidecar runs
// pion/dtls over the PacketConn from NewPacketConn and streams its handshake
// records back the same way.
//
// The transport is framing-agnostic (FrameTransport carries whole DTLS
// datagrams). This file implements the framed-stream backend — one big-endian
// uint16 length prefix per datagram over a net.Conn (a Unix-domain socket) —
// which also fits a gRPC bidi stream (swap the frame source). A datagram
// transport (unixgram) needs no framing and could implement FrameTransport
// trivially, or be handed to pion directly.
package ipc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// maxFrame bounds the IPC frame body ([type:1][record]) carried over the
// channel; it must match the Rust relay's MAX_FRAME. It is set above the relay's
// 4 KiB media recv buffer so a full-size DTLS record still fits once the 1-byte
// type tag is prepended (1 + 4096 = 4097). DTLS fragments handshake messages to
// a conservative MTU (~1200 bytes) in practice; the cap guards the per-frame
// allocation against a hostile/garbled length prefix.
const maxFrame = 8192

// FrameTransport carries whole DTLS datagrams between the sidecar and the Rust
// relay. Each frame is exactly one datagram.
type FrameTransport interface {
	// RecvFrame returns the next inbound datagram, blocking until one arrives,
	// the (read) deadline fires, or the transport is closed. A deadline set
	// while RecvFrame is blocked applies to that call too.
	RecvFrame() ([]byte, error)
	// SendFrame writes one outbound datagram.
	SendFrame([]byte) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

// framedConn is a FrameTransport over a stream net.Conn: each frame is a
// big-endian uint16 length prefix followed by the payload. A background reader
// decodes complete frames onto a channel so a read deadline never interrupts a
// partial frame (which would desync the length-prefixed stream) — the deadline
// is applied when selecting on the channel instead.
type framedConn struct {
	c       net.Conn
	writeMu sync.Mutex

	frames    chan []byte
	done      chan struct{}
	closeOnce sync.Once

	dlMu   sync.Mutex
	readDL time.Time
	// dlChanged is closed (and replaced) by SetReadDeadline, so that a
	// RecvFrame already blocked picks up the new deadline, as a read on a
	// net.Conn does.
	dlChanged chan struct{}

	errMu   sync.Mutex
	readErr error
}

// NewFramedTransport wraps a stream connection (Unix-domain socket, etc.) as a
// datagram frame transport and starts its background reader.
func NewFramedTransport(c net.Conn) FrameTransport {
	f := &framedConn{
		c:         c,
		frames:    make(chan []byte, 16),
		done:      make(chan struct{}),
		dlChanged: make(chan struct{}),
	}
	go f.readLoop()
	return f
}

func (f *framedConn) readLoop() {
	defer close(f.frames)
	for {
		frame, err := readOneFrame(f.c)
		if err != nil {
			f.errMu.Lock()
			f.readErr = err
			f.errMu.Unlock()
			return
		}
		select {
		case f.frames <- frame:
		case <-f.done:
			return
		}
	}
}

// readOneFrame reads exactly one length-prefixed frame (blocking, no deadline —
// framing must not be interrupted mid-frame).
func readOneFrame(c net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > maxFrame {
		return nil, fmt.Errorf("ipc: invalid frame length %d (max %d)", n, maxFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (f *framedConn) RecvFrame() ([]byte, error) {
	for {
		frame, again, err := f.recvOnce()
		if !again {
			return frame, err
		}
	}
}

// recvOnce waits for one frame under the read deadline in force when it is
// called. again reports that the deadline was changed meanwhile and the wait
// has to be redone under the new one.
func (f *framedConn) recvOnce() (frame []byte, again bool, err error) {
	f.dlMu.Lock()
	dl := f.readDL
	changed := f.dlChanged
	f.dlMu.Unlock()

	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return nil, false, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case frame, ok := <-f.frames:
		if !ok {
			f.errMu.Lock()
			err := f.readErr
			f.errMu.Unlock()
			if err == nil {
				err = io.EOF
			}
			return nil, false, err
		}
		return frame, false, nil
	case <-timeout:
		return nil, false, os.ErrDeadlineExceeded
	case <-changed:
		return nil, true, nil
	case <-f.done:
		return nil, false, net.ErrClosed
	}
}

func (f *framedConn) SendFrame(p []byte) error {
	if len(p) == 0 || len(p) > maxFrame {
		return fmt.Errorf("ipc: invalid frame length %d (max %d)", len(p), maxFrame)
	}
	// Marshal the length prefix and payload into one buffer and issue a single
	// Write. Two separate Writes could put the header on the wire and then fail
	// (a write deadline firing, or a transient error, between them), leaving the
	// peer's length-prefixed reader waiting for a payload that never comes —
	// desyncing the stream. One Write collapses that gap: a deadline now either
	// fails the whole frame or writes it whole.
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
	copy(frame[2:], p)

	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	_, err := f.c.Write(frame)
	// NIST 800-53 Rev5: SC-12 (best effort). One frame of a session carries
	// the exported SRTP keys (Ready); this copy of it is not left for the
	// garbage collector. Frames are handshake-rate, never media.
	clear(frame)
	return err
}

func (f *framedConn) SetReadDeadline(t time.Time) error {
	f.dlMu.Lock()
	f.readDL = t
	// Wake a RecvFrame that is already waiting. pion cancels a blocked read
	// this way (a deadline in the past, see netctx.ReadFromContext): without
	// the wake-up a handshake that ran into its deadline with a silent peer
	// would not return until the relay closed the connection.
	close(f.dlChanged)
	f.dlChanged = make(chan struct{})
	f.dlMu.Unlock()
	return nil
}

func (f *framedConn) SetWriteDeadline(t time.Time) error {
	return f.c.SetWriteDeadline(t)
}

func (f *framedConn) Close() error {
	f.closeOnce.Do(func() { close(f.done) })
	return f.c.Close()
}
