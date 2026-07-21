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

// maxFrame bounds a single DTLS datagram carried over the channel. DTLS uses a
// conservative MTU (~1200 bytes); 4 KiB is generous headroom and caps the
// per-frame allocation against a hostile/garbled length prefix.
const maxFrame = 4096

// FrameTransport carries whole DTLS datagrams between the sidecar and the Rust
// relay. Each frame is exactly one datagram.
type FrameTransport interface {
	// RecvFrame returns the next inbound datagram, blocking until one arrives,
	// the (read) deadline fires, or the transport is closed.
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

	errMu   sync.Mutex
	readErr error
}

// NewFramedTransport wraps a stream connection (Unix-domain socket, etc.) as a
// datagram frame transport and starts its background reader.
func NewFramedTransport(c net.Conn) FrameTransport {
	f := &framedConn{
		c:      c,
		frames: make(chan []byte, 16),
		done:   make(chan struct{}),
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
	f.dlMu.Lock()
	dl := f.readDL
	f.dlMu.Unlock()

	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return nil, os.ErrDeadlineExceeded
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
			return nil, err
		}
		return frame, nil
	case <-timeout:
		return nil, os.ErrDeadlineExceeded
	case <-f.done:
		return nil, net.ErrClosed
	}
}

func (f *framedConn) SendFrame(p []byte) error {
	if len(p) == 0 || len(p) > maxFrame {
		return fmt.Errorf("ipc: invalid frame length %d (max %d)", len(p), maxFrame)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))

	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	if _, err := f.c.Write(hdr[:]); err != nil {
		return err
	}
	_, err := f.c.Write(p)
	return err
}

func (f *framedConn) SetReadDeadline(t time.Time) error {
	f.dlMu.Lock()
	f.readDL = t
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
