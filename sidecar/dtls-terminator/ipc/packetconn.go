package ipc

import (
	"net"
	"time"
)

// peerAddr is a synthetic address for the remote DTLS peer. The real peer sits
// on the media socket owned by the Rust relay; over IPC its address is opaque,
// so pion only needs a stable non-nil Addr for its per-connection bookkeeping.
type peerAddr struct{}

func (peerAddr) Network() string { return "dtls-ipc" }
func (peerAddr) String() string  { return "dtls-ipc:peer" }

// PacketConn adapts a FrameTransport to net.PacketConn so pion/dtls can run
// over the IPC channel exactly as it would over a UDP socket. Each
// ReadFrom/WriteTo maps to one DTLS datagram frame.
type PacketConn struct {
	t    FrameTransport
	addr net.Addr
}

// NewPacketConn wraps a FrameTransport as a net.PacketConn.
func NewPacketConn(t FrameTransport) *PacketConn {
	return &PacketConn{t: t, addr: peerAddr{}}
}

// PeerAddr returns the synthetic remote address to pass to dtls.Server/Client
// as rAddr.
func (c *PacketConn) PeerAddr() net.Addr { return c.addr }

// ReadFrom returns the next inbound DTLS datagram. Like a UDP socket, a datagram
// larger than p is truncated to len(p); DTLS records fit the MTU so this does
// not occur in practice.
func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	frame, err := c.t.RecvFrame()
	if err != nil {
		return 0, nil, err
	}
	return copy(p, frame), c.addr, nil
}

// WriteTo sends one outbound DTLS datagram over the channel. addr is ignored:
// the IPC channel has a single implicit peer.
func (c *PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := c.t.SendFrame(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *PacketConn) Close() error        { return c.t.Close() }
func (c *PacketConn) LocalAddr() net.Addr { return c.addr }

func (c *PacketConn) SetReadDeadline(t time.Time) error  { return c.t.SetReadDeadline(t) }
func (c *PacketConn) SetWriteDeadline(t time.Time) error { return c.t.SetWriteDeadline(t) }

func (c *PacketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
