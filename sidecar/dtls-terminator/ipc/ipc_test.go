package ipc_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"errors"
	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
	"os"
)

// A full DTLS-SRTP handshake driven over the framed-UDS IPC PacketConn instead
// of a raw socket, proving dtlssession.Run runs unchanged over the relay
// channel. Two sidecars are cross-wired over one Unix-domain socket pair,
// standing in for "the Rust relay pumps DTLS records between the media socket
// and the sidecar".
func TestHandshakeOverFramedIPC(t *testing.T) {
	serverID, err := dtlssession.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := dtlssession.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	sConn, cConn := unixPair(t)
	sPC := ipc.NewPacketConn(ipc.NewFramedTransport(sConn))
	cPC := ipc.NewPacketConn(ipc.NewFramedTransport(cConn))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type out struct {
		res *dtlssession.Result
		err error
	}
	sch := make(chan out, 1)
	go func() {
		r, err := dtlssession.Run(ctx, sPC, sPC.PeerAddr(), dtlssession.Params{
			Identity:        serverID,
			Role:            dtlssession.RoleServer,
			PeerFingerprint: clientID.Fingerprint(),
		})
		sch <- out{r, err}
	}()

	cres, cerr := dtlssession.Run(ctx, cPC, cPC.PeerAddr(), dtlssession.Params{
		Identity:        clientID,
		Role:            dtlssession.RoleClient,
		PeerFingerprint: serverID.Fingerprint(),
	})
	if cerr != nil {
		t.Fatalf("client handshake over IPC: %v", cerr)
	}
	defer cres.Close()
	s := <-sch
	if s.err != nil {
		t.Fatalf("server handshake over IPC: %v", s.err)
	}
	defer s.res.Close()

	if len(cres.SRTPKeys) == 0 || string(cres.SRTPKeys) != string(s.res.SRTPKeys) {
		t.Fatal("SRTP keys derived over the IPC transport differ between endpoints")
	}
	t.Logf("PASS: DTLS-SRTP over framed IPC — %d-byte matching keys, profile=%v",
		len(cres.SRTPKeys), cres.Profile)
}

// SendFrame emits each length-prefixed frame as a single write that RecvFrame
// reads back intact and in order — guarding the framing against a header/payload
// split.
func TestFrameRoundTrip(t *testing.T) {
	sConn, cConn := unixPair(t)
	sender := ipc.NewFramedTransport(sConn)
	receiver := ipc.NewFramedTransport(cConn)
	defer sender.Close()
	defer receiver.Close()

	// A DTLS record header, a longer payload, and the 1-byte minimum frame.
	payloads := [][]byte{
		{0x16, 0xfe, 0xfd},
		[]byte("a longer dtls-ish record payload"),
		{0x01},
	}
	for _, p := range payloads {
		if err := sender.SendFrame(p); err != nil {
			t.Fatalf("SendFrame(%x): %v", p, err)
		}
	}
	for _, want := range payloads {
		got, err := receiver.RecvFrame()
		if err != nil {
			t.Fatalf("RecvFrame: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("frame mismatch: got %x want %x", got, want)
		}
	}
}

// unixPair returns the two ends of a connected Unix-domain stream socket.
func unixPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ipc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	type ac struct {
		c   net.Conn
		err error
	}
	accepted := make(chan ac, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- ac{c, err}
	}()

	dialed, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	a := <-accepted
	if a.err != nil {
		t.Fatalf("accept unix: %v", a.err)
	}
	t.Cleanup(func() {
		_ = dialed.Close()
		_ = a.c.Close()
	})
	return a.c, dialed
}

// A read deadline set while RecvFrame is already blocked applies to that
// call, as on a net.Conn. pion cancels a blocked read this way; without it
// a handshake with a silent peer could not be abandoned at its deadline.
func TestReadDeadlineWakesRecv(t *testing.T) {
	a, b := unixPair(t)
	defer a.Close()
	defer b.Close()
	ft := ipc.NewFramedTransport(a)
	defer ft.Close()

	got := make(chan error, 1)
	go func() {
		_, err := ft.RecvFrame()
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-got:
		t.Fatalf("RecvFrame returned early: %v", err)
	default:
	}
	_ = ft.SetReadDeadline(time.Unix(1, 0))
	select {
	case err := <-got:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("RecvFrame returned %v, want a deadline error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RecvFrame still blocked after the deadline was set")
	}

	// Clearing the deadline while blocked keeps the read waiting, and the
	// transport still delivers frames afterwards.
	_ = ft.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	go func() {
		f, err := ft.RecvFrame()
		if err == nil && string(f) != "frame" {
			err = errors.New("wrong frame")
		}
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = ft.SetReadDeadline(time.Time{})
	time.Sleep(200 * time.Millisecond)
	if err := ipc.NewFramedTransport(b).SendFrame([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	if err := <-got; err != nil {
		t.Fatalf("RecvFrame after the deadline was cleared: %v", err)
	}
}
