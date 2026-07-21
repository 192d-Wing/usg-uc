package ipc_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
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
