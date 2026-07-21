package main

import (
	"context"
	"net"
	"testing"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
)

// Two peers handshake DTLS-SRTP directly (client ⇄ server) and exchange SRTP
// media, each recovering the other's packets. Validates the peer's handshake,
// key split, and SRTP protect/unprotect before it is used against the SBC.
func TestPeerLoopbackSRTP(t *testing.T) {
	clientID, err := dtlssession.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := dtlssession.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	sSock := mustUDP(t)
	cSock := mustUDP(t)
	sAddr := sSock.LocalAddr().(*net.UDPAddr)
	cAddr := cSock.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const n = 20
	type out struct {
		r   *PeerResult
		err error
	}
	sch := make(chan out, 1)
	go func() {
		r, e := RunPeer(ctx, dtlssession.RoleServer, sSock, cAddr, serverID, clientID.Fingerprint(), n, 0xAAAA, 800*time.Millisecond)
		sch <- out{r, e}
	}()
	cRes, cErr := RunPeer(ctx, dtlssession.RoleClient, cSock, sAddr, clientID, serverID.Fingerprint(), n, 0xBBBB, 800*time.Millisecond)
	if cErr != nil {
		t.Fatalf("client peer: %v", cErr)
	}
	s := <-sch
	if s.err != nil {
		t.Fatalf("server peer: %v", s.err)
	}

	if cRes.Sent != n || s.r.Sent != n {
		t.Fatalf("sent: client=%d server=%d (want %d)", cRes.Sent, s.r.Sent, n)
	}
	if cRes.Received == 0 || s.r.Received == 0 {
		t.Fatalf("no SRTP received: client=%d server=%d", cRes.Received, s.r.Received)
	}
	if cRes.Profile != 8 || s.r.Profile != 8 {
		t.Fatalf("profile: client=%d server=%d (want 8 = AEAD_AES_256_GCM)", cRes.Profile, s.r.Profile)
	}
	t.Logf("PASS: client recv %d/%d, server recv %d/%d, profile=8", cRes.Received, n, s.r.Received, n)
}

func mustUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
