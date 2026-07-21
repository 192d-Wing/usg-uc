package service

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
)

// End-to-end service round trip: a scripted "relay" connects, reads the
// sidecar's Hello, sends Start, runs the peer DTLS endpoint over the Dtls
// channel, and reads back Ready — whose SRTP keys must equal the ones the
// relay-side endpoint derived. Exercises the full protocol + handshake + key
// export path. Runs in the FIPS module under GODEBUG=fips140=on.
func TestSessionRoundTrip(t *testing.T) {
	sidecarID, err := dtlssession.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	relayPeerID, err := dtlssession.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	svcConn, relayConn := unixPair(t)

	// The sidecar service handles svcConn as the DTLS SERVER.
	svcErr := make(chan error, 1)
	go func() { svcErr <- HandleSession(svcConn, sidecarID) }()

	ft := ipc.NewFramedTransport(relayConn)

	// 1. Hello — the sidecar's fingerprint (for the SDP a=fingerprint).
	raw, err := recvWithin(t, ft, 10*time.Second)
	if err != nil {
		t.Fatalf("read Hello: %v", err)
	}
	typ, body, _ := splitFrame(raw)
	if typ != msgHello {
		t.Fatalf("want Hello, got type %d", typ)
	}
	if got := string(body); got != sidecarID.Fingerprint() {
		t.Fatalf("Hello fingerprint %q != %q", got, sidecarID.Fingerprint())
	}

	// 2. Start — tell the service to be SERVER and expect our fingerprint.
	if err := ft.SendFrame(encodeStart(dtlssession.RoleServer, relayPeerID.Fingerprint())); err != nil {
		t.Fatal(err)
	}

	// 3. Run the relay-side DTLS CLIENT; records flow as Dtls frames.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pc := ipc.NewPacketConn(dtlsChannel{ft})
	cres, err := dtlssession.Run(ctx, pc, pc.PeerAddr(), dtlssession.Params{
		Identity:        relayPeerID,
		Role:            dtlssession.RoleClient,
		PeerFingerprint: sidecarID.Fingerprint(),
	})
	if err != nil {
		t.Fatalf("relay-side client handshake: %v", err)
	}
	defer cres.Close()

	// 4. Read frames until Ready (skip trailing Dtls), then compare keys.
	var readyKeys []byte
	for {
		raw, err := recvWithin(t, ft, 10*time.Second)
		if err != nil {
			t.Fatalf("awaiting Ready: %v", err)
		}
		typ, body, _ := splitFrame(raw)
		switch typ {
		case msgDtls:
			continue // trailing handshake/close record
		case msgError:
			t.Fatalf("service returned error: %s", body)
		case msgReady:
			_, keys, derr := decodeReady(body)
			if derr != nil {
				t.Fatal(derr)
			}
			readyKeys = keys
		default:
			t.Fatalf("unexpected message type %d", typ)
		}
		break
	}

	if len(readyKeys) == 0 || string(readyKeys) != string(cres.SRTPKeys) {
		t.Fatal("service Ready SRTP keys differ from the relay-side keys")
	}
	if err := <-svcErr; err != nil {
		t.Fatalf("service session: %v", err)
	}
	t.Logf("PASS: service round-trip — %d-byte matching SRTP keys", len(readyKeys))
}

func recvWithin(t *testing.T, ft ipc.FrameTransport, d time.Duration) ([]byte, error) {
	t.Helper()
	_ = ft.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = ft.SetReadDeadline(time.Time{}) }()
	return ft.RecvFrame()
}

func unixPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "svc.sock")
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
		c, e := ln.Accept()
		accepted <- ac{c, e}
	}()
	dialed, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	a := <-accepted
	if a.err != nil {
		t.Fatalf("accept unix: %v", a.err)
	}
	t.Cleanup(func() { _ = dialed.Close(); _ = a.c.Close() })
	return a.c, dialed
}
