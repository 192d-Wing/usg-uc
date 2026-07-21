package dtlssession

import (
	"context"
	"crypto/fips140"
	"net"
	"testing"
	"time"
)

// TestFIPSModeActive is the FIPS gate: this sidecar must be built with
// GOFIPS140 and run in FIPS mode so every crypto primitive uses the certified
// Go module. Run: GOFIPS140=v1.26.0 GODEBUG=fips140=on go test ./...
func TestFIPSModeActive(t *testing.T) {
	if !fips140.Enabled() {
		t.Fatal("FIPS mode is not active — build with GOFIPS140=v1.26.0 " +
			"and run with GODEBUG=fips140=on")
	}
	t.Logf("FIPS module version %q", fips140.Version())
}

func udpConn(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return c
}

// The core proof: two DTLS-SRTP endpoints complete a real handshake, verify
// each other's fingerprint, and export IDENTICAL SRTP keys. Under
// GODEBUG=fips140=on this runs entirely in the Go FIPS module.
func TestDtlsSrtpMatchingKeys(t *testing.T) {
	t.Logf("fips140.Enabled=%v version=%q", fips140.Enabled(), fips140.Version())

	serverID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	a, b := udpConn(t), udpConn(t)
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type out struct {
		res *Result
		err error
	}
	sch := make(chan out, 1)
	go func() {
		r, err := Run(ctx, a, b.LocalAddr(), Params{
			Identity:        serverID,
			Role:            RoleServer,
			PeerFingerprint: clientID.Fingerprint(),
		})
		sch <- out{r, err}
	}()

	cres, cerr := Run(ctx, b, a.LocalAddr(), Params{
		Identity:        clientID,
		Role:            RoleClient,
		PeerFingerprint: serverID.Fingerprint(),
	})
	if cerr != nil {
		t.Fatalf("client handshake: %v", cerr)
	}
	defer cres.Close()
	s := <-sch
	if s.err != nil {
		t.Fatalf("server handshake: %v", s.err)
	}
	defer s.res.Close()

	if cres.Profile != s.res.Profile {
		t.Fatalf("SRTP profile mismatch: %v vs %v", cres.Profile, s.res.Profile)
	}
	if cres.Profile != AES256GCMProfile {
		t.Fatalf("unexpected SRTP profile %v", cres.Profile)
	}
	if len(cres.SRTPKeys) != srtpKeyLen {
		t.Fatalf("client SRTP keys len %d, want %d", len(cres.SRTPKeys), srtpKeyLen)
	}
	if string(cres.SRTPKeys) != string(s.res.SRTPKeys) {
		t.Fatal("client and server derived DIFFERENT SRTP keys")
	}
	t.Logf("PASS: matching %d-byte SRTP keys, profile=%v", len(cres.SRTPKeys), cres.Profile)
}

// A wrong expected peer fingerprint must abort the handshake.
func TestDtlsFingerprintMismatchFails(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()
	wrongID, _ := GenerateIdentity()

	a, b := udpConn(t), udpConn(t)
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		// Server expects the WRONG client fingerprint → must reject the peer.
		_, _ = Run(ctx, a, b.LocalAddr(), Params{
			Identity:        serverID,
			Role:            RoleServer,
			PeerFingerprint: wrongID.Fingerprint(),
		})
	}()

	_, err := Run(ctx, b, a.LocalAddr(), Params{
		Identity:        clientID,
		Role:            RoleClient,
		PeerFingerprint: serverID.Fingerprint(),
	})
	if err == nil {
		t.Fatal("handshake must fail when the peer fingerprint does not match")
	}
	t.Logf("correctly rejected mismatched fingerprint: %v", err)
}
