package dtlssession

import (
	"context"
	"crypto/ecdsa"
	stdelliptic "crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

// TestFIPSModeActive is the FIPS gate: this sidecar must be built with
// GOFIPS140 and run in FIPS mode so the crypto primitives come from the Go
// FIPS module (the DTLS record GCM seal is non-approved, POA&M-400).
// Run: GOFIPS140=v1.26.0 GODEBUG=fips140=on go test ./...
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

// CNSA 2.0 (SC-13): a peer that signs ServerKeyExchange with ECDSA/SHA-256
// over its P-384 key (pion's default, and what this sidecar did before
// SignatureSchemes was pinned) must be rejected, even with a matching
// fingerprint, suite and SRTP profile.
func TestDtlsSha256SignatureRejected(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	a, b := udpConn(t), udpConn(t)
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A raw pion server identical to Run's config except for the scheme.
	srv, err := dtls.Server(a, b.LocalAddr(), &dtls.Config{
		Certificates:           []tls.Certificate{serverID.cert},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_256_GCM},
		SignatureSchemes:       []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		ClientAuth:             dtls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
	})
	if err != nil {
		t.Fatalf("create SHA-256 server: %v", err)
	}
	defer srv.Close()
	go func() { _ = srv.HandshakeContext(ctx) }()

	res, err := Run(ctx, b, a.LocalAddr(), Params{
		Identity:        clientID,
		Role:            RoleClient,
		PeerFingerprint: serverID.Fingerprint(),
	})
	if err == nil {
		res.Close()
		t.Fatal("handshake must fail when the peer signs with ECDSA/SHA-256")
	}
	if ctx.Err() != nil {
		t.Fatalf("handshake timed out instead of rejecting the SHA-256 signature: %v", err)
	}
	t.Logf("correctly rejected SHA-256 signature: %v", err)
}

// outOfProfilePeer runs a raw pion client that follows the profile except for
// what mut changes, against Run as server, and returns Run's error. The pion
// client presents cert; Run is given its fingerprint, so the fingerprint is
// never what fails. A handshake that only fails by timing out is a test
// failure: the peer must be refused, not ignored.
func outOfProfilePeer(t *testing.T, cert tls.Certificate, mut func(c *dtls.Config)) error {
	t.Helper()
	err, _ := outOfProfilePeerBothErrors(t, cert, mut)
	return err
}

// outOfProfilePeerBothErrors is outOfProfilePeer that also returns what the
// raw pion client's own handshake ended with.
func outOfProfilePeerBothErrors(t *testing.T, cert tls.Certificate, mut func(c *dtls.Config)) (runErr, peerErr error) {
	t.Helper()

	serverID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a, b := udpConn(t), udpConn(t)
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_256_GCM},
		SignatureSchemes:       []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384},
		EllipticCurves:         []elliptic.Curve{elliptic.P384},
		InsecureSkipVerify:     true,
	}
	mut(cfg)
	cli, err := dtls.Client(b, a.LocalAddr(), cfg)
	if err != nil {
		t.Fatalf("create out-of-profile client: %v", err)
	}
	defer cli.Close()
	peerDone := make(chan error, 1)
	go func() { peerDone <- cli.HandshakeContext(ctx) }()

	res, err := Run(ctx, a, b.LocalAddr(), Params{
		Identity:        serverID,
		Role:            RoleServer,
		PeerFingerprint: sdpFingerprint(cert.Certificate[0]),
	})
	if err == nil {
		res.Close()
		return nil, <-peerDone
	}
	if ctx.Err() != nil {
		t.Fatalf("handshake timed out instead of refusing the peer: %v", err)
	}
	// The peer was refused; give its own handshake a moment to notice.
	select {
	case peerErr = <-peerDone:
	case <-time.After(3 * time.Second):
		peerErr = errPeerStillHandshaking
	}
	return err, peerErr
}

var errPeerStillHandshaking = errors.New("peer was still handshaking 3 s after the refusal")

// The helper itself must not be what fails: a peer inside the profile, built
// the same way, completes.
func TestDtlsInProfileRawPeerAccepted(t *testing.T) {
	id, _ := GenerateIdentity()
	if err := outOfProfilePeer(t, id.cert, func(*dtls.Config) {}); err != nil {
		t.Fatalf("in-profile raw pion peer was refused: %v", err)
	}
}

// CNSA 2.0 (SC-12/SC-13): ECDHE is P-384 only. A peer that supports only
// P-256 for the key exchange must be refused. pion as server follows the
// client's first group whatever EllipticCurves says, so this is what
// groupGuard is for. (An X25519-only pion client was observed to send no
// ClientHello at all under GODEBUG=fips140=on, so X25519 is covered from the
// server side and in the scanner test below.)
func TestDtlsP256KeyExchangeRejected(t *testing.T) {
	id, _ := GenerateIdentity()
	err := outOfProfilePeer(t, id.cert, func(c *dtls.Config) {
		c.EllipticCurves = []elliptic.Curve{elliptic.P256}
	})
	if err == nil {
		t.Fatal("handshake must fail with a P-256-only ECDHE peer")
	}
	t.Logf("correctly rejected P-256-only ECDHE peer: %v", err)
}

// SC-23: the extended master secret (RFC 7627) is required. A peer with EMS
// disabled must be refused; pion's default (request) would complete.
func TestDtlsPeerWithoutExtendedMasterSecretRejected(t *testing.T) {
	id, _ := GenerateIdentity()
	err := outOfProfilePeer(t, id.cert, func(c *dtls.Config) {
		c.ExtendedMasterSecret = dtls.DisableExtendedMasterSecret
	})
	if err == nil {
		t.Fatal("handshake must fail when the peer does not support the extended master secret")
	}
	t.Logf("correctly rejected peer without extended master secret: %v", err)
}

// CNSA 2.0 (SC-13 / IA-3): the peer certificate key must be ECDSA P-384. A
// peer with a P-256 certificate whose fingerprint was signalled, signing with
// SHA-384, must still be refused.
func TestDtlsP256CertificateRejected(t *testing.T) {
	key, err := ecdsa.GenerateKey(stdelliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "p256.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	err = outOfProfilePeer(t, cert, func(*dtls.Config) {})
	if err == nil {
		t.Fatal("handshake must fail when the peer certificate key is P-256")
	}
	t.Logf("correctly rejected P-256 certificate: %v", err)

	if err := requireP384Key([]byte{0x30, 0x00}); err == nil {
		t.Fatal("an unparsable certificate must be refused")
	}
}

// The same from the other side: as DTLS client pion accepts whatever group
// the server's ServerKeyExchange names, offered or not. A server that answers
// on P-256 or X25519 must never get a handshake with Run as client.
//
// RFC-014 / SEC-011: the inbound ServerKeyExchange is unauthenticated, so the
// guard drops it instead of aborting. The handshake therefore cannot
// complete and ends at the caller's deadline; Run's error names the reason.
func TestDtlsServerChoosingNonP384GroupRejected(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{
		"P-256":  elliptic.P256,
		"X25519": elliptic.X25519,
	} {
		serverID, _ := GenerateIdentity()
		clientID, _ := GenerateIdentity()
		a, b := udpConn(t), udpConn(t)

		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		// The server rewrites the client's supported_groups before pion
		// reads them, so pion builds its ServerKeyExchange on `curve`.
		srv, err := dtls.Server(&groupRewriter{PacketConn: a, to: uint16(curve)}, b.LocalAddr(), &dtls.Config{
			Certificates:            []tls.Certificate{serverID.cert},
			CipherSuites:            []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
			SRTPProtectionProfiles:  []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_256_GCM},
			SignatureSchemes:        []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384},
			ClientAuth:              dtls.RequireAnyClientCert,
			InsecureSkipVerify:      true,
			InsecureSkipVerifyHello: true,
		})
		if err != nil {
			t.Fatalf("create server: %v", err)
		}
		go func() { _ = srv.HandshakeContext(ctx) }()

		res, err := Run(ctx, b, a.LocalAddr(), Params{
			Identity:        clientID,
			Role:            RoleClient,
			PeerFingerprint: serverID.Fingerprint(),
		})
		if err == nil {
			res.Close()
			t.Fatalf("handshake must fail when the server picks %s", name)
		}
		if !errors.Is(err, errPeerGroupOutsideProfile) {
			t.Fatalf("%s: the failure does not name the dropped ServerKeyExchange: %v", name, err)
		}
		t.Logf("correctly rejected server-chosen %s: %v", name, err)
		cancel()
		srv.Close()
		a.Close()
		b.Close()
	}
}

// RFC-018: a context that never expires is refused, because as client an
// out-of-profile server is only ever refused at the deadline.
func TestRunRequiresADeadline(t *testing.T) {
	id, _ := GenerateIdentity()
	a, b := udpConn(t), udpConn(t)
	defer a.Close()
	defer b.Close()
	for _, role := range []Role{RoleServer, RoleClient} {
		res, err := Run(context.Background(), a, b.LocalAddr(), Params{Identity: id, Role: role, PeerFingerprint: id.Fingerprint()})
		if !errors.Is(err, errNoDeadline) {
			if res != nil {
				res.Close()
			}
			t.Fatalf("role %d: Run without a deadline = %v", role, err)
		}
	}
}

// groupRewriter makes a pion server believe the client listed group `to`
// first: it overwrites the first entry of supported_groups in an inbound
// ClientHello. Test-only; it assumes the profile's ClientHello layout.
type groupRewriter struct {
	net.PacketConn
	to uint16
}

func (g *groupRewriter) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := g.PacketConn.ReadFrom(p)
	if err != nil || n < 25 || p[0] != 22 || p[13] != 1 {
		return n, addr, err
	}
	// Find the supported_groups extension (type 10) holding exactly P-384:
	// 00 0a 00 04 00 02 00 18.
	want := []byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x18}
	for i := 25; i+len(want) <= n; i++ {
		if string(p[i:i+len(want)]) == string(want) {
			p[i+6] = byte(g.to >> 8)
			p[i+7] = byte(g.to)
			break
		}
	}
	return n, addr, err
}

// The scanner itself, on shaped input: only a ServerKeyExchange whose first
// three bytes arrive whole, in a fragment at offset 0, and name secp384r1 is
// inside the profile. Nothing here may panic.
func TestServerKeyExchangeGroupScanner(t *testing.T) {
	record := func(epoch uint16, fragments ...[]byte) []byte {
		var body []byte
		for _, f := range fragments {
			body = append(body, f...)
		}
		out := []byte{22, 0xfe, 0xfd, byte(epoch >> 8), byte(epoch), 0, 0, 0, 0, 0, 0, byte(len(body) >> 8), byte(len(body))}
		return append(out, body...)
	}
	fragment := func(msgType byte, offset int, data ...byte) []byte {
		out := []byte{msgType, 0, 0, 200, 0, 3, byte(offset >> 16), byte(offset >> 8), byte(offset), 0, byte(len(data) >> 8), byte(len(data))}
		return append(out, data...)
	}
	p384 := []byte{3, 0, 24, 97, 4}
	cases := []struct {
		name     string
		datagram []byte
		outside  bool
	}{
		{"P-384", record(0, fragment(12, 0, p384...)), false},
		{"P-256", record(0, fragment(12, 0, 3, 0, 23, 65, 4)), true},
		{"X25519", record(0, fragment(12, 0, 3, 0, 29, 32)), true},
		{"explicit curve type", record(0, fragment(12, 0, 1, 0, 24)), true},
		{"first bytes split", record(0, fragment(12, 0, 3, 0)), true},
		{"empty first fragment", record(0, fragment(12, 0)), true},
		{"fragment starting inside the prefix", record(0, fragment(12, 1, 0, 24, 97)), true},
		{"later fragment", record(0, fragment(12, 3, 97, 4)), false},
		{"P-384 then an overlapping P-256", record(0, fragment(12, 0, p384...), fragment(12, 0, 3, 0, 23)), true},
		{"second record", append(record(0, fragment(2, 0, 1, 2, 3)), record(0, fragment(12, 0, 3, 0, 23))...), true},
		{"other message", record(0, fragment(11, 0, 3, 0, 23)), false},
		{"epoch 1", record(1, fragment(12, 0, 3, 0, 23)), false},
		{"empty", nil, false},
		{"short record header", []byte{22, 0xfe, 0xfd, 0, 0}, false},
		{"record longer than the datagram", record(0, fragment(12, 0, 3, 0, 23))[:20], false},
		{"fragment longer than the record", record(0, fragment(12, 0, 3, 0, 23)[:13]), false},
	}
	for _, c := range cases {
		if got := serverKeyExchangeOutsideProfile(c.datagram); got != c.outside {
			t.Errorf("%s: outside=%v, want %v", c.name, got, c.outside)
		}
	}
	// Every truncation of a valid datagram is handled without panicking.
	full := append(record(0, fragment(2, 0, 9, 9), fragment(12, 0, p384...)), record(0, fragment(12, 0, 3, 0, 23))...)
	for cut := 0; cut <= len(full); cut++ {
		_ = serverKeyExchangeOutsideProfile(full[:cut])
	}
}
