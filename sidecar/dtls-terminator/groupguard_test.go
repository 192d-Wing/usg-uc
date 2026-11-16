package dtlssession

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

// testRecord builds one epoch-`epoch` handshake record from fragments.
func testRecord(epoch uint16, seq byte, fragments ...[]byte) []byte {
	var body []byte
	for _, f := range fragments {
		body = append(body, f...)
	}
	out := []byte{22, 0xfe, 0xfd, byte(epoch >> 8), byte(epoch), 0, 0, 0, 0, 0, seq, byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// testFragment builds one handshake fragment of a 200-byte message with
// message_seq 9 (far ahead of anything a handshake under test expects).
func testFragment(msgType byte, offset int, data ...byte) []byte {
	out := []byte{msgType, 0, 0, 200, 0, 9, byte(offset >> 16), byte(offset >> 8), byte(offset), 0, byte(len(data) >> 8), byte(len(data))}
	return append(out, data...)
}

// A forged ServerKeyExchange fragment on P-256, as a whole 28-byte datagram
// with record sequence number seq.
func forgedP256KeyExchange(seq byte) []byte {
	return testRecord(0, seq, testFragment(typeServerKeyExchange, 0, 3, 0, 23))
}

// scriptConn is a PacketConn stub: ReadFrom hands out the queued datagrams,
// WriteTo records what was written.
type scriptConn struct {
	net.PacketConn
	mu      sync.Mutex
	inbound [][]byte
	written [][]byte
}

func (c *scriptConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.inbound) == 0 {
		return 0, nil, net.ErrClosed
	}
	n := copy(p, c.inbound[0])
	c.inbound = c.inbound[1:]
	return n, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, nil
}

func (c *scriptConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, append([]byte(nil), p...))
	return len(p), nil
}

// RFC-014 / SEC-011: the read path is role-aware and never aborts. As client
// an out-of-profile ServerKeyExchange datagram is dropped and counted; as
// server it is none of the guard's business and passes to pion untouched.
func TestGuardReadPathDropsWithoutAborting(t *testing.T) {
	good := testRecord(0, 1, testFragment(typeServerKeyExchange, 0, 3, 0, 24, 97, 4))
	other := testRecord(0, 2, testFragment(2, 0, 1, 2, 3))
	for _, client := range []bool{true, false} {
		aborted := false
		conn := &scriptConn{inbound: [][]byte{forgedP256KeyExchange(5), good, forgedP256KeyExchange(5), other}}
		g := newGroupGuard(conn, client, func() { aborted = true })
		var got [][]byte
		buf := make([]byte, 2048)
		for {
			n, _, err := g.ReadFrom(buf)
			if err != nil {
				break
			}
			got = append(got, append([]byte(nil), buf[:n]...))
		}
		wantDelivered, wantDropped := 4, uint32(0)
		if client {
			wantDelivered, wantDropped = 2, 2
		}
		if len(got) != wantDelivered || g.dropped.Load() != wantDropped {
			t.Errorf("client=%v: delivered %d dropped %d, want %d and %d", client, len(got), g.dropped.Load(), wantDelivered, wantDropped)
		}
		if client && (string(got[0]) != string(good) || string(got[1]) != string(other)) {
			t.Errorf("client: the in-profile datagrams were not delivered unchanged")
		}
		if aborted || g.tripped.Load() {
			t.Errorf("client=%v: an inbound datagram aborted the handshake", client)
		}

		// Disarmed: nothing is inspected.
		conn.inbound = [][]byte{forgedP256KeyExchange(5)}
		g.disarm()
		if n, _, err := g.ReadFrom(buf); err != nil || n == 0 {
			t.Errorf("client=%v: disarmed guard did not pass the datagram (%d, %v)", client, n, err)
		}
	}
}

// The write path: our own out-of-profile message is withheld, the peer gets
// exactly one fatal handshake_failure alert carrying the withheld record's
// sequence number, and the handshake is aborted. Which message is checked
// depends on the role (NIST-014, RFC-014).
func TestGuardWritePathWithholdsAlertsAndAborts(t *testing.T) {
	p256SKE := forgedP256KeyExchange(77)
	sha256CV := testRecord(0, 78, testFragment(typeCertificateVerify, 0, 4, 3, 0, 96))
	p384SKE := testRecord(0, 3, testFragment(typeServerKeyExchange, 0, 3, 0, 24, 97, 4))
	sha384CV := testRecord(0, 4, testFragment(typeCertificateVerify, 0, 5, 3, 0, 96))
	cases := []struct {
		name     string
		client   bool
		datagram []byte
		withheld bool
	}{
		{"server, ServerKeyExchange on P-256", false, p256SKE, true},
		{"server, ServerKeyExchange on P-384", false, p384SKE, false},
		{"server, CertificateVerify is not ours to send", false, sha256CV, false},
		{"client, CertificateVerify with SHA-256", true, sha256CV, true},
		{"client, CertificateVerify with SHA-384", true, sha384CV, false},
		{"client, ServerKeyExchange is not ours to send", true, p256SKE, false},
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	for _, c := range cases {
		aborts := 0
		conn := &scriptConn{}
		g := newGroupGuard(conn, c.client, func() { aborts++ })
		// Twice: a retransmission is withheld too, without a second alert.
		for i := 0; i < 2; i++ {
			if n, err := g.WriteTo(c.datagram, addr); err != nil || n != len(c.datagram) {
				t.Fatalf("%s: WriteTo = %d, %v", c.name, n, err)
			}
		}
		if !c.withheld {
			if len(conn.written) != 2 || string(conn.written[0]) != string(c.datagram) || aborts != 0 || g.tripped.Load() {
				t.Errorf("%s: not passed through untouched (written %d, aborts %d)", c.name, len(conn.written), aborts)
			}
			continue
		}
		seq := c.datagram[10]
		wantAlert := []byte{21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, seq, 0, 2, 2, 40}
		if len(conn.written) != 1 || string(conn.written[0]) != string(wantAlert) {
			t.Errorf("%s: wrote %x, want one alert %x", c.name, conn.written, wantAlert)
		}
		if aborts != 1 || !g.tripped.Load() {
			t.Errorf("%s: aborts=%d tripped=%v", c.name, aborts, g.tripped.Load())
		}
		// RFC-017: once tripped nothing follows the alert, neither another
		// datagram of the same flight nor anything after disarm.
		rest := testRecord(0, 80, testFragment(14, 0))
		for _, disarm := range []bool{false, true} {
			if disarm {
				g.disarm()
			}
			if n, err := g.WriteTo(rest, addr); err != nil || n != len(rest) {
				t.Fatalf("%s: WriteTo after the trip = %d, %v", c.name, n, err)
			}
		}
		if len(conn.written) != 1 {
			t.Errorf("%s: %d datagrams on the wire after the trip, want only the alert", c.name, len(conn.written))
		}
	}
}

// The CertificateVerify scanner on shaped input (same rules as the
// ServerKeyExchange one, two-byte prefix). Nothing here may panic.
func TestCertificateVerifySchemeScanner(t *testing.T) {
	cases := []struct {
		name     string
		datagram []byte
		outside  bool
	}{
		{"ECDSA/SHA-384", testRecord(0, 0, testFragment(15, 0, 5, 3, 0, 96)), false},
		{"ECDSA/SHA-256", testRecord(0, 0, testFragment(15, 0, 4, 3, 0, 96)), true},
		{"ECDSA/SHA-512", testRecord(0, 0, testFragment(15, 0, 6, 3)), true},
		{"RSA/SHA-384", testRecord(0, 0, testFragment(15, 0, 5, 1)), true},
		{"scheme split", testRecord(0, 0, testFragment(15, 0, 5)), true},
		{"empty first fragment", testRecord(0, 0, testFragment(15, 0)), true},
		{"fragment starting inside the scheme", testRecord(0, 0, testFragment(15, 1, 3, 0)), true},
		{"later fragment", testRecord(0, 0, testFragment(15, 2, 0, 96)), false},
		{"after other messages", testRecord(0, 0, testFragment(11, 0, 4, 3), testFragment(16, 0, 4, 3), testFragment(15, 0, 4, 3)), true},
		{"other message", testRecord(0, 0, testFragment(12, 0, 4, 3, 0)), false},
		{"epoch 1", testRecord(1, 0, testFragment(15, 0, 4, 3)), false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got := certificateVerifyOutsideProfile(c.datagram); got != c.outside {
			t.Errorf("%s: outside=%v, want %v", c.name, got, c.outside)
		}
	}
	full := append(testRecord(0, 0, testFragment(11, 0, 9, 9), testFragment(15, 0, 5, 3)), testRecord(0, 1, testFragment(15, 0, 4, 3))...)
	for cut := 0; cut <= len(full); cut++ {
		_ = certificateVerifyOutsideProfile(full[:cut])
	}
}

// injectConn delivers one forged datagram, as if from the peer, right after
// the first genuine datagram.
type injectConn struct {
	net.PacketConn
	forged   []byte
	state    atomic.Int32 // 0: nothing read yet, 1: inject next, 2: done
	lastAddr atomic.Value
}

func (c *injectConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.state.CompareAndSwap(1, 2) {
		return copy(p, c.forged), c.lastAddr.Load().(net.Addr), nil
	}
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && c.state.CompareAndSwap(0, 1) {
		c.lastAddr.Store(addr)
	}
	return n, addr, err
}

// RFC-014 / SEC-011: one spoofed 28-byte datagram with a P-256
// "ServerKeyExchange" fragment must not end a handshake between two peers
// inside the profile, whichever role the sidecar has. As server the guard
// does not look at inbound ServerKeyExchange at all; as client it drops the
// datagram and carries on with the genuine one.
func TestDtlsSpoofedKeyExchangeDoesNotAbortHandshake(t *testing.T) {
	for _, spoofed := range []Role{RoleServer, RoleClient} {
		serverID, _ := GenerateIdentity()
		clientID, _ := GenerateIdentity()
		a, b := udpConn(t), udpConn(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

		var serverConn, clientConn net.PacketConn = a, b
		// Record sequence number 0, like the reviewer's probe. A higher one
		// moves pion's own epoch-0 replay window (64 records, conn.go:37)
		// past the genuine records: the window is checked before any
		// authentication (conn.go:1063-1071) and a plaintext handshake
		// record that parses is marked valid (conn.go:1152). That is pion's
		// exposure (POA&M-335), not the guard's; with 77 the server-role
		// handshake was seen to time out.
		inject := &injectConn{forged: forgedP256KeyExchange(0)}
		if spoofed == RoleServer {
			inject.PacketConn = a
			serverConn = inject
		} else {
			inject.PacketConn = b
			clientConn = inject
		}

		type out struct {
			res *Result
			err error
		}
		sch := make(chan out, 1)
		go func() {
			r, err := Run(ctx, serverConn, b.LocalAddr(), Params{Identity: serverID, Role: RoleServer, PeerFingerprint: clientID.Fingerprint()})
			sch <- out{r, err}
		}()
		cres, cerr := Run(ctx, clientConn, a.LocalAddr(), Params{Identity: clientID, Role: RoleClient, PeerFingerprint: serverID.Fingerprint()})
		s := <-sch
		if cerr != nil || s.err != nil {
			t.Fatalf("spoofed role %d: client err %v, server err %v", spoofed, cerr, s.err)
		}
		if inject.state.Load() != 2 {
			t.Fatalf("spoofed role %d: the forged datagram was never injected", spoofed)
		}
		if string(cres.SRTPKeys) != string(s.res.SRTPKeys) || len(cres.SRTPKeys) != srtpKeyLen {
			t.Fatalf("spoofed role %d: keys differ", spoofed)
		}
		cres.Close()
		s.res.Close()
		cancel()
		a.Close()
		b.Close()
	}
}

// schemeRewriter sits under a raw pion SERVER. Outbound it rewrites the
// CertificateRequest's supported_signature_algorithms from ecdsa/sha384
// (05 03) to ecdsa/sha256 (04 03); inbound it records the scheme of every
// CertificateVerify that reaches the wire.
type schemeRewriter struct {
	net.PacketConn
	rewrote atomic.Bool
	mu      sync.Mutex
	schemes [][2]byte
	alerts  [][2]byte
}

func walkHandshake(d []byte, f func(msgType byte, offset int, fragment []byte)) {
	for len(d) >= recordHeaderLen {
		l := int(d[11])<<8 | int(d[12])
		if l > len(d)-recordHeaderLen {
			return
		}
		body := d[recordHeaderLen : recordHeaderLen+l]
		contentType, epoch := d[0], int(d[3])<<8|int(d[4])
		d = d[recordHeaderLen+l:]
		if contentType != contentTypeHandshake || epoch != 0 {
			continue
		}
		for len(body) >= handshakeHeaderLen {
			fl := uint24(body[9:12])
			if fl > len(body)-handshakeHeaderLen {
				break
			}
			f(body[0], uint24(body[6:9]), body[handshakeHeaderLen:handshakeHeaderLen+fl])
			body = body[handshakeHeaderLen+fl:]
		}
	}
}

func (p *schemeRewriter) WriteTo(b []byte, addr net.Addr) (int, error) {
	c := append([]byte(nil), b...)
	walkHandshake(c, func(msgType byte, _ int, fragment []byte) {
		if msgType != 13 {
			return
		}
		for i := 0; i+4 <= len(fragment); i++ {
			if fragment[i] == 0 && fragment[i+1] == 2 && fragment[i+2] == 5 && fragment[i+3] == 3 {
				fragment[i+2] = 4
				p.rewrote.Store(true)
				return
			}
		}
	})
	_, err := p.PacketConn.WriteTo(c, addr)
	return len(b), err
}

func (p *schemeRewriter) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := p.PacketConn.ReadFrom(b)
	if err == nil {
		p.mu.Lock()
		if n == recordHeaderLen+2 && b[0] == contentTypeAlert && b[3] == 0 && b[4] == 0 {
			p.alerts = append(p.alerts, [2]byte{b[13], b[14]})
		}
		walkHandshake(b[:n], func(msgType byte, offset int, fragment []byte) {
			if msgType == typeCertificateVerify && offset == 0 && len(fragment) >= 2 {
				p.schemes = append(p.schemes, [2]byte{fragment[0], fragment[1]})
			}
		})
		p.mu.Unlock()
	}
	return n, a, err
}

// NIST-014 (SC-13 / CNSA 2.0): as DTLS client pion signs CertificateVerify
// with the first ECDSA scheme of the server's CertificateRequest, whatever
// Config.SignatureSchemes says. A server that asks for ECDSA/SHA-256 only
// must be refused by Run, at once, and no CertificateVerify with a hash other
// than SHA-384 may reach the wire. The peer is told with a fatal alert.
func TestDtlsCertificateVerifySchemeEnforced(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()
	a, b := udpConn(t), udpConn(t)
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wire := &schemeRewriter{PacketConn: a}
	srv, err := dtls.Server(wire, b.LocalAddr(), &dtls.Config{
		Certificates:           []tls.Certificate{serverID.cert},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_256_GCM},
		SignatureSchemes:       []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384},
		ClientAuth:             dtls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.HandshakeContext(ctx) }()

	res, err := Run(ctx, b, a.LocalAddr(), Params{Identity: clientID, Role: RoleClient, PeerFingerprint: serverID.Fingerprint()})
	if err == nil {
		res.Close()
		t.Fatal("handshake must fail when the server requests only ECDSA/SHA-256 for CertificateVerify")
	}
	if ctx.Err() != nil {
		t.Fatalf("handshake timed out instead of refusing the scheme: %v", err)
	}
	if !errors.Is(err, errSchemeOutsideProfile) {
		t.Fatalf("refused for another reason: %v", err)
	}
	if !wire.rewrote.Load() {
		t.Fatal("the CertificateRequest was never rewritten: the test did not test anything")
	}
	// The server's handshake ends on our alert (or the deadline); either
	// way, wait for it so every datagram we sent has been seen.
	select {
	case <-srvDone:
	case <-time.After(3 * time.Second):
	}
	wire.mu.Lock()
	defer wire.mu.Unlock()
	for _, scheme := range wire.schemes {
		if scheme != [2]byte{5, 3} {
			t.Fatalf("a CertificateVerify with scheme %v reached the wire", scheme)
		}
	}
	if len(wire.alerts) != 1 || wire.alerts[0] != [2]byte{alertLevelFatal, alertHandshakeFailure} {
		t.Fatalf("the server saw alerts %v, want one fatal handshake_failure", wire.alerts)
	}
	t.Logf("correctly refused: %v", err)
}

// RFC-013 / SEC-012, user decision 6 (refuse and document): a client that
// supports secp384r1 but lists another group first is refused by Run as
// server, because pion builds its ServerKeyExchange on the client's first
// group (flight0handler.go:79) and the guard withholds it. The client is told
// with a fatal handshake_failure alert rather than left to time out.
//
// POAM: POA&M-336 (SC-13 / interop) -- selecting P-384 from the client's list
// needs a change in pion; when that lands this test must be turned around.
func TestDtlsClientListingP384SecondIsRefused(t *testing.T) {
	id, _ := GenerateIdentity()
	runErr, peerErr := outOfProfilePeerBothErrors(t, id.cert, func(c *dtls.Config) {
		c.EllipticCurves = []elliptic.Curve{elliptic.P256, elliptic.P384}
	})
	if runErr == nil {
		t.Fatal("a client listing P-256 before P-384 completed a handshake: update POA&M-336 and this test")
	}
	if !errors.Is(runErr, errGroupOutsideProfile) {
		t.Fatalf("refused for another reason: %v", runErr)
	}
	if peerErr == nil || errors.Is(peerErr, errPeerStillHandshaking) || errors.Is(peerErr, context.DeadlineExceeded) {
		t.Fatalf("the refused client was not told (its handshake: %v)", peerErr)
	}
	t.Logf("refused: %v; the client's handshake ended with: %v", runErr, peerErr)
}

// pionReviewedVersion is the pion/dtls release whose internals groupGuard was
// written against.
const pionReviewedVersion = "v3.1.5"

// SEC-013: groupGuard depends on pion internals that no API promises. This
// canary fails when pion changes, so that the guard is reviewed again before
// the upgrade ships:
//
//   - fragment_buffer.go: fragments keyed by offset per message_seq, first
//     one for an offset wins, the message is rebuilt from the offset-0
//     fragment on and takes its type from that fragment;
//   - flight0handler.go (namedCurve = the client's first group),
//     flight3handler.go (client follows the ServerKeyExchange's group),
//     flight5handler.go + signaturehash (CertificateVerify scheme follows the
//     CertificateRequest);
//   - conn.go: nothing is sent when a handshake is cancelled before it
//     completes; a plaintext fatal alert ends the handshake (POA&M-335).
//
// After the review, update pionReviewedVersion.
func TestPionReassemblyAssumptions(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info: cannot tell which pion/dtls this is")
	}
	found := false
	for _, dep := range info.Deps {
		if dep.Path != "github.com/pion/dtls/v3" {
			continue
		}
		found = true
		if dep.Version != pionReviewedVersion || dep.Replace != nil {
			t.Fatalf("pion/dtls is %s (replace: %v), groupGuard was reviewed against %s: re-read the files named above, then update pionReviewedVersion",
				dep.Version, dep.Replace != nil, pionReviewedVersion)
		}
	}
	if !found {
		t.Fatal("github.com/pion/dtls/v3 is not among the build dependencies")
	}

	// Behaviour, seen from outside: a pion server answers a ClientHello
	// (with a HelloVerifyRequest) when it arrives as two fragments of which
	// only the offset-0 one says ClientHello, and when a second, different
	// fragment for offset 0 follows the genuine one.
	hello := capturedClientHello(t)
	body := hello[recordHeaderLen+handshakeHeaderLen:]
	fragment := func(msgType byte, offset int, data []byte) []byte {
		out := append([]byte(nil), hello[recordHeaderLen:recordHeaderLen+handshakeHeaderLen]...)
		out[0] = msgType
		out[6], out[7], out[8] = byte(offset>>16), byte(offset>>8), byte(offset)
		out[9], out[10], out[11] = byte(len(data)>>16), byte(len(data)>>8), byte(len(data))
		return append(out, data...)
	}
	record := func(seq byte, fragment []byte) []byte {
		out := append([]byte(nil), hello[:recordHeaderLen]...)
		out[10] = seq
		out[11], out[12] = byte(len(fragment)>>8), byte(len(fragment))
		return append(out, fragment...)
	}
	garbage := make([]byte, 10)
	cases := []struct {
		name      string
		datagrams [][]byte
	}{
		{"type from the offset-0 fragment", [][]byte{
			record(0, fragment(1, 0, body[:10])),
			record(1, fragment(99, 10, body[10:])),
		}},
		{"first fragment for an offset wins", [][]byte{
			record(0, fragment(1, 0, body[:10])),
			record(1, fragment(1, 0, garbage)),
			record(2, fragment(1, 10, body[10:])),
		}},
	}
	for _, c := range cases {
		a, b := udpConn(t), udpConn(t)
		id, _ := GenerateIdentity()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		srv, err := dtls.Server(a, b.LocalAddr(), &dtls.Config{
			Certificates: []tls.Certificate{id.cert},
			CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.HandshakeContext(ctx) }()
		for _, d := range c.datagrams {
			if _, err := b.WriteTo(d, a.LocalAddr()); err != nil {
				t.Fatal(err)
			}
		}
		reply := make([]byte, 2048)
		_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := b.ReadFrom(reply)
		// HelloVerifyRequest is handshake type 3.
		if err != nil || n <= recordHeaderLen || reply[0] != contentTypeHandshake || reply[recordHeaderLen] != 3 {
			t.Errorf("%s: pion no longer reassembles as groupGuard assumes (n=%d err=%v first bytes %x)", c.name, n, err, reply[:min(n, 14)])
		}
		cancel()
		srv.Close()
		a.Close()
		b.Close()
	}
}

// capturedClientHello returns the first datagram a pion client sends: one
// record holding an unfragmented ClientHello.
func capturedClientHello(t *testing.T) []byte {
	t.Helper()
	a, b := udpConn(t), udpConn(t)
	defer a.Close()
	defer b.Close()
	id, _ := GenerateIdentity()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := dtls.Client(b, a.LocalAddr(), &dtls.Config{
		Certificates:       []tls.Certificate{id.cert},
		CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		EllipticCurves:     []elliptic.Curve{elliptic.P384},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	go func() { _ = cli.HandshakeContext(ctx) }()
	buf := make([]byte, 2048)
	_ = a.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := a.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no ClientHello from pion: %v", err)
	}
	hello := buf[:n]
	if n < recordHeaderLen+handshakeHeaderLen+40 || hello[0] != contentTypeHandshake || hello[recordHeaderLen] != 1 ||
		int(hello[11])<<8|int(hello[12]) != n-recordHeaderLen {
		t.Fatalf("unexpected first datagram from pion (%d bytes)", n)
	}
	return hello
}
