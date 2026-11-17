package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	dtlselliptic "github.com/pion/dtls/v3/pkg/crypto/elliptic"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
)

// DTLS record content types (RFC 6347 §4.1), readable in the cleartext
// record header also once the record is encrypted.
const (
	recChangeCipherSpec = 20
	recAlert            = 21
)

// relayTap is the test's stand-in for the Rust relay's side of one IPC
// connection. It is the FrameTransport of the relay-side DTLS endpoint (the
// "peer"), and it records every Dtls frame the sidecar sends, so that a
// test can tell what the relay would have forwarded to the peer. Ready and
// Error frames go to control.
type relayTap struct {
	inner   ipc.FrameTransport
	control chan []byte

	mu      sync.Mutex
	records [][]byte // every Dtls record received from the sidecar
	seen    chan struct{}

	// dropCCS is the number of sidecar datagrams starting with a
	// ChangeCipherSpec record (the server's final flight) still to be
	// withheld from the peer, as a lossy network would.
	dropCCS atomic.Int32
	dropped atomic.Int32

	// forged holds datagrams to hand to the relay-side endpoint as if they
	// had come from the sidecar (see injectToPeer).
	forged chan []byte
}

func newRelayTap(ft ipc.FrameTransport) *relayTap {
	return &relayTap{inner: ft, control: make(chan []byte, 4), seen: make(chan struct{}, 64), forged: make(chan []byte, 4)}
}

// injectToPeer hands d to the relay-side endpoint as its next datagram. A
// read already blocked is woken through the read deadline.
func (r *relayTap) injectToPeer(d []byte) {
	r.forged <- d
	_ = r.inner.SetReadDeadline(time.Unix(1, 0))
}

func (r *relayTap) RecvFrame() ([]byte, error) {
	for {
		select {
		case d := <-r.forged:
			_ = r.inner.SetReadDeadline(time.Time{})
			return d, nil
		default:
		}
		raw, err := r.inner.RecvFrame()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) && len(r.forged) > 0 {
				continue
			}
			return nil, err
		}
		t, body, err := splitFrame(raw)
		if err != nil {
			return nil, err
		}
		if t != msgDtls {
			r.control <- raw
			continue
		}
		r.mu.Lock()
		r.records = append(r.records, append([]byte(nil), body...))
		r.mu.Unlock()
		select {
		case r.seen <- struct{}{}:
		default:
		}
		if len(body) > 0 && body[0] == recChangeCipherSpec && r.dropCCS.Load() > 0 {
			r.dropCCS.Add(-1)
			r.dropped.Add(1)
			continue
		}
		return body, nil
	}
}

func (r *relayTap) SendFrame(p []byte) error           { return r.inner.SendFrame(frame(msgDtls, p)) }
func (r *relayTap) SetReadDeadline(t time.Time) error  { return r.inner.SetReadDeadline(t) }
func (r *relayTap) SetWriteDeadline(t time.Time) error { return r.inner.SetWriteDeadline(t) }

// Close is a no-op: the test owns the IPC connection, as the relay does. The
// relay-side endpoint must not be able to close it (pion closes its
// transport when the peer sends close_notify).
func (r *relayTap) Close() error { return nil }

// count returns how many recorded sidecar datagrams start with a record of
// the given content type.
func (r *relayTap) count(contentType byte) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.records {
		if len(rec) > 0 && rec[0] == contentType {
			n++
		}
	}
	return n
}

// liveSession is one sidecar session with a relay-side endpoint attached.
type liveSession struct {
	relayConn *net.UnixConn
	ft        ipc.FrameTransport
	tap       *relayTap
	svcErr    chan error
	sidecarID *dtlssession.Identity
	peerID    *dtlssession.Identity
}

// startSession starts a session on one end of a Unix socket pair and
// performs Hello and Start from the other end. sidecarRole is the DTLS role
// the sidecar is told to take.
func startSession(t *testing.T, sidecarRole dtlssession.Role) *liveSession {
	t.Helper()
	return startSessionContext(t, context.Background(), sidecarRole, handshakeTimeout)
}

func startSessionContext(t *testing.T, ctx context.Context, sidecarRole dtlssession.Role, hsTimeout time.Duration) *liveSession {
	t.Helper()
	return startSessionFor(t, ctx, sidecarRole, hsTimeout, "")
}

// startSessionFor is startSessionContext with the fingerprint the sidecar is
// to expect of the peer; empty means that of a new identity (peerID).
func startSessionFor(t *testing.T, ctx context.Context, sidecarRole dtlssession.Role, hsTimeout time.Duration, peerFP string) *liveSession {
	t.Helper()
	sidecarID, peerID := mustIdentity(t), mustIdentity(t)
	if peerFP == "" {
		peerFP = peerID.Fingerprint()
	}
	svcConn, relayConn := unixPair(t)
	s := &liveSession{
		relayConn: relayConn.(*net.UnixConn),
		svcErr:    make(chan error, 1),
		sidecarID: sidecarID,
		peerID:    peerID,
	}
	go func() { s.svcErr <- handleSession(ctx, svcConn, sidecarID, hsTimeout) }()

	s.ft = ipc.NewFramedTransport(relayConn)
	raw, err := recvWithin(t, s.ft, 10*time.Second)
	if err != nil {
		t.Fatalf("read Hello: %v", err)
	}
	if typ, _, _ := splitFrame(raw); typ != msgHello {
		t.Fatalf("want Hello, got type %d", typ)
	}
	if err := s.ft.SendFrame(encodeStart(sidecarRole, peerFP)); err != nil {
		t.Fatal(err)
	}
	s.tap = newRelayTap(s.ft)
	return s
}

// peerHandshake runs the relay-side endpoint's handshake in the role
// opposite to the sidecar's.
func (s *liveSession) peerHandshake(ctx context.Context, sidecarRole dtlssession.Role) (*dtlssession.Result, error) {
	role := dtlssession.RoleClient
	if sidecarRole == dtlssession.RoleClient {
		role = dtlssession.RoleServer
	}
	pc := ipc.NewPacketConn(s.tap)
	return dtlssession.Run(ctx, pc, pc.PeerAddr(), dtlssession.Params{
		Identity:        s.peerID,
		Role:            role,
		PeerFingerprint: s.sidecarID.Fingerprint(),
	})
}

// awaitReady waits for the sidecar's Ready and returns its keys.
func (s *liveSession) awaitReady(t *testing.T) []byte {
	t.Helper()
	select {
	case raw := <-s.tap.control:
		typ, body, _ := splitFrame(raw)
		if typ != msgReady {
			t.Fatalf("want Ready, got type %d: %s", typ, body)
		}
		_, keys, err := decodeReady(body)
		if err != nil {
			t.Fatal(err)
		}
		return keys
	case <-time.After(10 * time.Second):
		t.Fatal("timeout awaiting Ready")
		return nil
	}
}

// RFC-001: after Ready the association stays up for as long as the relay
// keeps the IPC connection open. The sidecar must not emit an alert (the
// relay forwards every post-Ready Dtls frame to the peer, and a peer that
// reads close_notify ends its media), and must not end the session.
func TestNoCloseNotifyAfterReadyWhileIPCOpen(t *testing.T) {
	for _, tc := range []struct {
		name string
		role dtlssession.Role
	}{{"sidecar-server", dtlssession.RoleServer}, {"sidecar-client", dtlssession.RoleClient}} {
		t.Run(tc.name, func(t *testing.T) {
			s := startSession(t, tc.role)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			peer, err := s.peerHandshake(ctx, tc.role)
			if err != nil {
				t.Fatalf("peer handshake: %v", err)
			}
			defer func() { _ = peer.Close() }()
			keys := s.awaitReady(t)
			if string(keys) != string(peer.SRTPKeys) {
				t.Fatal("Ready keys differ from the peer's")
			}

			// Hold the association. Nothing may come from the sidecar and
			// the session must stay up.
			select {
			case err := <-s.svcErr:
				t.Fatalf("session ended %v after Ready with the IPC open (alerts sent: %d)",
					err, s.tap.count(recAlert))
			case raw := <-s.tap.control:
				t.Fatalf("unexpected control frame after Ready: type %d", raw[0])
			case <-time.After(2500 * time.Millisecond):
			}
			if n := s.tap.count(recAlert); n != 0 {
				t.Fatalf("sidecar emitted %d alert record(s) after Ready with the IPC open", n)
			}
		})
	}
}

// RFC 6347 §4.2.4: the side that sent the last flight must answer a
// retransmission of the peer's last flight for as long as the association
// lives. With the sidecar as DTLS server, its final flight
// (ChangeCipherSpec, Finished) is lost once; the client retransmits its own
// final flight after the sidecar has reported Ready, and must be answered.
func TestRetransmittedFinalClientFlightAnsweredAfterReady(t *testing.T) {
	s := startSession(t, dtlssession.RoleServer)
	s.tap.dropCCS.Store(1)

	type outcome struct {
		res *dtlssession.Result
		err error
	}
	done := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() {
		res, err := s.peerHandshake(ctx, dtlssession.RoleServer)
		done <- outcome{res, err}
	}()

	// The sidecar finishes first: it has the client's Finished and its own
	// final flight is on its way (and lost).
	keys := s.awaitReady(t)
	select {
	case o := <-done:
		t.Fatalf("peer finished without the server's final flight: %v", o.err)
	default:
	}

	o := <-done
	if o.err != nil {
		t.Fatalf("peer handshake after a lost final flight: %v (final flights seen from the sidecar: %d, alerts: %d)",
			o.err, s.tap.count(recChangeCipherSpec), s.tap.count(recAlert))
	}
	defer func() { _ = o.res.Close() }()
	if s.tap.dropped.Load() != 1 {
		t.Fatalf("dropped %d final flights, want 1", s.tap.dropped.Load())
	}
	if n := s.tap.count(recChangeCipherSpec); n < 2 {
		t.Fatalf("sidecar sent its final flight %d time(s), want at least 2", n)
	}
	if string(keys) != string(o.res.SRTPKeys) {
		t.Fatal("Ready keys differ from the peer's")
	}
	if n := s.tap.count(recAlert); n != 0 {
		t.Fatalf("sidecar emitted %d alert record(s)", n)
	}
}

// readToEnd reads the IPC connection directly (the relay-side endpoint has
// stopped reading) until the sidecar closes its end, and returns the frames
// still sent.
func readToEnd(t *testing.T, ft ipc.FrameTransport) [][]byte {
	t.Helper()
	var frames [][]byte
	for {
		raw, err := recvWithin(t, ft, 5*time.Second)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return frames
			}
			t.Fatalf("reading the IPC connection to its end: %v", err)
		}
		frames = append(frames, raw)
	}
}

// established brings one session to Ready and returns it with the
// relay-side endpoint's association.
func established(t *testing.T, ctx context.Context, role dtlssession.Role) (*liveSession, *dtlssession.Result) {
	t.Helper()
	s := startSessionContext(t, ctx, role, handshakeTimeout)
	hctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	peer, err := s.peerHandshake(hctx, role)
	if err != nil {
		t.Fatalf("peer handshake: %v", err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	s.awaitReady(t)
	return s, peer
}

func (s *liveSession) awaitEnd(t *testing.T) error {
	t.Helper()
	select {
	case err := <-s.svcErr:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("session did not end")
		return nil
	}
}

// awaitAlerts waits until the tap has seen n alert records from the sidecar.
func (s *liveSession) awaitAlerts(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.tap.count(recAlert) < n {
		if time.Now().After(deadline) {
			t.Fatalf("saw %d alert record(s) from the sidecar, want %d", s.tap.count(recAlert), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The relay ends a call by closing its sending half and reading on: the
// session ends, and exactly one close_notify comes back for the peer, in
// either role.
func TestRelayHalfCloseEndsSessionWithOneCloseNotify(t *testing.T) {
	for _, role := range []dtlssession.Role{dtlssession.RoleServer, dtlssession.RoleClient} {
		s, _ := established(t, context.Background(), role)
		if err := s.relayConn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		// The relay-side endpoint reads the close_notify (through the tap)
		// and stops reading; whatever else the sidecar sent is still queued.
		s.awaitAlerts(t, 1)
		if rest := readToEnd(t, s.ft); len(rest) != 0 {
			t.Fatalf("role %d: %d more frame(s) after the close_notify, first type %d", role, len(rest), rest[0][0])
		}
		if err := s.awaitEnd(t); err != nil {
			t.Fatalf("role %d: session: %v", role, err)
		}
		if n := s.tap.count(recAlert); n != 1 {
			t.Fatalf("role %d: %d alert records, want 1", role, n)
		}
	}
}

// A relay that closes the whole connection (or dies) also ends the session.
func TestRelayCloseEndsSession(t *testing.T) {
	s, _ := established(t, context.Background(), dtlssession.RoleServer)
	_ = s.relayConn.Close()
	if err := s.awaitEnd(t); err != nil {
		t.Fatalf("session: %v", err)
	}
}

// The peer ends the association: the sidecar answers its close_notify with
// one of its own (RFC 5246 §7.2.1), tells the relay with an Error frame and
// ends the session.
func TestPeerCloseNotifyIsReportedToRelay(t *testing.T) {
	s, peer := established(t, context.Background(), dtlssession.RoleServer)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	// The relay-side endpoint is closed and reads nothing more.
	frames := readToEnd(t, s.ft)
	if len(frames) != 2 {
		t.Fatalf("got %d frame(s) after the peer's close_notify, want 2", len(frames))
	}
	if typ, body, _ := splitFrame(frames[0]); typ != msgDtls || len(body) == 0 || body[0] != recAlert {
		t.Fatalf("first frame: type %d, want a Dtls frame with an alert record", typ)
	}
	if typ, body, _ := splitFrame(frames[1]); typ != msgError || string(body) != ErrPeerCloseNotify {
		t.Fatalf("second frame: type %d %q, want Error %q", typ, body, ErrPeerCloseNotify)
	}
	if err := s.awaitEnd(t); err != nil {
		t.Fatalf("session: %v", err)
	}
}

// rawPionPeer is a relay-side endpoint made of pion alone, without the
// sidecar's plaintext gate, so that the test can make it send what a
// misbehaving or failing peer sends. It is DTLS client with the profile's
// parameters and its own P-384 identity.
func rawPionPeer(t *testing.T, s *liveSession, priv *ecdsa.PrivateKey, der []byte) *dtls.Conn {
	t.Helper()
	pc := ipc.NewPacketConn(s.tap)
	conn, err := dtls.Client(pc, pc.PeerAddr(), &dtls.Config{
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_256_GCM},
		SignatureSchemes:       []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384},
		EllipticCurves:         []dtlselliptic.Curve{dtlselliptic.P384},
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		// The test does not check the sidecar's certificate.
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("pion client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatalf("pion client handshake: %v", err)
	}
	return conn
}

// NIST-017: the peer ends the association with a genuine, protected fatal
// alert after Ready. The sidecar sends nothing back (a fatal alert is not
// answered), tells the relay which of the two ways the peer ended it, and
// ends the session.
//
// pion has no call that sends a fatal alert, so the peer is made to: it is
// a pion endpoint without the plaintext gate, and it is handed a malformed
// plaintext ChangeCipherSpec, which pion answers with a protected fatal
// decode_error to the other side (the defect the gate keeps from the
// sidecar's own associations, SEC-010).
func TestPeerFatalAlertIsReportedToRelay(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "raw-pion-peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum384(der)
	hexb := make([]string, len(sum))
	for i, b := range sum {
		hexb[i] = fmt.Sprintf("%02X", b)
	}
	fingerprint := "sha-384 " + strings.Join(hexb, ":")

	s := startSessionFor(t, context.Background(), dtlssession.RoleServer, handshakeTimeout, fingerprint)
	rawPionPeer(t, s, priv, der)
	s.awaitReady(t)

	// Epoch 0, sequence number far above the handshake's, body 2.
	s.tap.injectToPeer([]byte{recChangeCipherSpec, 0xfe, 0xfd, 0, 0, 0, 0, 0xff, 0xff, 0xff, 9, 0, 1, 2})

	select {
	case raw := <-s.tap.control:
		if typ, body, _ := splitFrame(raw); typ != msgError || string(body) != ErrPeerFatalAlert {
			t.Fatalf("frame: type %d %q, want Error %q", typ, body, ErrPeerFatalAlert)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no Error frame after the peer's fatal alert")
	}
	if err := s.awaitEnd(t); err != nil {
		t.Fatalf("session: %v", err)
	}
	if n := s.tap.count(recAlert); n != 0 {
		t.Fatalf("sidecar sent %d alert record(s) in answer to a fatal alert, want none", n)
	}
}

// The sidecar stops: an established session sends close_notify towards its
// peer, tells the relay why, and ends.
func TestShutdownEndsEstablishedSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, _ := established(t, ctx, dtlssession.RoleClient)
	cancel()
	s.awaitAlerts(t, 1)
	frames := readToEnd(t, s.ft)
	if len(frames) != 1 {
		t.Fatalf("got %d frame(s) after the close_notify, want 1 (Error)", len(frames))
	}
	if typ, body, _ := splitFrame(frames[0]); typ != msgError || string(body) != ErrShutdown {
		t.Fatalf("frame: type %d %q, want Error %q", typ, body, ErrShutdown)
	}
	if err := s.awaitEnd(t); err != nil {
		t.Fatalf("session: %v", err)
	}
}

// A handshake with a silent peer ends at the handshake timeout (not when the
// relay gives up), the relay gets the Error frame, and the timeout is for
// the handshake only (TestNoCloseNotifyAfterReadyWhileIPCOpen holds an
// association for longer than the timeout used here).
func TestHandshakeTimeoutEndsSessionAndReportsError(t *testing.T) {
	s := startSessionContext(t, context.Background(), dtlssession.RoleServer, 300*time.Millisecond)
	started := time.Now()
	err := s.awaitEnd(t)
	if err == nil {
		t.Fatal("session ended without an error")
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("session ended after %v, want about 300ms", took)
	}
	frames := readToEnd(t, s.ft)
	if len(frames) != 1 {
		t.Fatalf("got %d frame(s), want 1 (Error)", len(frames))
	}
	if typ, body, _ := splitFrame(frames[0]); typ != msgError || len(body) == 0 {
		t.Fatalf("frame: type %d %q, want a non-empty Error", typ, body)
	}
}

// The sidecar stops while a handshake is in flight, or before Start: the
// session ends at once.
func TestShutdownEndsSessionBeforeReady(t *testing.T) {
	t.Run("during handshake", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := startSessionContext(t, ctx, dtlssession.RoleServer, handshakeTimeout)
		time.Sleep(50 * time.Millisecond)
		cancel()
		if err := s.awaitEnd(t); err == nil {
			t.Fatal("session ended without an error")
		}
	})
	t.Run("before Start", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		svcConn, relayConn := unixPair(t)
		svcErr := make(chan error, 1)
		go func() { svcErr <- HandleSession(ctx, svcConn, mustIdentity(t)) }()
		ft := ipc.NewFramedTransport(relayConn)
		if _, err := recvWithin(t, ft, 10*time.Second); err != nil {
			t.Fatalf("read Hello: %v", err)
		}
		cancel()
		select {
		case err := <-svcErr:
			if err != nil {
				t.Fatalf("session: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("session did not end")
		}
	})
}

// A frame other than Dtls after Ready is a protocol error: the session ends
// (with close_notify for the peer) instead of carrying on out of step.
func TestNonDtlsFrameAfterReadyEndsSession(t *testing.T) {
	s, _ := established(t, context.Background(), dtlssession.RoleServer)
	if err := s.ft.SendFrame(encodeStart(dtlssession.RoleServer, "x")); err != nil {
		t.Fatal(err)
	}
	if err := s.awaitEnd(t); err == nil {
		t.Fatal("session ended without an error")
	}
	s.awaitAlerts(t, 1)
}

// SC-5: sessions leave nothing behind, whichever way they end. Runs every
// way a session can end and then requires that no goroutine of the
// sidecar's packages or of pion is left.
func TestSessionsLeaveNoGoroutines(t *testing.T) {
	t.Run("ends", func(t *testing.T) {
		for _, role := range []dtlssession.Role{dtlssession.RoleServer, dtlssession.RoleClient} {
			// Relay half-close.
			s, peer := established(t, context.Background(), role)
			_ = s.relayConn.CloseWrite()
			_ = s.awaitEnd(t)
			_ = peer.Close()
			_ = s.ft.Close()
			// Relay close.
			s, peer = established(t, context.Background(), role)
			_ = s.relayConn.Close()
			_ = s.awaitEnd(t)
			_ = peer.Close()
			_ = s.ft.Close()
			// Peer close_notify.
			s, peer = established(t, context.Background(), role)
			_ = peer.Close()
			_ = s.awaitEnd(t)
			_ = s.ft.Close()
			// Shutdown.
			ctx, cancel := context.WithCancel(context.Background())
			s, peer = established(t, ctx, role)
			cancel()
			_ = s.awaitEnd(t)
			_ = peer.Close()
			_ = s.ft.Close()
		}
		// Handshake timeout with a silent peer.
		s := startSessionContext(t, context.Background(), dtlssession.RoleServer, 200*time.Millisecond)
		_ = s.awaitEnd(t)
		_ = s.ft.Close()
	})

	// The subtest's cleanups (sockets, relay-side endpoints) have run.
	deadline := time.Now().Add(10 * time.Second)
	for {
		left := sidecarGoroutines()
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutine(s) left behind:\n\n%s", len(left), strings.Join(left, "\n\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// sidecarGoroutines returns the stacks of the goroutines that run code of
// the sidecar's packages or of pion, other than the caller's.
func sidecarGoroutines() []string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var left []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "sidecarGoroutines") {
			continue
		}
		if strings.Contains(g, "github.com/pion/") || strings.Contains(g, "dtls-terminator/ipc.") ||
			strings.Contains(g, "dtls-terminator/service.handleSession") ||
			strings.Contains(g, "dtls-terminator.(") {
			left = append(left, g)
		}
	}
	return left
}

func mustIdentity(t *testing.T) *dtlssession.Identity {
	t.Helper()
	id, err := dtlssession.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
