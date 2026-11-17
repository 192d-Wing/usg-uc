package dtlssession

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

// injectableConn delivers the datagrams of the wrapped socket and, on
// demand, forged ones "from the peer's address", as an off-path sender who
// knows the media address can.
type injectableConn struct {
	net.PacketConn
	in   chan []byte
	addr net.Addr
	done chan struct{}
}

func newInjectableConn(conn net.PacketConn, peer net.Addr) *injectableConn {
	c := &injectableConn{PacketConn: conn, in: make(chan []byte, 64), addr: peer, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		for {
			buf := make([]byte, 8192)
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			c.in <- buf[:n]
		}
	}()
	return c
}

func (c *injectableConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case d := <-c.in:
		return copy(p, d), c.addr, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *injectableConn) inject(d []byte) { c.in <- d }

// plaintextRecord is an epoch-0 record with a sequence number far above
// anything the handshake used (pion's replay check comes first).
func plaintextRecord(contentType byte, seq byte, body ...byte) []byte {
	rec := []byte{contentType, 0xfe, 0xfd, 0, 0, 0, 0, 0xff, 0xff, 0xff, seq, 0, byte(len(body))}
	return append(rec, body...)
}

// establishedPair completes a handshake over loopback UDP with the given
// role behind an injectableConn, and returns that side (the victim), the
// other side and the injector.
func establishedPair(t *testing.T, victim Role) (v, other *Result, inj *injectableConn) {
	t.Helper()
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()
	a, b := udpConn(t), udpConn(t)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var serverConn, clientConn net.PacketConn = a, b
	if victim == RoleServer {
		inj = newInjectableConn(a, b.LocalAddr())
		serverConn = inj
	} else {
		inj = newInjectableConn(b, a.LocalAddr())
		clientConn = inj
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
		t.Fatalf("handshake: client %v, server %v", cerr, s.err)
	}
	t.Cleanup(func() { _ = cres.Close(); _ = s.res.Close() })
	if victim == RoleServer {
		return s.res, cres, inj
	}
	return cres, s.res, inj
}

// readOutcome reads the association for d and reports how the read ended.
func readOutcome(r *Result, d time.Duration) error {
	_ = r.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = r.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, 8192)
	for {
		if _, err := r.Read(buf); err != nil {
			return err
		}
	}
}

func isDeadline(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// The forged datagrams an association must survive once it is established.
func forgedUnprotected() [][]byte {
	closeNotify := plaintextRecord(21, 1, 1, 0)
	fatal := plaintextRecord(21, 2, 2, 40)
	appData := plaintextRecord(23, 3, 'x')
	// An alert hidden behind a handshake record in the same datagram.
	behind := append(plaintextRecord(22, 4, 1, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0), plaintextRecord(21, 5, 1, 0)...)
	// SEC-010: a ChangeCipherSpec whose body is not the single octet 1. pion
	// would answer it with a protected fatal decode_error to the real peer.
	badCCS := plaintextRecord(20, 6, 2)
	longCCS := plaintextRecord(20, 7, 1, 1)
	emptyCCS := plaintextRecord(20, 8)
	// The same hidden behind a well-formed one.
	ccsBehind := append(plaintextRecord(20, 9, 1), plaintextRecord(20, 10, 2)...)
	return [][]byte{closeNotify, fatal, appData, behind, badCCS, longCCS, emptyCCS, ccsBehind}
}

// handshakeRecord is one complete epoch-0 handshake message (ClientHello
// type, any body) with the given record sequence number and message_seq.
func handshakeRecord(recSeq uint64, msgSeq uint16, body int) []byte {
	rec := make([]byte, recordHeaderLen+12+body)
	rec[0] = contentTypeHandshake
	rec[1], rec[2] = 0xfe, 0xfd
	binary.BigEndian.PutUint64(rec[3:11], recSeq)
	rec[3], rec[4] = 0, 0 // epoch 0
	binary.BigEndian.PutUint16(rec[11:13], uint16(12+body))
	h := rec[recordHeaderLen:]
	h[0] = 1
	h[1], h[2], h[3] = byte(body>>16), byte(body>>8), byte(body)
	binary.BigEndian.PutUint16(h[4:6], msgSeq)
	h[9], h[10], h[11] = byte(body>>16), byte(body>>8), byte(body)
	return rec
}

// SEC-010: one forged, malformed plaintext ChangeCipherSpec must not make us
// send the genuine peer an alert. Without the gate it does (second half), so
// a pion upgrade that changes this shows up here.
func TestMalformedChangeCipherSpecDoesNotAlertThePeer(t *testing.T) {
	for _, role := range []Role{RoleServer, RoleClient} {
		victim, other, inj := establishedPair(t, role)
		inj.inject(plaintextRecord(20, 9, 2))
		if err := readOutcome(victim, 500*time.Millisecond); !isDeadline(err) {
			t.Fatalf("role %d: association ended by a malformed ChangeCipherSpec: %v", role, err)
		}
		if err := readOutcome(other, 300*time.Millisecond); !isDeadline(err) {
			t.Fatalf("role %d: the genuine peer got an alert: %v", role, err)
		}
		if got := victim.DroppedUnprotected(); got != 1 {
			t.Fatalf("role %d: %d datagrams dropped, want 1", role, got)
		}
	}

	victim, other, inj := establishedPair(t, RoleServer)
	victim.gate.established.Store(false)
	inj.inject(plaintextRecord(20, 9, 2))
	if err := readOutcome(other, 5*time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("without the gate the genuine peer's Read returned %v; "+
			"pion used to send it a fatal alert (io.EOF)", err)
	}
}

// SEC-011: a flood of complete, consecutive epoch-0 handshake messages after
// the handshake reaches pion only up to the association's budget; the rest
// is dropped and counted, the association stays up, the genuine peer is not
// told anything, and the process does not keep what was sent.
func TestHandshakeFloodAfterHandshakeIsBounded(t *testing.T) {
	const flood, body = 5000, 4000
	for _, role := range []Role{RoleServer, RoleClient} {
		victim, other, inj := establishedPair(t, role)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := 0; i < flood; i++ {
			inj.inject(handshakeRecord(0x1000_0000+uint64(i), uint16(i), body))
		}
		// Every datagram has gone through the gate once a later one has.
		inj.inject(plaintextRecord(21, 1, 1, 0))
		deadline := time.Now().Add(5 * time.Second)
		for victim.DroppedUnprotected() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)

		if got, want := victim.DroppedHandshake(), uint64(flood-handshakeClassBudget); got != want {
			t.Fatalf("role %d: %d handshake datagrams dropped, want %d (budget %d)", role, got, want, handshakeClassBudget)
		}
		// 20 MB were sent. What may stay is the budget's worth (32 x 4 KB)
		// plus noise; 4 MB is far above that and far below the flood.
		if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 4<<20 {
			t.Fatalf("role %d: live heap grew by %d bytes under a %d byte flood", role, grown, flood*body)
		}
		if err := readOutcome(victim, 300*time.Millisecond); !isDeadline(err) {
			t.Fatalf("role %d: association ended by the flood: %v", role, err)
		}
		if err := readOutcome(other, 200*time.Millisecond); !isDeadline(err) {
			t.Fatalf("role %d: the genuine peer was told the association ended: %v", role, err)
		}
		// The genuine peer's close_notify still ends it.
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
		if err := readOutcome(victim, 5*time.Second); !errors.Is(err, io.EOF) {
			t.Fatalf("role %d: after the peer's close_notify Read returned %v, want io.EOF", role, err)
		}
		runtime.KeepAlive(victim)
	}
}

// scriptedConn hands out the given datagrams, then reports closed.
type scriptedConn struct {
	net.PacketConn
	datagrams [][]byte
}

func (c *scriptedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.datagrams) == 0 {
		return 0, nil, net.ErrClosed
	}
	d := c.datagrams[0]
	c.datagrams = c.datagrams[1:]
	return copy(p, d), nil, nil
}

// passed runs every datagram through the gate and returns how many came out.
func passed(g *plaintextGate) int {
	buf := make([]byte, 8192)
	n := 0
	for {
		if _, _, err := g.ReadFrom(buf); err != nil {
			return n
		}
		n++
	}
}

// The budget of the gate: nothing is dropped before the handshake has
// completed; afterwards handshake-class datagrams pass up to the budget and
// only inside the window, and protected datagrams always pass.
func TestPlaintextGateHandshakeBudget(t *testing.T) {
	hs := handshakeRecord(1, 0, 16)
	finalFlight := append(plaintextRecord(20, 2, 1), 22, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 9, 9)
	protected := []byte{23, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 2, 9, 9}
	script := func(n int) [][]byte {
		var out [][]byte
		for i := 0; i < n; i++ {
			out = append(out, hs, finalFlight, protected)
		}
		return out
	}

	// Not armed (the handshake itself): everything passes.
	g := newPlaintextGate(&scriptedConn{datagrams: script(100)})
	if got := passed(g); got != 300 {
		t.Fatalf("during the handshake %d of 300 datagrams passed", got)
	}

	// Armed: all protected datagrams, and the budget of the others.
	g = newPlaintextGate(&scriptedConn{datagrams: script(100)})
	g.arm()
	if got, want := passed(g), 100+handshakeClassBudget; got != want {
		t.Fatalf("after the handshake %d datagrams passed, want %d", got, want)
	}
	if got, want := g.droppedHandshake.Load(), uint64(200-handshakeClassBudget); got != want {
		t.Fatalf("%d handshake datagrams dropped, want %d", got, want)
	}

	// Armed, window over: no handshake-class datagram passes any more.
	g = newPlaintextGate(&scriptedConn{datagrams: script(3)})
	g.arm()
	g.armed = time.Now().Add(-handshakeClassWindow - time.Second)
	if got := passed(g); got != 3 {
		t.Fatalf("after the window %d datagrams passed, want the 3 protected ones", got)
	}
	if got := g.droppedHandshake.Load(); got != 6 {
		t.Fatalf("%d handshake datagrams dropped after the window, want 6", got)
	}
}

// After the handshake an unprotected alert "from the peer's address" must not
// end the association (and must not make us send close_notify to the real
// peer), in either role; the peer's own, protected close_notify still does.
func TestForgedUnprotectedAlertsDoNotEndAnEstablishedAssociation(t *testing.T) {
	for _, role := range []Role{RoleServer, RoleClient} {
		victim, other, inj := establishedPair(t, role)
		forged := forgedUnprotected()
		for _, d := range forged {
			inj.inject(d)
		}
		if err := readOutcome(victim, 500*time.Millisecond); !isDeadline(err) {
			t.Fatalf("role %d: association ended by forged unprotected records: %v", role, err)
		}
		if got := victim.DroppedUnprotected(); got != uint64(len(forged)) {
			t.Fatalf("role %d: %d datagrams dropped, want %d", role, got, len(forged))
		}
		// The other side saw nothing either: no close_notify was sent to it.
		if err := readOutcome(other, 200*time.Millisecond); !isDeadline(err) {
			t.Fatalf("role %d: the genuine peer was told the association ended: %v", role, err)
		}
		// A genuine close_notify (epoch 1) still ends it.
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
		if err := readOutcome(victim, 5*time.Second); !errors.Is(err, io.EOF) {
			t.Fatalf("role %d: after the peer's close_notify Read returned %v, want io.EOF", role, err)
		}
	}
}

// What the gate is for: without it, one forged unprotected close_notify ends
// an established pion association and makes pion send a genuine close_notify
// to the real peer. If a pion upgrade changes that, this test fails and the
// gate can be reconsidered.
func TestPionHonoursUnprotectedCloseNotifyAfterHandshake(t *testing.T) {
	victim, other, inj := establishedPair(t, RoleServer)
	victim.gate.established.Store(false)
	inj.inject(plaintextRecord(21, 1, 1, 0))
	if err := readOutcome(victim, 5*time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("victim Read returned %v, want io.EOF", err)
	}
	if err := readOutcome(other, 5*time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("genuine peer Read returned %v, want io.EOF (close_notify from the victim)", err)
	}
}

func TestUnprotectedScanner(t *testing.T) {
	hs := plaintextRecord(22, 1, 1, 2, 3)
	ccs := plaintextRecord(20, 2, 1)
	alert := plaintextRecord(21, 3, 1, 0)
	protected := []byte{21, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 2, 9, 9}
	join := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	const none, handshake, forged = unprotectedNone, unprotectedHandshake, unprotectedForged
	for _, tc := range []struct {
		name string
		d    []byte
		want unprotectedKind
	}{
		{"empty", nil, none},
		{"handshake", hs, handshake},
		{"change cipher spec", ccs, handshake},
		{"final flight", join(ccs, protected), handshake},
		{"handshake after protected", join(protected, hs), handshake},
		{"protected alert", protected, none},
		{"alert", alert, forged},
		{"application data", plaintextRecord(23, 4, 0), forged},
		{"alert after handshake", join(hs, alert), forged},
		{"alert after protected", join(protected, alert), forged},
		{"change cipher spec, body 2", plaintextRecord(20, 5, 2), forged},
		{"change cipher spec, body 0", plaintextRecord(20, 5, 0), forged},
		{"change cipher spec, two octets", plaintextRecord(20, 5, 1, 1), forged},
		{"change cipher spec, empty", plaintextRecord(20, 5), forged},
		{"change cipher spec, body cut off", ccs[:13], forged},
		{"malformed change cipher spec after a good one", join(ccs, plaintextRecord(20, 5, 2)), forged},
		{"malformed change cipher spec after handshake", join(hs, plaintextRecord(20, 5, 2)), forged},
		{"protected change cipher spec type, any body", []byte{20, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 2, 9, 9}, none},
		{"short header", alert[:12], none},
		{"overlong length then alert", join([]byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff}, alert), handshake},
	} {
		if got := scanUnprotected(tc.d); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	// No input may panic.
	full := join(hs, ccs, protected, alert)
	for cut := 0; cut <= len(full); cut++ {
		_ = scanUnprotected(full[:cut])
	}
}
