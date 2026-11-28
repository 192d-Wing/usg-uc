package dtlssession

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"testing"
	"time"
)

// fragmentRecord is one epoch-0 handshake record holding a single fragment
// of a message of msgLen bytes, at offset, of body bytes.
func fragmentRecord(recSeq uint64, msgSeq uint16, msgLen, offset, body int) []byte {
	rec := make([]byte, recordHeaderLen+handshakeHeaderLen+body)
	rec[0] = contentTypeHandshake
	rec[1], rec[2] = 0xfe, 0xfd
	binary.BigEndian.PutUint64(rec[3:11], recSeq)
	rec[3], rec[4] = 0, 0 // epoch 0
	binary.BigEndian.PutUint16(rec[11:13], uint16(handshakeHeaderLen+body))
	h := rec[recordHeaderLen:]
	h[0] = 11 // Certificate
	h[1], h[2], h[3] = byte(msgLen>>16), byte(msgLen>>8), byte(msgLen)
	binary.BigEndian.PutUint16(h[4:6], msgSeq)
	h[6], h[7], h[8] = byte(offset>>16), byte(offset>>8), byte(offset)
	h[9], h[10], h[11] = byte(body>>16), byte(body>>8), byte(body)
	return rec
}

// A genuine handshake in either role stays far inside the per-association
// budget, so that a peer on a lossy path that retransmits its flights
// several times still fits.
func TestGenuineHandshakeFitsTheBudget(t *testing.T) {
	for _, role := range []Role{RoleServer, RoleClient} {
		v, other, _ := establishedPair(t, role)
		for _, r := range []*Result{v, other} {
			l := r.limiter
			l.mu.Lock()
			d, b := l.datagrams, l.bytes
			l.mu.Unlock()
			t.Logf("role %d side client=%v: %d datagrams, %d bytes before the handshake completed", role, l.maxSeq == maxPeerMessageSeqPeerServer, d, b)
			if d*4 > PreHandshakeDatagrams || b*4 > PreHandshakeBytes {
				t.Fatalf("a genuine handshake used %d datagrams / %d bytes: less than 4x headroom in %d / %d",
					d, b, PreHandshakeDatagrams, PreHandshakeBytes)
			}
			if got := r.DroppedPreHandshake(); got != 0 {
				t.Fatalf("a genuine handshake had %d datagrams dropped", got)
			}
		}
	}
	if got := defaultPool.InUse(); got != 0 {
		t.Fatalf("%d bytes still charged to the pool after every handshake ended", got)
	}
}

// renumberConn gives every epoch-0 record the victim reads, forged or
// genuine, the next record sequence number, as a peer that sends both
// itself numbers them. Without it the forged records' numbers would move
// pion's epoch-0 replay window past the genuine ones (POA&M-335).
type renumberConn struct {
	*injectableConn
	next uint64
}

func (c *renumberConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.injectableConn.ReadFrom(p)
	d := p[:n]
	for len(d) >= recordHeaderLen {
		length := int(binary.BigEndian.Uint16(d[11:13]))
		if binary.BigEndian.Uint16(d[3:5]) == 0 {
			var seq [8]byte
			binary.BigEndian.PutUint64(seq[:], c.next)
			copy(d[5:11], seq[2:])
			c.next++
		}
		if length > len(d)-recordHeaderLen {
			break
		}
		d = d[recordHeaderLen+length:]
	}
	return n, addr, err
}

// floodedHandshake runs a handshake in which the victim's own peer address
// sends, before and while the genuine flights arrive, n fragments of
// message_seq seq (4 KB each, never completed), and returns the victim's
// result and how much its live heap grew while the association is held.
func floodedHandshake(t *testing.T, victim Role, n int, seq uint16, disable bool) (*Result, int64) {
	t.Helper()
	flood := make([][]byte, n)
	for i := range flood {
		// Distinct offsets, so pion would keep every one.
		flood[i] = fragmentRecord(0, seq, 1<<23, i*4000, 4000)
	}
	return floodedHandshakeWith(t, victim, flood, disable)
}

// tinyFragments is one record of n zero-length fragments of message_seq
// seq at distinct offsets: pion keeps each as an object of its own.
func tinyFragments(seq uint16, first, n int) []byte {
	rec := make([]byte, recordHeaderLen, recordHeaderLen+n*handshakeHeaderLen)
	rec[0] = contentTypeHandshake
	rec[1], rec[2] = 0xfe, 0xfd
	for i := 0; i < n; i++ {
		h := make([]byte, handshakeHeaderLen)
		h[0] = 11
		h[1], h[2], h[3] = 0x10, 0, 0 // a 1 MiB message, never completed
		binary.BigEndian.PutUint16(h[4:6], seq)
		off := first + i
		h[6], h[7], h[8] = byte(off>>16), byte(off>>8), byte(off)
		rec = append(rec, h...)
	}
	binary.BigEndian.PutUint16(rec[11:13], uint16(len(rec)-recordHeaderLen))
	return rec
}

func floodedHandshakeWith(t *testing.T, victim Role, flood [][]byte, disable bool) (*Result, int64) {
	t.Helper()
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()
	a, b := udpConn(t), udpConn(t)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var serverConn, clientConn net.PacketConn = a, b
	var inj *injectableConn
	if victim == RoleServer {
		inj = newInjectableConn(a, b.LocalAddr())
		serverConn = &renumberConn{injectableConn: inj}
	} else {
		inj = newInjectableConn(b, a.LocalAddr())
		clientConn = &renumberConn{injectableConn: inj}
	}
	if disable {
		testDisableLimiter = true
		defer func() { testDisableLimiter = false }()
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	go func() {
		for _, d := range flood {
			inj.inject(d)
		}
	}()

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
		t.Fatalf("handshake under a flood: client %v, server %v", cerr, s.err)
	}
	t.Cleanup(func() { _ = cres.Close(); _ = s.res.Close() })
	v := s.res
	if victim == RoleClient {
		v = cres
	}
	// Every flood datagram has reached the victim once its injector queue
	// has drained and one more datagram has gone through.
	deadline := time.Now().Add(10 * time.Second)
	for len(inj.in) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(cres)
	runtime.KeepAlive(s.res)
	runtime.KeepAlive(flood)
	return v, int64(after.HeapAlloc) - int64(before.HeapAlloc)
}

// SR-13: a peer that sends hundreds of fragments of a message_seq it will never
// complete during its own handshake, and then completes the handshake,
// used to pin up to about 2 MB for the whole call. With the limiter those
// fragments never reach pion and the heap does not keep them. The second
// half shows the flood does pin memory without the limiter, so
// the test detects a regression.
func TestPreHandshakeFragmentFloodIsBounded(t *testing.T) {
	const flood = 400
	for _, role := range []Role{RoleServer, RoleClient} {
		v, grown := floodedHandshake(t, role, flood, 40, false)
		t.Logf("role %d: live heap grew by %d bytes, %d datagrams dropped", role, grown, v.DroppedPreHandshake())
		if got := v.limiter.droppedSeq.Load(); got != flood {
			t.Fatalf("role %d: %d flood datagrams dropped, want %d", role, got, flood)
		}
		if grown > 512<<10 {
			t.Fatalf("role %d: live heap grew by %d bytes under a %d byte pre-handshake flood", role, grown, flood*4000)
		}
	}

	_, grown := floodedHandshake(t, RoleServer, flood, 40, true)
	t.Logf("without the limiter: live heap grew by %d bytes", grown)
	if grown < 1<<20 {
		t.Fatalf("without the limiter the heap grew by only %d bytes; the flood no longer "+
			"exercises pion's fragment buffer, so this test proves nothing", grown)
	}
}

// SR-13 review: zero-length fragments of a message_seq inside the peer's
// range stay far under the byte budget, but pion would keep each as a heap
// object; the fragment budget bounds them. The victim is the DTLS client,
// whose peer's range (up to 7) leaves room above the last message it uses.
// Here the flood fits the budget, so the handshake completes and what it
// pins is at most MaxHandshakeFragments objects; a larger flood spends the
// budget and the peer's own handshake fails (TestHandshakeFragmentUnits
// shows the cap). The second half shows pion keeps a larger flood without
// the limiter.
func TestPreHandshakeTinyFragmentFloodIsBounded(t *testing.T) {
	var fits [][]byte
	for i := 0; i < 3; i++ {
		fits = append(fits, tinyFragments(7, i*38, 38))
	}
	v, grown := floodedHandshakeWith(t, RoleClient, fits, false)
	t.Logf("live heap grew by %d bytes, %d fragments admitted", grown, v.limiter.fragments)
	if v.limiter.fragments > MaxHandshakeFragments {
		t.Fatalf("%d fragments admitted, budget %d", v.limiter.fragments, MaxHandshakeFragments)
	}
	if grown > 64<<10 {
		t.Fatalf("live heap grew by %d bytes under a tiny-fragment flood", grown)
	}

	var large [][]byte
	for i := 0; i < 24; i++ {
		large = append(large, tinyFragments(7, i*41, 41))
	}
	_, grown = floodedHandshakeWith(t, RoleClient, large, true)
	t.Logf("without the limiter: live heap grew by %d bytes", grown)
	if grown < 96<<10 {
		t.Fatalf("without the limiter the heap grew by only %d bytes; the flood proves nothing", grown)
	}
}

// The per-association budget: datagrams and bytes before the handshake
// ends, then nothing more is charged.
func TestHandshakeLimiterBudget(t *testing.T) {
	small := fragmentRecord(1, 0, 100, 0, 100)
	script := make([][]byte, 100)
	for i := range script {
		script[i] = small
	}
	pool := NewHandshakePool(1 << 30)
	l := newHandshakeLimiter(&scriptedConn{datagrams: script}, pool, false)
	if got := passedLimiter(l); got != PreHandshakeDatagrams {
		t.Fatalf("%d of 100 small datagrams passed, want %d", got, PreHandshakeDatagrams)
	}
	if got := l.droppedBudget.Load(); got != 100-PreHandshakeDatagrams {
		t.Fatalf("%d dropped over budget, want %d", got, 100-PreHandshakeDatagrams)
	}
	if got, want := pool.InUse(), int64(PreHandshakeDatagrams*len(small)); got != want {
		t.Fatalf("pool holds %d, want %d", got, want)
	}
	l.release()
	l.release()
	if got := pool.InUse(); got != 0 {
		t.Fatalf("pool holds %d after release, want 0", got)
	}

	// Bytes: 4 KB datagrams, the byte budget binds first.
	big := fragmentRecord(1, 0, 1<<20, 0, 4000)
	script = make([][]byte, 20)
	for i := range script {
		script[i] = big
	}
	l = newHandshakeLimiter(&scriptedConn{datagrams: script}, pool, false)
	if got, want := passedLimiter(l), PreHandshakeBytes/len(big); got != want {
		t.Fatalf("%d 4 KB datagrams passed, want %d", got, want)
	}
	l.release()

	// After the handshake: no budget, but the message_seq check stays.
	script = [][]byte{big, big, fragmentRecord(1, 8, 100, 0, 100), small}
	l = newHandshakeLimiter(&scriptedConn{datagrams: script}, pool, false)
	l.release()
	if got := passedLimiter(l); got != 3 {
		t.Fatalf("after the handshake %d of 4 datagrams passed, want 3", got)
	}
	if got := pool.InUse(); got != 0 {
		t.Fatalf("pool charged %d after the handshake", got)
	}
}

// The pool bounds associations together: once it is full a new
// association's datagrams are dropped until a charge is returned.
func TestHandshakePoolIsShared(t *testing.T) {
	d := fragmentRecord(1, 0, 1<<20, 0, 4000)
	script := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = d
		}
		return out
	}
	pool := NewHandshakePool(int64(3 * len(d)))
	first := newHandshakeLimiter(&scriptedConn{datagrams: script(2)}, pool, false)
	second := newHandshakeLimiter(&scriptedConn{datagrams: script(2)}, pool, true)
	if got := passedLimiter(first); got != 2 {
		t.Fatalf("first: %d passed, want 2", got)
	}
	if got := passedLimiter(second); got != 1 {
		t.Fatalf("second: %d passed, want 1 (pool full)", got)
	}
	if got := second.droppedPool.Load(); got != 1 || pool.Refused() != 1 {
		t.Fatalf("pool refusals: limiter %d, pool %d, want 1", got, pool.Refused())
	}
	first.release()
	third := newHandshakeLimiter(&scriptedConn{datagrams: script(2)}, pool, false)
	if got := passedLimiter(third); got != 2 {
		t.Fatalf("after a release %d passed, want 2", got)
	}
	second.release()
	third.release()
	if got := pool.InUse(); got != 0 {
		t.Fatalf("pool holds %d after every release", got)
	}
}

// Run returns its pool charge when the handshake fails as well.
func TestFailedHandshakeReturnsThePoolCharge(t *testing.T) {
	pool := NewHandshakePool(0)
	id, _ := GenerateIdentity()
	a, b := udpConn(t), udpConn(t)
	defer a.Close()
	defer b.Close()
	go func() {
		for i := 0; i < 8; i++ {
			_, _ = b.WriteTo(fragmentRecord(uint64(i), 0, 1<<20, i*1000, 1000), a.LocalAddr())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := Run(ctx, a, b.LocalAddr(), Params{Identity: id, Role: RoleServer, PeerFingerprint: id.Fingerprint(), Pool: pool}); err == nil {
		t.Fatal("handshake with garbage completed")
	}
	if got := pool.InUse(); got != 0 {
		t.Fatalf("pool holds %d after a failed handshake", got)
	}
}

func TestHandshakeSeqScanner(t *testing.T) {
	two := append(fragmentRecord(1, 3, 10, 0, 10), fragmentRecord(2, 6, 10, 0, 10)...)
	// Two fragments in one record, the second out of range.
	inOne := fragmentRecord(1, 2, 10, 0, 10)
	second := fragmentRecord(1, 9, 10, 0, 10)[recordHeaderLen:]
	inOne = append(inOne, second...)
	binary.BigEndian.PutUint16(inOne[11:13], uint16(len(inOne)-recordHeaderLen))
	protected := fragmentRecord(1, 9, 10, 0, 10)
	protected[4] = 1 // epoch 1: encrypted, not read
	cases := []struct {
		name string
		d    []byte
		max  uint16
		want bool
	}{
		{"in range", fragmentRecord(1, 5, 10, 0, 10), 5, false},
		{"above", fragmentRecord(1, 6, 10, 0, 10), 5, true},
		{"second record above", two, 5, true},
		{"second fragment above", inOne, 5, true},
		{"short protected record passes", protected, 5, false},
		{"long protected handshake record", append([]byte{22, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 65}, make([]byte, 65)...), 5, true},
		{"truncated header", fragmentRecord(1, 9, 10, 0, 10)[:20], 5, false},
		{"empty", nil, 5, false},
	}
	for _, c := range cases {
		if got := handshakeSeqAbove(c.d, c.max); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Fragment units: one per epoch-0 fragment, three per protected record.
func TestHandshakeFragmentUnits(t *testing.T) {
	fin := append([]byte{22, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 48}, make([]byte, 48)...)
	d := append(tinyFragments(2, 0, 5), fin...)
	if units, ok := scanHandshake(d, 5); !ok || units != 5+protectedRecordFragments {
		t.Fatalf("units %d ok %v, want %d true", units, ok, 5+protectedRecordFragments)
	}
	// The budget holds for the life of the association, after the handshake too.
	script := make([][]byte, 0, 20)
	for i := 0; i < 20; i++ {
		script = append(script, tinyFragments(2, i*10, 10))
	}
	l := newHandshakeLimiter(&scriptedConn{datagrams: script}, NewHandshakePool(0), false)
	l.release()
	if got, want := passedLimiter(l), MaxHandshakeFragments/10; got != want {
		t.Fatalf("%d datagrams of 10 fragments passed, want %d", got, want)
	}
}

func passedLimiter(l *handshakeLimiter) int {
	buf := make([]byte, 8192)
	n := 0
	for {
		if _, _, err := l.ReadFrom(buf); err != nil {
			return n
		}
		n++
	}
}

// FuzzHandshakeSeqScanner: the scanner never panics on peer input.
func FuzzHandshakeSeqScanner(f *testing.F) {
	f.Add(fragmentRecord(1, 3, 10, 0, 10))
	f.Add([]byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13})
	f.Fuzz(func(_ *testing.T, d []byte) {
		_ = handshakeSeqAbove(d, 5)
	})
}
