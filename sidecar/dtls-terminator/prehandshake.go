package dtlssession

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
)

// Budgets for what a handshake may hand pion before it completes (see
// handshakeLimiter). A genuine handshake, retransmissions included, stays
// well below them: TestGenuineHandshakeFitsTheBudget measures both roles.
const (
	// PreHandshakeDatagrams is how many inbound datagrams one association
	// delivers to pion before its handshake has completed.
	PreHandshakeDatagrams = 32
	// PreHandshakeBytes is how many inbound bytes one association delivers
	// to pion before its handshake has completed.
	PreHandshakeBytes = 16 << 10
	// MaxHandshakeFragments is how many handshake fragments one association
	// delivers to pion over its life: each epoch-0 handshake fragment counts
	// one, each protected handshake record protectedRecordFragments. pion
	// keeps every fragment at a distinct offset as a heap object of its own
	// whatever its length, so bytes alone do not bound what it holds. A
	// genuine handshake has one fragment per message, about ten per flight
	// counting a protected Finished as three.
	MaxHandshakeFragments = 128
	// DefaultHandshakePoolBytes bounds the pre-handshake bytes of every
	// association still in its handshake, together (2,048 associations at
	// their full budget).
	DefaultHandshakePoolBytes = 32 << 20
)

// The highest handshake message_seq a peer sends in the profile (RFC 6347
// §4.2.2: numbered from 0 per side, incremented per message, retransmissions
// keep theirs).
//
//   - Peer is the client (we are server): ClientHello 0, ClientHello with
//     cookie 1 (pion always sends HelloVerifyRequest), Certificate 2,
//     ClientKeyExchange 3, CertificateVerify 4, Finished 5.
//   - Peer is the server (we are client): HelloVerifyRequest 0 (optional),
//     ServerHello, Certificate, ServerKeyExchange, CertificateRequest,
//     ServerHelloDone, NewSessionTicket (optional), Finished: at most 7.
//
// The peer-server bound assumes at most one HelloVerifyRequest: a server
// that sends two and a NewSessionTicket puts that ticket at 8 and is refused
// (no known stack does; POA&M-520).
const (
	maxPeerMessageSeqPeerClient = 5
	maxPeerMessageSeqPeerServer = 7
)

// Protected handshake records. In DTLS 1.2 the only one a peer sends is
// Finished: 12 bytes of verify_data behind a 12-byte handshake header, plus
// the 8-byte explicit nonce and 16-byte tag of AES-256-GCM, 48 bytes. A
// longer one is dropped; one of this length holds at most three fragments
// (40 bytes of plaintext / 12-byte headers), which is what it is charged.
const (
	maxProtectedHandshakeRecord = 64
	protectedRecordFragments    = 3
)

// HandshakePool bounds the inbound bytes that associations still in their
// handshake have delivered to pion, across every association that shares
// it. A charge is returned when its handshake ends, whether it completed,
// failed or timed out.
type HandshakePool struct {
	limit   int64
	used    atomic.Int64
	refused atomic.Uint64
}

// NewHandshakePool returns a pool of limit bytes (DefaultHandshakePoolBytes
// if limit is not positive).
func NewHandshakePool(limit int64) *HandshakePool {
	if limit <= 0 {
		limit = DefaultHandshakePoolBytes
	}
	return &HandshakePool{limit: limit}
}

// defaultPool is the pool of a Run whose Params name none: one per process.
var defaultPool = NewHandshakePool(DefaultHandshakePoolBytes)

// DefaultHandshakePool is the pool Run uses when Params name none.
func DefaultHandshakePool() *HandshakePool { return defaultPool }

// InUse is the bytes now charged by handshakes in progress.
func (p *HandshakePool) InUse() int64 { return p.used.Load() }

// Refused is how many datagrams were dropped because the pool was full.
func (p *HandshakePool) Refused() uint64 { return p.refused.Load() }

func (p *HandshakePool) take(n int64) bool {
	for {
		used := p.used.Load()
		if used+n > p.limit {
			p.refused.Add(1)
			return false
		}
		if p.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

// handshakeLimiter sits under pion (below groupGuard, above plaintextGate)
// for the life of the association.
//
// NIST 800-53 Rev5: SC-5 / SC-6. pion keeps every handshake fragment it has
// not yet reassembled, keyed by message_seq, up to 2,000,000 bytes and 1,000
// fragments per connection, and never trims that buffer
// (fragment_buffer.go); it also keeps every reassembled message for the
// transcript (handshake_cache.go). Fragments of a message_seq the peer never
// completes therefore stay for the whole call once the handshake has
// succeeded, and a session's own peer can pin about 2 MB that way. The
// limiter:
//
//   - drops, for the life of the association, every datagram holding an
//     unprotected (epoch 0) handshake fragment whose message_seq is above
//     the highest one the peer's role sends (maxPeerMessageSeq*): such a
//     fragment can never be reassembled into the handshake and would only
//     be kept, and every datagram with a protected handshake record longer
//     than a Finished (maxProtectedHandshakeRecord);
//   - for the life of the association, delivers at most
//     MaxHandshakeFragments handshake fragments (protected records counted
//     at the most they can hold);
//   - until the handshake has ended, delivers at most PreHandshakeDatagrams
//     datagrams and PreHandshakeBytes bytes per association, and charges
//     them to a HandshakePool shared by every association; a datagram over
//     either budget, or that the pool cannot take, is dropped and counted.
//     The pool charge is returned when Run ends (completed, failed or timed
//     out); what pion keeps of the admitted bytes after a completed
//     handshake is at most the per-association budgets: about 16 KiB of
//     data and MaxHandshakeFragments fragment objects.
//
// Dropping is fail closed: a flood can make a handshake fail at its
// deadline, it cannot make one complete. The limiter reads only record and
// fragment headers and never allocates.
//
// POAM: POA&M-520 -- protected (epoch 1) handshake fragments carry their
// message_seq encrypted, so the limiter cannot check it; it bounds them by
// record length and the fragment budget only.
type handshakeLimiter struct {
	net.PacketConn
	pool   *HandshakePool
	maxSeq uint16

	// fragments is charged on the read path only (pion's single reader),
	// against maxFragments.
	fragments    int
	maxFragments int

	mu        sync.Mutex
	open      bool // still in the handshake
	datagrams int
	bytes     int64

	droppedSeq    atomic.Uint64
	droppedBudget atomic.Uint64
	droppedPool   atomic.Uint64
	// inHandshake mirrors open for the read path's fast check.
	inHandshake atomic.Bool
}

func newHandshakeLimiter(conn net.PacketConn, pool *HandshakePool, weAreClient bool) *handshakeLimiter {
	if pool == nil {
		pool = defaultPool
	}
	maxSeq := uint16(maxPeerMessageSeqPeerClient)
	if weAreClient {
		maxSeq = maxPeerMessageSeqPeerServer
	}
	l := &handshakeLimiter{PacketConn: conn, pool: pool, maxSeq: maxSeq, maxFragments: MaxHandshakeFragments, open: true}
	if testDisableLimiter {
		l.maxSeq, l.maxFragments, l.open = 0xffff, 1<<30, false
	}
	l.inHandshake.Store(l.open)
	return l
}

// testDisableLimiter makes new limiters pass everything (tests only: shows
// what pion keeps without them).
var testDisableLimiter bool

// release ends the handshake budget and returns the pool charge. Safe to
// call more than once.
func (l *handshakeLimiter) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.open {
		return
	}
	l.open = false
	l.inHandshake.Store(false)
	l.pool.used.Add(-l.bytes)
}

// dropped is every datagram the limiter has withheld from pion.
func (l *handshakeLimiter) dropped() uint64 {
	return l.droppedSeq.Load() + l.droppedBudget.Load() + l.droppedPool.Load()
}

func (l *handshakeLimiter) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := l.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		units, ok := scanHandshake(p[:n], l.maxSeq)
		if !ok {
			l.droppedSeq.Add(1)
			continue
		}
		if l.fragments+units > l.maxFragments {
			l.droppedBudget.Add(1)
			continue
		}
		if !l.inHandshake.Load() || l.charge(int64(n)) {
			l.fragments += units
			return n, addr, nil
		}
	}
}

// charge admits a datagram of n bytes against the association's and the
// pool's budgets.
func (l *handshakeLimiter) charge(n int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.open {
		return true
	}
	if l.datagrams >= PreHandshakeDatagrams || l.bytes+n > PreHandshakeBytes {
		l.droppedBudget.Add(1)
		return false
	}
	if !l.pool.take(n) {
		l.droppedPool.Add(1)
		return false
	}
	l.datagrams++
	l.bytes += n
	return true
}

// scanHandshake walks a datagram's records the way pion delimits them (by
// their length fields; what does not parse ends the walk, as it ends
// pion's) and returns how many handshake fragments it would hand pion
// (epoch-0 fragments counted one each, a protected handshake record
// protectedRecordFragments). ok is false when the datagram must be dropped:
// it holds an epoch-0 handshake fragment with a message_seq above maxSeq,
// or a protected handshake record longer than maxProtectedHandshakeRecord.
func scanHandshake(d []byte, maxSeq uint16) (units int, ok bool) {
	for len(d) >= recordHeaderLen {
		contentType := d[0]
		epoch := binary.BigEndian.Uint16(d[3:5])
		length := int(binary.BigEndian.Uint16(d[11:13]))
		if length > len(d)-recordHeaderLen {
			return units, true
		}
		body := d[recordHeaderLen : recordHeaderLen+length]
		d = d[recordHeaderLen+length:]
		if contentType != contentTypeHandshake {
			continue
		}
		if epoch != 0 {
			if length > maxProtectedHandshakeRecord {
				return units, false
			}
			units += protectedRecordFragments
			continue
		}
		for len(body) >= handshakeHeaderLen {
			if binary.BigEndian.Uint16(body[4:6]) > maxSeq {
				return units, false
			}
			units++
			fragLen := uint24(body[9:12])
			if fragLen > len(body)-handshakeHeaderLen {
				break
			}
			body = body[handshakeHeaderLen+fragLen:]
		}
	}
	return units, true
}

// handshakeSeqAbove reports whether scanHandshake would drop the datagram.
func handshakeSeqAbove(d []byte, maxSeq uint16) bool {
	_, ok := scanHandshake(d, maxSeq)
	return !ok
}
