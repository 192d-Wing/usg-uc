package dtlssession

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"
)

// contentTypeChangeCipherSpec is the record type of ChangeCipherSpec
// (RFC 6347 §4.1); the other wire constants are with groupGuard.
const contentTypeChangeCipherSpec = 20

// Budget for unprotected handshake-class datagrams after the handshake (see
// plaintextGate). A genuine peer sends them only as retransmissions of its
// final flight, when ours was lost: RFC 6347 §4.2.4.1 starts that timer at
// 1 s and doubles it, so five retransmissions fall inside 60 s (intervals
// of 1, 2, 4, 8, 16 s: sent at a cumulative 1, 3, 7, 15, 31 s; the sixth
// would be at 63 s), and a final flight (Certificate, ClientKeyExchange,
// CertificateVerify, ChangeCipherSpec) is a handful of datagrams with our
// P-384 certificates: five per flight is 25. The handshake timeouts of our
// peers (10 s soft client, 30 s pion) end such retransmission well inside
// the window.
//
// The gate passes or drops whole datagrams. A protected (epoch 1 or later)
// handshake record counts as handshake class as well: after the handshake a
// genuine peer sends one only as a retransmitted Finished, and pion would
// otherwise buffer its fragments, whose message_seq is encrypted, for the
// life of the connection. Once the budget is spent or the window is over,
// a retransmitted final flight, Finished included, is dropped.
const (
	// handshakeClassBudget is how many datagrams with an epoch-0 handshake
	// or ChangeCipherSpec record an established association accepts.
	handshakeClassBudget = 32
	// handshakeClassBytes is how many bytes of such datagrams it accepts.
	// pion keeps the fragments of a handshake message it cannot yet
	// reassemble for the life of the connection (fragment_buffer.go), so
	// this, not the datagram count, is what bounds the memory they can pin.
	handshakeClassBytes = 16 << 10
	// handshakeClassWindow is how long after the handshake they are
	// accepted at all.
	handshakeClassWindow = 60 * time.Second
)

// plaintextGate sits under pion for the whole association and, once the
// handshake has completed, lets no unprotected (epoch-0) record through to
// pion except a small, counted number of retransmitted final-flight
// datagrams:
//
//   - a datagram with an epoch-0 record that is neither handshake nor a
//     well-formed ChangeCipherSpec is dropped (alerts, application data, a
//     ChangeCipherSpec whose body is not the single octet 0x01);
//   - a datagram with epoch-0 handshake, well-formed ChangeCipherSpec or
//     protected handshake records passes while the association's budget
//     lasts (handshakeClassBudget datagrams and handshakeClassBytes bytes,
//     within handshakeClassWindow of the handshake's end) and is dropped
//     afterwards.
//
// NIST 800-53 Rev5: SC-5 / SC-23. pion accepts epoch-0 records for the life
// of a connection and does not authenticate them (conn.go:1042-1080: only
// records of a later epoch are decrypted). Left alone, anyone able to send
// from the peer's address could, with unprotected records:
//
//   - end an established association with one alert (conn.go:1174-1183); an
//     unprotected close_notify also makes pion answer with a close_notify of
//     its own, which is protected and which the relay forwards to the real
//     peer;
//   - do the same with one malformed ChangeCipherSpec: pion fails to parse
//     it and sends the real peer a protected fatal decode_error alert
//     (conn.go:1167-1170, :942-947);
//   - grow this process without bound: pion reassembles epoch-0 handshake
//     messages for the life of the connection and appends every complete
//     one to a cache that is never trimmed (handshake_cache.go:37-48), and
//     as server it resends its final flight to the real peer each time.
//
// Now that the association lives for the whole call all three matter. What
// a genuine peer still sends in epoch 0 after our handshake completed is
// only a retransmission of its last flight (handshake messages and
// ChangeCipherSpec, RFC 6347 §4.2.4): our handshake only completes once the
// peer's Finished has been verified, and the peer sent that in epoch 1, so
// everything it originates afterwards is in epoch 1 or later. The budget
// lets a lost final flight be recovered and bounds what the cache and the
// fragment buffer can grow by to handshakeClassBytes.
//
// POAM: POA&M-335 -- what is left: (1) within the budget pion still acts on
// forged handshake records (a resend of our final flight to the peer per
// datagram, cached messages); (2) an attacker who can send from the peer's
// address can spend the budget, after which a lost final flight of ours is
// not recovered and the peer's handshake fails at its own timeout (no media,
// fail closed); (3) during the handshake nothing is dropped here: alerts
// are unprotected by design then; (4) between pion completing the handshake
// and Run arming the gate there is a window of a few instructions in which
// a forged alert would still be honoured; (5) in front of this gate the SBC
// relay limits post-handshake DTLS-class datagrams per leg with a token
// bucket (burst 8, 4/s, sbc-media-core srtp_relay.rs) that is charged before
// authentication and shared by forged and genuine datagrams: a sender
// spoofing the peer's address at 4 datagrams a second or more keeps it
// empty for as long as it sends, with no 60 s limit, so the genuine peer's
// close_notify, alert or retransmitted final flight never reaches this
// process. The outcome is that of (2): the call ends by signalling only, or
// that handshake fails at the peer (fail closed, nothing forged accepted).
//
// The gate does not look at protected records: pion discards those that fail
// authentication (conn.go:1104-1109).
type plaintextGate struct {
	net.PacketConn
	established atomic.Bool
	// armed is when the handshake completed; written before established.
	armed time.Time
	// budget and window are handshakeClassBudget and handshakeClassWindow
	// (fields so that tests can shorten them).
	budget     uint64
	byteBudget uint64
	window     time.Duration
	// handshakeClass counts handshake-class datagrams seen after the
	// handshake, passed or not; handshakeClassBytes their bytes.
	handshakeClass      atomic.Uint64
	handshakeClassBytes atomic.Uint64
	// dropped counts datagrams withheld from pion because of an alert,
	// application-data or malformed ChangeCipherSpec record.
	dropped atomic.Uint64
	// droppedHandshake counts handshake-class datagrams withheld because
	// the budget was spent or the window over.
	droppedHandshake atomic.Uint64
}

func newPlaintextGate(conn net.PacketConn) *plaintextGate {
	return &plaintextGate{PacketConn: conn, budget: handshakeClassBudget, byteBudget: handshakeClassBytes, window: handshakeClassWindow}
}

// arm starts dropping: the handshake has completed.
func (g *plaintextGate) arm() {
	g.armed = time.Now()
	g.established.Store(true)
}

func (g *plaintextGate) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := g.PacketConn.ReadFrom(p)
		if err != nil || !g.established.Load() {
			return n, addr, err
		}
		switch scanUnprotected(p[:n]) {
		case unprotectedForged:
			g.dropped.Add(1)
		case unprotectedHandshake:
			// The clock is read only for these datagrams, never for a
			// protected one.
			if g.handshakeClass.Add(1) > g.budget || g.handshakeClassBytes.Add(uint64(n)) > g.byteBudget ||
				time.Since(g.armed) > g.window {
				g.droppedHandshake.Add(1)
				continue
			}
			return n, addr, nil
		default:
			return n, addr, nil
		}
	}
}

// What scanUnprotected found in a datagram.
type unprotectedKind int

const (
	// unprotectedNone: no epoch-0 record.
	unprotectedNone unprotectedKind = iota
	// unprotectedHandshake: handshake class: epoch-0 records, all of them
	// handshake or well-formed ChangeCipherSpec, or a protected handshake
	// record.
	unprotectedHandshake
	// unprotectedForged: an epoch-0 record a genuine peer cannot send after
	// the handshake.
	unprotectedForged
)

// scanUnprotected classifies a datagram by its epoch-0 records. It walks the
// records the way pion splits a datagram (by the length field); what does
// not parse as a record header is left for pion to discard.
func scanUnprotected(d []byte) unprotectedKind {
	kind := unprotectedNone
	for len(d) >= recordHeaderLen {
		contentType := d[0]
		epoch := binary.BigEndian.Uint16(d[3:5])
		length := int(binary.BigEndian.Uint16(d[11:13]))
		body := d[recordHeaderLen:]
		if epoch != 0 && contentType == contentTypeHandshake {
			kind = unprotectedHandshake
		}
		if epoch == 0 {
			switch contentType {
			case contentTypeHandshake:
				kind = unprotectedHandshake
			case contentTypeChangeCipherSpec:
				// RFC 5246 §7.1: a single octet of value 1. Anything else
				// makes pion send the peer a fatal alert.
				if length != 1 || len(body) < 1 || body[0] != 1 {
					return unprotectedForged
				}
				kind = unprotectedHandshake
			default:
				return unprotectedForged
			}
		}
		if length > len(body) {
			return kind
		}
		d = body[length:]
	}
	return kind
}
