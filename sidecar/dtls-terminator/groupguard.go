package dtlssession

import (
	"encoding/binary"
	"net"
	"sync/atomic"
)

// Wire constants for the two messages the guard looks at (RFC 6347 §4.1,
// §4.2.2; RFC 8422 §5.4; RFC 5246 §7.4.8).
const (
	recordHeaderLen       = 13
	handshakeHeaderLen    = 12
	contentTypeAlert      = 21
	contentTypeHandshake  = 22
	typeServerKeyExchange = 12
	typeCertificateVerify = 15
	alertLevelFatal       = 2
	alertHandshakeFailure = 40
)

var (
	// ecParamsP384 is the start of ServerECDHParams inside the profile:
	// curve_type named_curve (3), namedcurve secp384r1 (24).
	ecParamsP384 = []byte{3, 0, 24}
	// schemeP384SHA384 is the start of a CertificateVerify inside the
	// profile: hash SHA-384 (5), signature ECDSA (3).
	schemeP384SHA384 = []byte{5, 3}
)

// groupGuard wraps the PacketConn handed to pion and enforces, on the wire,
// two parts of the profile that pion/dtls v3.1.5 cannot be configured to
// enforce: the ECDHE group and the scheme of our own CertificateVerify.
//
// NIST 800-53 Rev5: SC-12 / SC-13. CNSA 2.0 key establishment is ECDH on
// P-384. Config.EllipticCurves does not enforce that in pion: as server pion
// uses the first group of the client's supported_groups whatever its own list
// says (flight0handler.go:79), and as client it uses whatever group the
// server's ServerKeyExchange names (flight3handler). The negotiated group is
// not exposed afterwards either. It is, however, named in exactly one
// handshake message, ServerKeyExchange, which crosses this conn in the clear
// (epoch 0). Likewise Config.SignatureSchemes does not bind the scheme of the
// CertificateVerify pion sends as client: pion takes the first scheme of the
// server's CertificateRequest that fits the key type (flight5handler.go:212;
// signaturehash isCompatible accepts any ECDSA hash), so a server asking for
// ECDSA/SHA-256 would get a SHA-256 signature from our P-384 key. The scheme
// is the first two bytes of CertificateVerify, also in the clear.
//
// What the guard does depends on our DTLS role and on the direction:
//
//   - Server, outbound ServerKeyExchange (ours, built by pion on the client's
//     first group): if it names anything but secp384r1 the datagram is
//     withheld, a fatal handshake_failure alert is sent instead and the
//     handshake is aborted.
//   - Client, outbound CertificateVerify (ours): if its scheme is anything
//     but ecdsa_secp384r1_sha384 the datagram is withheld, the alert is sent
//     and the handshake is aborted. The out-of-profile signature never
//     leaves.
//   - Client, inbound ServerKeyExchange: a datagram holding one that names
//     anything but secp384r1 is dropped and counted; it is not delivered to
//     pion and it does NOT abort. Inbound epoch-0 datagrams are
//     unauthenticated: aborting on one would let anyone who can spoof the
//     peer's address end a handshake with a conformant peer using a single
//     28-byte datagram. Dropping is enough for the profile: a server that
//     really is on another group never gets its ServerKeyExchange through,
//     so the handshake cannot complete and ends at the caller's deadline
//     (Run then reports the drops).
//   - Everything else passes: as server we never act on an inbound
//     ServerKeyExchange (pion ignores the message in that role), and
//     inbound CertificateVerify schemes are checked by pion itself against
//     Config.SignatureSchemes.
//
// The outbound trip writes its own alert because pion sends nothing when a
// handshake is cancelled or its Conn is closed before completion (conn.go
// close(): close_notify only after a successful handshake). The alert takes
// the record sequence number of the record it replaces. Once tripped, every
// later write is swallowed, so nothing follows the alert.
//
// Known gap (RFC 5246 §7.2.2; tracked with POA&M-335): as client, a server
// that is refused by dropping its ServerKeyExchange gets no alert. The
// refusal only becomes final at the caller's deadline, and by the time
// HandshakeContext returns pion has closed the transport (conn.go:1382-1384,
// "handshake timeouts - closing underline connection"), so nothing can be
// written then. An alert sent earlier would have to guess that the handshake
// will fail and take a record sequence number that pion may still use for a
// retransmission, and it would rest on unauthenticated datagrams. The server
// runs into its own handshake timeout instead.
//
// Fragmentation. The check relies on how pion v3.1.5 reassembles
// (fragment_buffer.go): fragments are kept per message_seq keyed by fragment
// offset, the first fragment seen for an offset wins, the message is rebuilt
// by following the chain from the fragment at offset 0, and the message type
// (the whole header) is taken from that offset-0 fragment. The first bytes of
// a message pion processes as ServerKeyExchange therefore always come from a
// fragment of type ServerKeyExchange at offset 0, and every such fragment is
// checked here. To leave no room, the guard is stricter than that: every
// fragment of the message type that overlaps the checked prefix must start at
// offset 0, hold the whole prefix and match it. The scan also assumes that
// pion delimits the fragments inside one record by fragment_length alone and
// stops at a fragment_length that overruns the record (fragment_buffer.go
// push: errBufferTooSmall; the fragments before it stay buffered), which is
// how outsideProfile walks a record, so both see the same fragments. Known
// restriction: a peer
// whose first ServerKeyExchange fragment is shorter than three bytes, or that
// sends a fragment starting at offset 1 or 2, is refused although RFC 6347
// §4.2.3 allows such fragments; no known stack fragments that way.
// TestPionReassemblyAssumptions fails if a pion upgrade changes the version
// or this behaviour.
//
// POAM: POA&M-336 (SC-13 / interop) -- as server the sidecar refuses a client
// that supports secp384r1 but lists another group first, because pion follows
// the client's first entry. Selecting P-384 from the client's list needs a
// change in pion (upstream or patched); until then peers must list secp384r1
// first.
//
// POAM: POA&M-335 (SC-5) -- pion itself still ends the handshake on a forged
// plaintext fatal alert in epoch 0 (conn.go:1174-1183), and treats forged
// in-profile-looking plaintext handshake fragments as the peer's. The guard
// only makes sure it does not add a cheaper way to do the same. pion's
// epoch-0 replay window (64 records, conn.go:37) is likewise moved by
// unauthenticated records: the check at conn.go:1063-1071 runs before any
// authentication and a plaintext handshake record that parses is marked
// valid at conn.go:1152, so one forged epoch-0 record with a high sequence
// number makes pion discard the peer's genuine records below it as
// duplicates and the handshake stalls. This is the SBC-side equivalent of
// POA&M-334 in the soft client's proto-dtls.
type groupGuard struct {
	net.PacketConn
	// client is true when we are the DTLS client.
	client  bool
	armed   atomic.Bool
	tripped atomic.Bool
	// dropped counts inbound datagrams not delivered to pion.
	dropped atomic.Uint32
	abort   func()
}

func newGroupGuard(conn net.PacketConn, client bool, abort func()) *groupGuard {
	g := &groupGuard{PacketConn: conn, client: client, abort: abort}
	g.armed.Store(true)
	return g
}

// disarm stops the inspection once the handshake is over; later datagrams
// pass through untouched.
func (g *groupGuard) disarm() { g.armed.Store(false) }

// ReadFrom, as DTLS client, drops a datagram whose ServerKeyExchange is
// outside the profile. It never aborts: the datagram is unauthenticated.
func (g *groupGuard) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := g.PacketConn.ReadFrom(p)
		if err != nil || !g.client || !g.armed.Load() {
			return n, addr, err
		}
		if !serverKeyExchangeOutsideProfile(p[:n]) {
			return n, addr, nil
		}
		g.dropped.Add(1)
	}
}

// WriteTo withholds our own message when pion built it outside the profile:
// as server a ServerKeyExchange on another group (the client listed that
// group first), as client a CertificateVerify with another scheme (the server
// asked for it). The peer gets a fatal alert and the handshake is aborted.
//
// Once that has happened nothing more is written, armed or not: the fatal
// alert is the last record the peer gets (RFC 5246 §7.2.2).
func (g *groupGuard) WriteTo(p []byte, addr net.Addr) (int, error) {
	if g.tripped.Load() {
		return len(p), nil
	}
	if !g.armed.Load() {
		return g.PacketConn.WriteTo(p, addr)
	}
	var offending []byte
	if g.client {
		offending = outsideProfile(p, typeCertificateVerify, schemeP384SHA384)
	} else {
		offending = outsideProfile(p, typeServerKeyExchange, ecParamsP384)
	}
	if offending == nil {
		return g.PacketConn.WriteTo(p, addr)
	}
	if g.tripped.CompareAndSwap(false, true) {
		// RFC 5246 §7.2.2: tell the peer why nothing more will come. Same
		// version, epoch (0) and sequence number as the withheld record.
		alert := make([]byte, 0, recordHeaderLen+2)
		alert = append(alert, contentTypeAlert)
		alert = append(alert, offending[1:11]...)
		alert = append(alert, 0, 2, alertLevelFatal, alertHandshakeFailure)
		_, _ = g.PacketConn.WriteTo(alert, addr)
		g.abort()
	}
	return len(p), nil
}

// serverKeyExchangeOutsideProfile reports whether the datagram holds a
// plaintext ServerKeyExchange fragment that names, or could hide, a group
// other than secp384r1.
func serverKeyExchangeOutsideProfile(datagram []byte) bool {
	return outsideProfile(datagram, typeServerKeyExchange, ecParamsP384) != nil
}

// certificateVerifyOutsideProfile reports whether the datagram holds a
// plaintext CertificateVerify fragment that carries, or could hide, a scheme
// other than ecdsa_secp384r1_sha384.
func certificateVerifyOutsideProfile(datagram []byte) bool {
	return outsideProfile(datagram, typeCertificateVerify, schemeP384SHA384) != nil
}

// outsideProfile looks for a plaintext (epoch 0) handshake fragment of
// msgType whose message does not, or might not, start with prefix: a
// fragment that overlaps the prefix must start at offset 0, hold all of it
// and match. It returns the header of the record holding the first such
// fragment, or nil. Fragments inside a record are delimited by their
// fragment_length, as pion delimits them (see "Fragmentation" on groupGuard).
// Peer input: every length is checked before use, and anything that does not
// parse as a record or fragment ends the scan (pion drops it as well).
func outsideProfile(datagram []byte, msgType byte, prefix []byte) []byte {
	for len(datagram) >= recordHeaderLen {
		header := datagram[:recordHeaderLen]
		contentType := header[0]
		epoch := binary.BigEndian.Uint16(header[3:5])
		length := int(binary.BigEndian.Uint16(header[11:13]))
		if length > len(datagram)-recordHeaderLen {
			return nil
		}
		body := datagram[recordHeaderLen : recordHeaderLen+length]
		datagram = datagram[recordHeaderLen+length:]
		if contentType != contentTypeHandshake || epoch != 0 {
			continue
		}
		for len(body) >= handshakeHeaderLen {
			fragType := body[0]
			offset := uint24(body[6:9])
			fragLen := uint24(body[9:12])
			if fragLen > len(body)-handshakeHeaderLen {
				break
			}
			fragment := body[handshakeHeaderLen : handshakeHeaderLen+fragLen]
			body = body[handshakeHeaderLen+fragLen:]
			if fragType != msgType || offset >= len(prefix) {
				continue
			}
			if offset != 0 || fragLen < len(prefix) {
				return header
			}
			if string(fragment[:len(prefix)]) != string(prefix) {
				return header
			}
		}
	}
	return nil
}

func uint24(b []byte) int {
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}
