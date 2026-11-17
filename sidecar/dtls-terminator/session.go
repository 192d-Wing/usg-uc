package dtlssession

import (
	"context"
	"crypto/ecdsa"
	stdelliptic "crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

// Role is the SBC's DTLS role for a leg, derived from the negotiated a=setup.
type Role int

const (
	// RoleServer: the SBC is the DTLS server (peer offered a=setup:active).
	RoleServer Role = iota
	// RoleClient: the SBC is the DTLS client (peer is a=setup:passive).
	RoleClient
)

// srtpKeyLen is the DTLS-SRTP exported keying-material length for
// AEAD_AES_256_GCM: 2 × (32-byte key + 12-byte salt) (RFC 5764 / RFC 7714).
const srtpKeyLen = 88

// AES256GCMProfile is the only SRTP profile the terminator negotiates
// (CNSA 2.0): AEAD_AES_256_GCM.
const AES256GCMProfile = dtls.SRTP_AEAD_AES_256_GCM

// fpAlgPrefix is the required SDP fingerprint algorithm (normalized), CNSA 2.0.
const fpAlgPrefix = "SHA-384 "

// Params configures one DTLS-SRTP leg.
type Params struct {
	Identity *Identity
	Role     Role
	// PeerFingerprint is the peer's SDP a=fingerprint (RFC 8122), REQUIRED and
	// SHA-384 (CNSA 2.0), e.g. "sha-384 AB:CD:...". DTLS-SRTP is authenticated
	// by this fingerprint, so it must be present.
	PeerFingerprint string
}

// Result is a DTLS-SRTP association whose handshake has completed.
type Result struct {
	SRTPKeys []byte                     // exported keying material (srtpKeyLen)
	Profile  dtls.SRTPProtectionProfile // negotiated SRTP profile

	conn *dtls.Conn // owned by the caller; tear down via Close() at session end
	gate *plaintextGate
}

// DroppedUnprotected returns how many inbound datagrams were withheld from
// the association after the handshake because they carried an unprotected
// alert, application-data or malformed ChangeCipherSpec record (see
// plaintextGate). A genuine peer sends none, so a count above zero means
// someone forged traffic from its address.
func (r *Result) DroppedUnprotected() uint64 {
	if r == nil || r.gate == nil {
		return 0
	}
	return r.gate.dropped.Load()
}

// DroppedHandshake returns how many inbound datagrams with unprotected
// handshake or ChangeCipherSpec records were withheld from the association
// because its budget for them was spent or its window over (see
// plaintextGate). A genuine peer stays far below the budget.
func (r *Result) DroppedHandshake() uint64 {
	if r == nil || r.gate == nil {
		return 0
	}
	return r.gate.droppedHandshake.Load()
}

// Close ends the DTLS association: a close_notify alert is sent to the peer
// (unless the peer ended the association first) and, per pion, the
// underlying PacketConn is closed. Call it when the media session ends, NOT
// before: a peer that reads close_notify stops its media (RFC 5764 ties the
// SRTP session to the association), and an association that is gone cannot
// answer a retransmission of the peer's final flight (RFC 6347 §4.2.4).
func (r *Result) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

// Read returns the next application-data record of the association. A
// DTLS-SRTP association carries none (media is SRTP, beside it), so the
// point of calling Read is to learn when the association ends: io.EOF means
// the peer ended it (close_notify or a fatal alert), the transport ended, or
// Close was called. Any other error (a record that failed authentication, a
// warning alert, a read deadline) leaves the association up.
//
// pion keeps answering the peer's handshake retransmissions and alerts on
// its own goroutines for as long as the association is open, whether or not
// Read is called.
func (r *Result) Read(p []byte) (int, error) { return r.conn.Read(p) }

// SetReadDeadline bounds a Read in progress and later ones; the zero time
// removes the bound. A deadline in the past makes a blocked Read return.
func (r *Result) SetReadDeadline(t time.Time) error { return r.conn.SetReadDeadline(t) }

// Run drives the DTLS-SRTP handshake for one leg over conn (a UDP- or
// IPC-backed PacketConn) toward the peer at rAddr, verifies the peer's SDP
// fingerprint, and returns the exported SRTP keying material. Restricted to
// the CNSA 2.0 profile; nothing is negotiated down. What is enforced, and by
// what:
//
//   - cipher suite ECDHE-ECDSA-AES256-GCM-SHA384 and SRTP profile
//     AEAD_AES_256_GCM: pion configuration, the latter re-checked after the
//     handshake;
//   - extended master secret (RFC 7627): pion configuration (required);
//   - peer certificate: SDP fingerprint (SHA-384) and an ECDSA P-384 key,
//     in VerifyPeerCertificate;
//   - signatures we verify (the peer's ServerKeyExchange or
//     CertificateVerify): ECDSA P-384/SHA-384 only, pion configuration;
//   - signatures we make: ServerKeyExchange with ECDSA P-384/SHA-384 by pion
//     configuration; CertificateVerify (as client) by groupGuard, which
//     withholds any other scheme and aborts, because pion would follow the
//     server's CertificateRequest;
//   - ECDHE group secp384r1: by groupGuard on the ServerKeyExchange. As
//     server, a client that does not list secp384r1 FIRST in supported_groups
//     is refused with a handshake_failure alert, even if it supports the
//     group (POA&M-336). As client, a ServerKeyExchange on another group is
//     dropped unread, so a server that insists on one makes the handshake
//     fail at ctx's deadline rather than at once; that server gets no
//     alert (see the known gap on groupGuard).
//
// ctx must therefore carry a deadline; Run returns an error if it has none.
//
// On success the caller owns the association and its teardown via
// Result.Close() (which closes conn); Run does NOT close the caller-provided
// conn on the success path, and the association outlives ctx: ctx bounds the
// handshake only. On failure Run closes the DTLS conn it created.
func Run(ctx context.Context, conn net.PacketConn, rAddr net.Addr, p Params) (*Result, error) {
	if p.Identity == nil {
		return nil, fmt.Errorf("nil identity")
	}
	// As client an out-of-profile server is refused by dropping, which only
	// ends at the deadline: without one the handshake could run forever.
	if _, ok := ctx.Deadline(); !ok {
		return nil, errNoDeadline
	}
	// DTLS-SRTP is fingerprint-authenticated (RFC 8122): a missing fingerprint
	// would mean an unauthenticated peer, so fail closed rather than accept any
	// certificate. CNSA 2.0 requires SHA-384.
	want := normalizeFP(p.PeerFingerprint)
	if want == "" {
		return nil, fmt.Errorf("peer fingerprint required (DTLS-SRTP is fingerprint-authenticated)")
	}
	if !strings.HasPrefix(want, fpAlgPrefix) {
		return nil, fmt.Errorf("unsupported peer fingerprint algorithm (CNSA 2.0 requires sha-384): %q", p.PeerFingerprint)
	}

	cfg := &dtls.Config{
		Certificates:           []tls.Certificate{p.Identity.cert},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_256_GCM},
		// NIST 800-53 Rev5: SC-13. CNSA 2.0 requires SHA-384: sign
		// ServerKeyExchange with ECDSA P-384/SHA-384 (pion's default list
		// would pick ECDSA/SHA-256), offer only that scheme in
		// signature_algorithms and CertificateRequest, and accept nothing
		// else in the peer's ServerKeyExchange / CertificateVerify.
		//
		// This list does NOT bind the scheme of our own CertificateVerify:
		// as DTLS client pion takes the first scheme of the peer's
		// CertificateRequest that fits an ECDSA key, whatever its hash
		// (flight5handler.go:212, signaturehash isCompatible), so a server
		// that asks for ECDSA/SHA-256 first would be answered with a
		// SHA-256 signature. groupGuard enforces it instead: a
		// CertificateVerify with any scheme but ECDSA P-384/SHA-384 is
		// withheld and the handshake aborted. No residual is left on the
		// wire; the cost is that such a server is refused rather than
		// answered with a scheme further down its list.
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384},
		// NIST 800-53 Rev5: SC-12 / SC-13. CNSA 2.0 key establishment is
		// ECDH on P-384 only. pion's default list is X25519, P-256, P-384;
		// this makes P-384 the only group we offer as client and the group
		// we would pick ourselves. It does NOT make pion refuse another
		// group the peer chooses (see groupGuard, which does).
		EllipticCurves: []elliptic.Curve{elliptic.P384},
		// NIST 800-53 Rev5: SC-23. Require the extended master secret
		// (RFC 7627): pion's default only requests it and completes without.
		// The soft client requires it too.
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		// Self-signed peers are bound by the SDP fingerprint (RFC 8122), not
		// PKI: skip chain verification and check the fingerprint ourselves.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer presented no certificate")
			}
			if got := normalizeFP(sdpFingerprint(rawCerts[0])); got != want {
				return fmt.Errorf("peer fingerprint mismatch: got %q want %q", got, want)
			}
			// NIST 800-53 Rev5: SC-13 / IA-3. The fingerprint says which
			// certificate, not what kind: CNSA 2.0 requires the key in it to
			// be ECDSA on P-384 (the signature scheme alone does not fix the
			// curve of the key in TLS 1.2).
			return requireP384Key(rawCerts[0])
		},
	}
	// Mutual auth: as server, request the peer's cert so its fingerprint is
	// verified (verification is via VerifyPeerCertificate above).
	if p.Role == RoleServer {
		cfg.ClientAuth = dtls.RequireAnyClientCert
	}

	if p.Role != RoleServer && p.Role != RoleClient {
		return nil, fmt.Errorf("invalid DTLS role %d", p.Role)
	}
	// The ECDHE group and the scheme of our CertificateVerify are enforced
	// on the wire (see groupGuard).
	hctx, abort := context.WithCancel(ctx)
	defer abort()
	// Under the guard, for the life of the association: after the handshake
	// unprotected alerts are no longer let through to pion.
	gate := newPlaintextGate(conn)
	guard := newGroupGuard(gate, p.Role == RoleClient, abort)

	var conn2 *dtls.Conn
	var err error
	if p.Role == RoleServer {
		conn2, err = dtls.Server(guard, rAddr, cfg)
	} else {
		conn2, err = dtls.Client(guard, rAddr, cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("create DTLS %v: %w", p.Role, err)
	}

	res, err := finishHandshake(hctx, conn2)
	guard.disarm()
	if guard.tripped.Load() {
		// Whatever pion reported (or even if it finished meanwhile), a
		// message of ours outside the profile was withheld: fail closed.
		_ = conn2.Close()
		if res != nil {
			clear(res.SRTPKeys)
		}
		if p.Role == RoleServer {
			return nil, fmt.Errorf("DTLS handshake: %w", errGroupOutsideProfile)
		}
		return nil, fmt.Errorf("DTLS handshake: %w", errSchemeOutsideProfile)
	}
	if err != nil {
		// Tear down the DTLS conn we created (and its transport) on failure;
		// on success the caller owns it via Result.Close().
		_ = conn2.Close()
		if n := guard.dropped.Load(); n > 0 {
			return nil, fmt.Errorf("%w (%d datagram(s) dropped: %w)", err, n, errPeerGroupOutsideProfile)
		}
		return nil, err
	}
	res.gate = gate
	gate.arm()
	return res, nil
}

// Refusals by Run and groupGuard, for errors.Is.
var (
	// errNoDeadline: Run was called with a context that never expires.
	errNoDeadline = errors.New("DTLS handshake context has no deadline")
	// errGroupOutsideProfile: as server, the client listed a group other
	// than secp384r1 first.
	errGroupOutsideProfile = errors.New("key exchange group outside the profile (CNSA 2.0 requires ECDHE on P-384, listed first by the client)")
	// errSchemeOutsideProfile: as client, the server asked for a
	// CertificateVerify scheme other than ECDSA P-384/SHA-384.
	errSchemeOutsideProfile = errors.New("CertificateVerify scheme outside the profile (CNSA 2.0 requires ECDSA P-384/SHA-384)")
	// errPeerGroupOutsideProfile: as client, datagrams with a
	// ServerKeyExchange on another group were dropped. Unauthenticated: it
	// explains a failed handshake, it does not prove what the peer sent.
	errPeerGroupOutsideProfile = errors.New("ServerKeyExchange on a group outside the profile (CNSA 2.0 requires ECDHE on P-384)")
)

// finishHandshake completes the handshake, confirms the required SRTP profile
// was negotiated, and exports the SRTP keys. It does not close conn2.
func finishHandshake(ctx context.Context, conn2 *dtls.Conn) (*Result, error) {
	if err := conn2.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	// use_srtp is an optional DTLS extension: a plain handshake can succeed
	// without it. Require that the peer actually agreed to our SRTP profile,
	// otherwise the exported keys would guard media the peer isn't protecting.
	prof, ok := conn2.SelectedSRTPProtectionProfile()
	if !ok || prof != AES256GCMProfile {
		return nil, fmt.Errorf("peer did not negotiate the required SRTP profile (ok=%v profile=%v)", ok, prof)
	}
	st, ok := conn2.ConnectionState()
	if !ok {
		return nil, fmt.Errorf("DTLS connection state unavailable after handshake")
	}
	keys, err := st.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyLen)
	if err != nil {
		return nil, fmt.Errorf("export SRTP keying material: %w", err)
	}
	return &Result{SRTPKeys: keys, Profile: prof, conn: conn2}, nil
}

// requireP384Key parses the peer's leaf certificate and accepts it only if its
// public key is ECDSA on P-384 (CNSA 2.0).
func requireP384Key(der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("peer certificate does not parse: %w", err)
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("peer certificate key is not ECDSA (CNSA 2.0 requires ECDSA P-384)")
	}
	if key.Curve != stdelliptic.P384() {
		return fmt.Errorf("peer certificate key is not on P-384 (CNSA 2.0 requires ECDSA P-384)")
	}
	return nil
}

func normalizeFP(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }
