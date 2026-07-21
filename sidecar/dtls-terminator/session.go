package dtlssession

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"github.com/pion/dtls/v3"
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

// Result is the outcome of a completed DTLS-SRTP handshake.
type Result struct {
	SRTPKeys []byte                     // exported keying material (srtpKeyLen)
	Profile  dtls.SRTPProtectionProfile // negotiated SRTP profile

	conn *dtls.Conn // owned by the caller; tear down via Close() at session end
}

// Close tears down the DTLS association. Call it when the media session ends —
// NOT before, since (per pion) this also closes the underlying PacketConn.
func (r *Result) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

// Run drives the DTLS-SRTP handshake for one leg over conn (a UDP- or
// IPC-backed PacketConn) toward the peer at rAddr, verifies the peer's SDP
// fingerprint, and returns the exported SRTP keying material. Restricted to
// ECDHE-ECDSA-AES256-GCM-SHA384 + the AEAD_AES_256_GCM SRTP profile.
//
// On success the caller owns teardown via Result.Close() (which closes conn);
// Run does NOT close the caller-provided conn on the success path. On failure
// Run closes the DTLS conn it created.
func Run(ctx context.Context, conn net.PacketConn, rAddr net.Addr, p Params) (*Result, error) {
	if p.Identity == nil {
		return nil, fmt.Errorf("nil identity")
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
			return nil
		},
	}
	// Mutual auth: as server, request the peer's cert so its fingerprint is
	// verified (verification is via VerifyPeerCertificate above).
	if p.Role == RoleServer {
		cfg.ClientAuth = dtls.RequireAnyClientCert
	}

	var conn2 *dtls.Conn
	var err error
	switch p.Role {
	case RoleServer:
		conn2, err = dtls.Server(conn, rAddr, cfg)
	case RoleClient:
		conn2, err = dtls.Client(conn, rAddr, cfg)
	default:
		return nil, fmt.Errorf("invalid DTLS role %d", p.Role)
	}
	if err != nil {
		return nil, fmt.Errorf("create DTLS %v: %w", p.Role, err)
	}

	res, err := finishHandshake(ctx, conn2)
	if err != nil {
		// Tear down the DTLS conn we created (and its transport) on failure;
		// on success the caller owns it via Result.Close().
		_ = conn2.Close()
		return nil, err
	}
	return res, nil
}

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

func normalizeFP(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }
