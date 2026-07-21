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

// Params configures one DTLS-SRTP leg.
type Params struct {
	Identity        *Identity
	Role            Role
	PeerFingerprint string // expected "sha-384 ..."; empty skips verification
}

// Result is the outcome of a completed DTLS-SRTP handshake.
type Result struct {
	SRTPKeys []byte                       // exported keying material (srtpKeyLen)
	Profile  dtls.SRTPProtectionProfile   // negotiated SRTP profile
}

// Run drives the DTLS-SRTP handshake for one leg over conn (a UDP- or
// IPC-backed PacketConn) toward the peer at rAddr, verifies the peer's SDP
// fingerprint, and returns the exported SRTP keying material. Restricted to
// ECDHE-ECDSA-AES256-GCM-SHA384 + the AEAD_AES_256_GCM SRTP profile.
func Run(ctx context.Context, conn net.PacketConn, rAddr net.Addr, p Params) (*Result, error) {
	if p.Identity == nil {
		return nil, fmt.Errorf("nil identity")
	}
	cfg := &dtls.Config{
		Certificates:           []tls.Certificate{p.Identity.cert},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_256_GCM},
		// Self-signed peers are bound by the SDP fingerprint (RFC 8122), not
		// PKI: skip chain verification and check the fingerprint ourselves.
		InsecureSkipVerify: true,
	}
	// DTLS-SRTP is mutually authenticated: as server, request the peer's cert
	// so its fingerprint can be verified (verification is via the callback).
	if p.Role == RoleServer {
		cfg.ClientAuth = dtls.RequireAnyClientCert
	}
	if p.PeerFingerprint != "" {
		want := normalizeFP(p.PeerFingerprint)
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer presented no certificate")
			}
			if got := normalizeFP(sdpFingerprint(rawCerts[0])); got != want {
				return fmt.Errorf("peer fingerprint mismatch: got %q want %q", got, want)
			}
			return nil
		}
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
	defer func() { _ = conn2.Close() }()

	// Drive the handshake to completion (bounded by ctx).
	if err := conn2.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("DTLS handshake: %w", err)
	}

	st, ok := conn2.ConnectionState()
	if !ok {
		return nil, fmt.Errorf("DTLS connection state unavailable after handshake")
	}
	keys, err := st.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyLen)
	if err != nil {
		return nil, fmt.Errorf("export SRTP keying material: %w", err)
	}
	prof, _ := conn2.SelectedSRTPProtectionProfile()
	return &Result{SRTPKeys: keys, Profile: prof}, nil
}

func normalizeFP(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }
