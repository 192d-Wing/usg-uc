// Package dtlssession is the transport-agnostic core of the usg DTLS-SRTP
// terminator sidecar: it generates the SBC's DTLS identity and drives the
// DTLS-SRTP handshake for one media leg over any net.PacketConn (later backed
// by the IPC channel to the Rust relay), returning the exported SRTP keys.
//
// Built with GOFIPS140=v1.26.0 / GODEBUG=fips140=on, every primitive here runs
// in the Go FIPS 140-3 module. Restricted to P-384 + AES-256-GCM (CNSA 2.0).
package dtlssession

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Identity is the SBC's DTLS-SRTP identity: an ephemeral self-signed P-384
// certificate plus its SHA-384 SDP fingerprint (RFC 8122). The private key
// never leaves this process — only the fingerprint crosses to the Rust relay
// for the SDP a=fingerprint.
type Identity struct {
	cert        tls.Certificate
	fingerprint string
}

// GenerateIdentity creates a fresh self-signed P-384 identity.
func GenerateIdentity() (*Identity, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-384 key: %w", err)
	}
	// RFC 5280 recommends a unique, unpredictable serial (up to 20 octets). The
	// cert is bound by its SDP fingerprint (RFC 8122), not chain-validated, so a
	// fixed serial is harmless here — but a random 128-bit one is the norm.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "usg-sbc-dtls"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("self-sign certificate: %w", err)
	}
	return &Identity{
		cert:        tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv},
		fingerprint: sdpFingerprint(der),
	}, nil
}

// Fingerprint returns the SDP a=fingerprint value, e.g. "sha-384 AB:CD:...".
func (id *Identity) Fingerprint() string { return id.fingerprint }

// sdpFingerprint computes the RFC 8122 SHA-384 fingerprint of a DER cert:
// "sha-384 " + uppercase hex bytes joined by ':'.
func sdpFingerprint(der []byte) string {
	sum := sha512.Sum384(der)
	hexb := make([]string, len(sum))
	for i, b := range sum {
		hexb[i] = fmt.Sprintf("%02X", b)
	}
	return "sha-384 " + strings.Join(hexb, ":")
}
