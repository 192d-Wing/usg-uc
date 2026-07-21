package service

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFingerprintFile publishes the sidecar's SDP fingerprint to path so the
// Rust SBC can read it at startup and advertise it in the SDP a=fingerprint —
// the fingerprint is a call-independent property of the sidecar identity and
// MUST be available at signaling time, before any media/DTLS (RFC 8122/5763).
// This is the fingerprint-provisioning half of the relay contract; the
// Unix-domain socket carries only per-call DTLS records.
//
// The write is atomic (temp file + rename) so a concurrently-reading relay
// never observes a partial fingerprint. A trailing newline is included so the
// file is greppable/catable; readers should trim whitespace.
func WriteFingerprintFile(path, fingerprint string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".fp-*")
	if err != nil {
		return fmt.Errorf("create temp fingerprint file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we fail before the rename.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.WriteString(fingerprint + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write fingerprint: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp fingerprint file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename fingerprint file into place: %w", err)
	}
	return nil
}
