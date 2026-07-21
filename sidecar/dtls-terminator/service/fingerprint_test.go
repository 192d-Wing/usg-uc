package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFingerprintFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dtls.fp")
	const fp = "sha-384 AB:CD:EF:00:11:22"

	if err := WriteFingerprintFile(path, fp); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(got)) != fp {
		t.Fatalf("content %q, want %q", strings.TrimSpace(string(got)), fp)
	}

	// Overwrites atomically (rename), leaving no stray temp files behind.
	if err := WriteFingerprintFile(path, "sha-384 99:88:77"); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	got, _ = os.ReadFile(path)
	if strings.TrimSpace(string(got)) != "sha-384 99:88:77" {
		t.Fatalf("rewrite content %q", strings.TrimSpace(string(got)))
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".fp-") {
			t.Fatalf("stray temp file left behind: %s", e.Name())
		}
	}
}
