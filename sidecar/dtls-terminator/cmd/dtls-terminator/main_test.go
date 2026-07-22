package main

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestRunHealthcheck covers both probe outcomes: no listener (unhealthy) and a
// listener that sends the Hello frame on accept (healthy).
func TestRunHealthcheck(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "hc.sock")

	// Nothing listening yet → unhealthy.
	if code := runHealthcheck(sock); code != 1 {
		t.Fatalf("expected exit 1 with no listener, got %d", code)
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Frame: [len:2 BE][type=Hello][fingerprint].
		body := append([]byte{msgHelloType}, []byte("sha-384 AA:BB")...)
		//nolint:gosec // len(body) is small and bounded here.
		hdr := []byte{byte(len(body) >> 8), byte(len(body))}
		_, _ = conn.Write(append(hdr, body...))
		time.Sleep(50 * time.Millisecond)
	}()

	if code := runHealthcheck(sock); code != 0 {
		t.Fatalf("expected exit 0 against a serving listener, got %d", code)
	}
}
