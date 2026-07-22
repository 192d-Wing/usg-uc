// Command dtls-terminator is the DTLS-SRTP terminator sidecar. It listens on a
// Unix-domain socket for the Rust media relay and terminates one DTLS-SRTP leg
// per connection, entirely inside the Go FIPS 140-3 module.
//
// Build + run in FIPS mode:
//
//	GOFIPS140=v1.26.0 go build ./cmd/dtls-terminator
//	GODEBUG=fips140=on ./dtls-terminator -socket /run/usg/dtls-terminator.sock
package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/service"
)

// maxFrame bounds a health-probe read; mirrors the IPC frame limit.
const maxFrame = 4096

// msgHelloType is the wire type byte of the sidecar's Hello frame (see
// service/protocol.go msgHello). Duplicated here so the health probe stays a
// standalone client that does not import the session internals.
const msgHelloType = 1

// runHealthcheck connects to the sidecar socket and reads the Hello frame it
// sends on every accepted connection. Success proves the accept loop is live and
// serving (not merely that the socket file exists — which lingers after a crash).
// Returns a process exit code.
func runHealthcheck(sockPath string) int {
	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		log.Printf("healthcheck: dial %s: %v", sockPath, err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		log.Printf("healthcheck: read Hello length: %v", err)
		return 1
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n < 1 || n > maxFrame {
		log.Printf("healthcheck: bad Hello frame length %d", n)
		return 1
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		log.Printf("healthcheck: read Hello body: %v", err)
		return 1
	}
	if body[0] != msgHelloType {
		log.Printf("healthcheck: expected Hello, got message type %d", body[0])
		return 1
	}
	return 0
}

func main() {
	sockPath := flag.String("socket", "/run/usg/dtls-terminator.sock",
		"Unix-domain socket to accept relay sessions on")
	fpFile := flag.String("fingerprint-file", "/run/usg/dtls-terminator.fp",
		"file to publish the SDP fingerprint to (read by the SBC at signaling time)")
	healthcheck := flag.Bool("healthcheck", false,
		"probe mode: connect to -socket, verify the sidecar is serving, and exit 0/1")
	flag.Parse()

	// Health-probe mode (Kubernetes startup/liveness): a lightweight client that
	// does not need the FIPS module or an identity of its own.
	if *healthcheck {
		os.Exit(runHealthcheck(*sockPath))
	}

	// Refuse to run outside the FIPS module — the entire reason this sidecar
	// exists is FIPS-validated DTLS-SRTP.
	if !fips140.Enabled() {
		log.Fatal("refusing to start: not in FIPS mode " +
			"(build with GOFIPS140=v1.26.0 and run with GODEBUG=fips140=on)")
	}

	identity, err := dtlssession.GenerateIdentity()
	if err != nil {
		log.Fatalf("generate DTLS identity: %v", err)
	}
	log.Printf("DTLS identity fingerprint: %s", identity.Fingerprint())

	// Publish the fingerprint for the SBC to read at signaling time (it must
	// appear in the SDP a=fingerprint before any media/DTLS). Do this before
	// accepting sessions so the file exists once we are up.
	if err := service.WriteFingerprintFile(*fpFile, identity.Fingerprint()); err != nil {
		log.Fatalf("publish fingerprint to %s: %v", *fpFile, err)
	}
	log.Printf("published fingerprint to %s", *fpFile)

	// Bind the listening socket (replacing any stale one).
	_ = os.Remove(*sockPath)
	ln, err := net.Listen("unix", *sockPath)
	if err != nil {
		log.Fatalf("listen %s: %v", *sockPath, err)
	}
	log.Printf("dtls-terminator listening on %s (FIPS module %s)", *sockPath, fips140.Version())

	// Graceful shutdown: on SIGINT/SIGTERM stop accepting and drain in-flight
	// sessions (closing the listener unblocks Accept with net.ErrClosed and
	// removes the socket file).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Print("shutdown signal received: closing listener and draining sessions")
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break // listener closed by shutdown
			}
			// Transient error (e.g. fd exhaustion): back off instead of
			// spinning at 100% CPU retrying immediately.
			log.Printf("accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := service.HandleSession(conn, identity); err != nil {
				log.Printf("session error: %v", err)
			}
		}()
	}

	wg.Wait()
	log.Print("all sessions drained; exiting")
}
