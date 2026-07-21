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

func main() {
	sockPath := flag.String("socket", "/run/usg/dtls-terminator.sock",
		"Unix-domain socket to accept relay sessions on")
	flag.Parse()

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
