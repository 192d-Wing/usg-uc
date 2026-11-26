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
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
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

// maxSessionsEnv is the environment variable that sets the default of
// -max-sessions.
const maxSessionsEnv = "DTLS_TERMINATOR_MAX_SESSIONS"

// envInt returns the integer value of the environment variable name, or def
// if it is unset or empty. A value that is set but is not an integer is a
// configuration error: the process refuses to start rather than run with a
// limit other than the one asked for.
func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("refusing to start: $%s=%q is not an integer", name, v)
	}
	return n
}

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
	maxSessions := flag.Int("max-sessions", envInt(maxSessionsEnv, service.DefaultMaxSessions),
		"limit on concurrent sessions (one per terminated media leg, two per call); at the limit "+
			"new legs are refused. Size it to 2 x the SBC's max_calls. Default from $"+maxSessionsEnv)
	healthcheck := flag.Bool("healthcheck", false,
		"probe mode: connect to -socket, verify the sidecar is serving, and exit 0/1")
	flag.Parse()

	// Health-probe mode (Kubernetes startup/liveness): a lightweight client that
	// does not need the FIPS module or an identity of its own.
	if *healthcheck {
		os.Exit(runHealthcheck(*sockPath))
	}

	// A limit that is accepted is enforced; one that cannot be is refused.
	if *maxSessions < 1 {
		log.Fatalf("refusing to start: -max-sessions must be at least 1, got %d", *maxSessions)
	}

	// Refuse to run outside the FIPS module — the reason this sidecar exists
	// is DTLS-SRTP on the Go FIPS module (record GCM seal: POA&M-400).
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
	// net.Listen creates the socket without group write (umask). Grant it so the
	// sbc container can connect via the shared pod fsGroup (gid 1000) rather than
	// relying on both containers coincidentally running the same owner uid —
	// which silently breaks if the sbc container's runAsUser ever changes.
	if err := os.Chmod(*sockPath, 0o660); err != nil {
		log.Fatalf("chmod %s: %v", *sockPath, err)
	}
	log.Printf("dtls-terminator listening on %s (FIPS module %s)", *sockPath, fips140.Version())

	// Shutdown: on SIGINT/SIGTERM stop accepting (closing the listener
	// unblocks Accept with net.ErrClosed and removes the socket file) and end
	// every session: ctx is the sessions' context. A session holds its DTLS
	// association for the whole call, so there is nothing to wait out; each
	// one sends close_notify towards its peer and returns.
	// POAM: POA&M-341 -- stopping or restarting the sidecar (SIGTERM, image
	// upgrade, a liveness-probe restart) therefore ends the DTLS association
	// of every call in progress: a peer that honours close_notify (the soft
	// client does) ends its call, while the relay keeps its keys and keeps
	// relaying. A crash sends nothing. All outcomes are fail-secure (no
	// plaintext, no key change). Drain calls before restarting the sidecar.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Print("shutdown signal received: closing listener and ending sessions")
		_ = ln.Close()
	}()

	// NIST 800-53 Rev5: SC-5. Sessions are capped (-max-sessions); at the
	// cap a new leg is refused with an Error frame and the calls in progress
	// are not touched. Serve returns when the sessions have ended, or a few
	// seconds after the listener closed if one cannot finish.
	srv := &service.Server{Identity: identity, MaxSessions: *maxSessions}
	log.Printf("session limit: %d concurrent sessions (two per terminated call)", srv.Stats().Max)
	srv.Serve(ctx, ln)
}
