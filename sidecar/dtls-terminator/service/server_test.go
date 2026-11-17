package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
)

// SC-5 (PERF-012, SEC-015, NIST-014): at -max-sessions a new leg is refused
// with an Error frame, the sessions in progress are not touched, the
// liveness probe (which reads only Hello) keeps passing, and a slot that is
// freed is used again.
func TestServerRefusesSessionsAtTheLimit(t *testing.T) {
	dir, err := os.MkdirTemp("", "dtls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "svc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	id := mustIdentity(t)
	srv := &Server{Identity: id, MaxSessions: 2}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(served) }()
	t.Cleanup(func() { cancel(); _ = ln.Close(); <-served })

	// dial connects and reads Hello, as the relay and the probe both do.
	dial := func() ipc.FrameTransport {
		t.Helper()
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		ft := ipc.NewFramedTransport(conn)
		t.Cleanup(func() { _ = ft.Close() })
		raw, err := recvWithin(t, ft, 5*time.Second)
		if err != nil {
			t.Fatalf("read Hello: %v", err)
		}
		if typ, body, _ := splitFrame(raw); typ != msgHello || string(body) != id.Fingerprint() {
			t.Fatalf("want Hello with the fingerprint, got type %d", typ)
		}
		return ft
	}
	awaitActive := func(want int64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for srv.Stats().Active != want {
			if time.Now().After(deadline) {
				t.Fatalf("active sessions: %d, want %d", srv.Stats().Active, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	start := encodeStart(dtlssession.RoleServer, id.Fingerprint())

	// Two sessions fill the sidecar (they wait for the peer's ClientHello).
	first, second := dial(), dial()
	for _, ft := range []ipc.FrameTransport{first, second} {
		if err := ft.SendFrame(start); err != nil {
			t.Fatal(err)
		}
	}
	awaitActive(2)

	// The third leg: Hello, and Error in answer to Start, then closed.
	third := dial()
	if err := third.SendFrame(start); err != nil {
		t.Fatal(err)
	}
	raw, err := recvWithin(t, third, 5*time.Second)
	if err != nil {
		t.Fatalf("refused leg: %v", err)
	}
	if typ, body, _ := splitFrame(raw); typ != msgError || string(body) != ErrSessionLimit {
		t.Fatalf("refused leg: type %d %q, want Error %q", typ, body, ErrSessionLimit)
	}
	if _, err := recvWithin(t, third, 5*time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("refused leg not closed: %v", err)
	}
	// The probe: Hello is all it reads (dial checked it), then it hangs up.
	_ = dial().Close()

	if st := srv.Stats(); st.Active != 2 || st.Peak != 2 || st.Max != 2 || st.Refused != 2 {
		t.Fatalf("stats at the limit: %+v", st)
	}
	// The sessions in progress were not ended.
	for _, ft := range []ipc.FrameTransport{first, second} {
		if raw, err := recvWithin(t, ft, 200*time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("a session in progress got a frame or ended at the limit: %v %v", raw, err)
		}
	}

	// A freed slot is used again.
	_ = first.Close()
	awaitActive(1)
	fourth := dial()
	if err := fourth.SendFrame(start); err != nil {
		t.Fatal(err)
	}
	awaitActive(2)
	if raw, err := recvWithin(t, fourth, 200*time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("leg after a freed slot was not served: %v %v", raw, err)
	}

	// Shutdown ends what is left and Serve returns.
	cancel()
	_ = ln.Close()
	select {
	case <-served:
	case <-time.After(shutdownGrace + 5*time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
	if st := srv.Stats(); st.Active != 0 {
		t.Fatalf("sessions left after shutdown: %+v", st)
	}
}

// A zero limit means the default, which covers two legs for each of the
// SBC's default max_calls.
func TestServerDefaultLimit(t *testing.T) {
	if got := (&Server{}).Stats().Max; got != DefaultMaxSessions || got < 2*5000 {
		t.Fatalf("default limit %d", got)
	}
}
