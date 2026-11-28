package service

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
)

const (
	// DefaultMaxSessions is the session limit when none is configured: two
	// legs for each of the SBC's default general.max_calls (5000).
	DefaultMaxSessions = 10000
	// maxRefusing bounds the connections that are being told "session
	// limit" at one time; beyond it a connection is closed unanswered.
	maxRefusing = 64
	// statsInterval is how often the session count is logged.
	statsInterval = 60 * time.Second
	// shutdownGrace bounds the wait for sessions to end at shutdown. A
	// session's teardown is two writes of at most closeWriteTimeout each.
	shutdownGrace = 2*closeWriteTimeout + time.Second
)

// Server accepts relay connections and runs one session per connection, up
// to MaxSessions at a time.
//
// NIST 800-53 Rev5: SC-5 / SC-6. A session holds its DTLS association, five
// goroutines and about 70 KiB (measured, see the README) for the whole call,
// so the number of sessions is what sizes this process. A session's own peer
// can make it keep about 55 KiB more: 16 KiB of input during the handshake
// (dtlssession.PreHandshakeBytes) and 16 KiB after it (the plaintext gate's
// byte budget), in at most dtlssession.MaxHandshakeFragments fragments. Input of handshakes still in progress is bounded for the
// process as a whole by dtlssession's handshake pool (32 MiB), returned when
// each handshake ends. The relay opens one per terminated leg and is
// itself bounded by the SBC's max_calls; the limit here is the sidecar's own
// bound, so that a relay fault that leaks connections, or a sidecar sized
// below the SBC's call limit, makes new legs fail (the call is refused, fail
// closed) instead of taking the process to its memory or descriptor limit,
// which would end every call's association at once. There is no idle or
// lifetime limit: a session lasts as long as the relay holds its connection.
type Server struct {
	Identity *dtlssession.Identity
	// MaxSessions is the limit on concurrent sessions; DefaultMaxSessions
	// if zero or negative.
	MaxSessions int

	active   atomic.Int64
	peak     atomic.Int64
	refusing atomic.Int64
	refused  atomic.Uint64
	// run is HandleSession; a test replaces it.
	run func(context.Context, net.Conn, *dtlssession.Identity) error
}

// Stats is the session count of a Server.
type Stats struct {
	Active  int64  // sessions now
	Peak    int64  // most sessions at one time since start
	Max     int64  // the limit
	Refused uint64 // connections refused at the limit since start
	// HandshakePoolBytes is the pre-handshake input now held by handshakes
	// in progress; HandshakePoolRefused the datagrams dropped because the
	// pool was full, since start.
	HandshakePoolBytes   int64
	HandshakePoolRefused uint64
}

// Stats returns the current counts.
func (s *Server) Stats() Stats {
	pool := dtlssession.DefaultHandshakePool()
	return Stats{
		Active: s.active.Load(), Peak: s.peak.Load(), Max: int64(s.max()), Refused: s.refused.Load(),
		HandshakePoolBytes: pool.InUse(), HandshakePoolRefused: pool.Refused(),
	}
}

func (s *Server) max() int {
	if s.MaxSessions <= 0 {
		return DefaultMaxSessions
	}
	return s.MaxSessions
}

// Serve accepts connections on ln until it is closed, and returns once the
// sessions have ended or shutdownGrace after that is over. ctx is the
// sessions' context: cancelling it ends every session (close_notify towards
// the peer, Error to the relay). The caller closes ln, normally when ctx is
// done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) {
	run := s.run
	if run == nil {
		run = HandleSession
	}
	limit := int64(s.max())

	statsDone := make(chan struct{})
	defer close(statsDone)
	go s.logStats(statsDone)

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
		// Only this loop adds, so the check cannot be overrun.
		if s.active.Load() >= limit {
			s.refuse(conn)
			continue
		}
		n := s.active.Add(1)
		if n > s.peak.Load() {
			s.peak.Store(n)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.active.Add(-1)
			if err := run(ctx, conn, s.Identity); err != nil {
				log.Printf("session error: %v", err)
			}
		}()
	}

	// POAM: POA&M-341 -- every session ends here with close_notify towards
	// its peer. The wait is bounded: a session that cannot finish its
	// teardown does not keep the process from exiting.
	ended := make(chan struct{})
	go func() { wg.Wait(); close(ended) }()
	select {
	case <-ended:
		log.Print("all sessions ended; exiting")
	case <-time.After(shutdownGrace):
		log.Printf("exiting with %d session(s) still ending after %s", s.active.Load(), shutdownGrace)
	}
}

// refuse turns a connection away at the session limit.
func (s *Server) refuse(conn net.Conn) {
	// NIST 800-53 Rev5: AU-2. The first refusal and every 1000th are
	// logged at once; the running count is in the periodic line.
	if n := s.refused.Add(1); n == 1 || n%1000 == 0 {
		log.Printf("session limit reached (max-sessions=%d): %d connection(s) refused so far", s.max(), n)
	}
	if s.refusing.Load() >= maxRefusing {
		_ = conn.Close()
		return
	}
	s.refusing.Add(1)
	go func() {
		defer s.refusing.Add(-1)
		RefuseSession(conn, s.Identity)
	}()
}

// logStats writes the session count once per statsInterval while it is not
// zero or has changed. NIST 800-53 Rev5: AU-2. This is a log line, not a
// metric: it supports SI-4 only where the container log is collected and
// alerted on; nothing is exported and nothing alerts before the session
// cap is reached.
//
// POAM: POA&M-342 -- no exported session gauge or metrics endpoint.
func (s *Server) logStats(done <-chan struct{}) {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	var last Stats
	for {
		select {
		case <-done:
			return
		case <-t.C:
			st := s.Stats()
			if st == last && st.Active == 0 {
				continue
			}
			last = st
			log.Printf("sessions: active=%d peak=%d max=%d refused=%d handshake_pool_bytes=%d handshake_pool_refused=%d",
				st.Active, st.Peak, st.Max, st.Refused, st.HandshakePoolBytes, st.HandshakePoolRefused)
		}
	}
}
