package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
)

const (
	// startTimeout bounds how long we wait for the relay's Start after Hello.
	startTimeout = 10 * time.Second
	// handshakeTimeout bounds the DTLS handshake once media records flow. It
	// bounds the handshake only: the association that follows lives as long
	// as the relay keeps the connection open.
	handshakeTimeout = 30 * time.Second
	// closeWriteTimeout bounds the frames written while a session is torn
	// down (close_notify, Error), so that a relay that has stopped reading
	// cannot keep an ended session alive.
	closeWriteTimeout = 2 * time.Second
	// discardBuffer is the read buffer for the association after the
	// handshake. DTLS-SRTP carries no application data, so what is read is
	// thrown away: a record that does not fit is reported by pion as an
	// error about that one record ("buffer is too small"), which
	// holdAssociation treats like any other and reads on. Kept small because
	// there is one per session for the whole call.
	discardBuffer = 64
	// refusedStartTimeout bounds how long a session refused for lack of
	// room waits for the relay's Start before it answers with Error.
	refusedStartTimeout = 2 * time.Second
)

// Messages of the Error frame that reports the end of an association after
// Ready, or a refused session. Each starts with a fixed token, up to the
// colon, which the relay maps to the reason of its own
// dtls.association.closed record; the relay ends its pumps on any Error.
const (
	// ErrPeerCloseNotify: the peer sent close_notify (and pion answered it).
	ErrPeerCloseNotify = "peer-close-notify: the peer ended the DTLS association with close_notify"
	// ErrPeerFatalAlert: the peer sent a fatal alert.
	ErrPeerFatalAlert = "peer-fatal-alert: the peer ended the DTLS association with a fatal alert"
	// ErrShutdown: the sidecar is stopping.
	ErrShutdown = "sidecar-shutdown: the DTLS terminator is stopping"
	// ErrSessionLimit: the sidecar is at -max-sessions.
	ErrSessionLimit = "session-limit: the DTLS terminator is at its session limit"
)

// HandleSession terminates one DTLS-SRTP leg over conn (one relay IPC
// connection). It announces the sidecar identity's fingerprint, reads the
// relay's Start (role + peer fingerprint), drives the DTLS handshake with
// fingerprint verification, and replies with the exported SRTP keys, or an
// Error frame on failure.
//
// Ready is not the end of the session. The DTLS association stays open and
// Dtls frames keep flowing in both directions (RFC 5764: the association
// lives as long as the SRTP session it keyed; RFC 6347 §4.2.4: a
// retransmitted final flight of the peer is answered) until one of:
//
//   - the relay closes the connection, or its sending half: the call is
//     over. A close_notify is written back, which reaches the peer if the
//     relay is still reading (it is when it only closed its sending half);
//   - the peer ends the association (close_notify or a fatal alert): the
//     relay is told with an Error frame that says which;
//   - ctx is cancelled (the sidecar is stopping): close_notify, then an
//     Error frame.
//
// Nothing else ends it: there is no idle or lifetime limit after Ready, a
// call may last as long as the relay holds the connection. conn is closed on
// return, and every goroutine of the session has ended or is about to (they
// end on the closed connection).
func HandleSession(ctx context.Context, conn net.Conn, identity *dtlssession.Identity) error {
	return handleSession(ctx, conn, identity, handshakeTimeout)
}

func handleSession(ctx context.Context, conn net.Conn, identity *dtlssession.Identity, hsTimeout time.Duration) error {
	ft := ipc.NewFramedTransport(conn)
	defer func() { _ = ft.Close() }()

	// Announce our fingerprint; the relay advertises it as the SDP a=fingerprint.
	if err := ft.SendFrame(encodeHello(identity.Fingerprint())); err != nil {
		return fmt.Errorf("send Hello: %w", err)
	}

	// Read the relay's Start (bounded, and given up when the sidecar stops).
	_ = ft.SetReadDeadline(time.Now().Add(startTimeout))
	stopStart := context.AfterFunc(ctx, func() { _ = ft.SetReadDeadline(time.Unix(1, 0)) })
	raw, err := ft.RecvFrame()
	stopStart()
	if err != nil {
		// A peer that hangs up before sending Start — e.g. the liveness probe,
		// which connects only to read our Hello and then closes — is not an error.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
			errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("read Start: %w", err)
	}
	_ = ft.SetReadDeadline(time.Time{})
	t, body, err := splitFrame(raw)
	if err != nil {
		return err
	}
	if t != msgStart {
		return fmt.Errorf("expected Start, got message type %d", t)
	}
	role, peerFP, err := decodeStart(body)
	if err != nil {
		return err
	}

	// Drive the DTLS handshake over the same connection (Dtls frames). The
	// deadline is for the handshake only.
	ch := &dtlsChannel{inner: ft}
	pc := ipc.NewPacketConn(ch)
	hctx, cancel := context.WithTimeout(ctx, hsTimeout)
	res, runErr := dtlssession.Run(hctx, pc, pc.PeerAddr(), dtlssession.Params{
		Identity:        identity,
		Role:            role,
		PeerFingerprint: peerFP,
	})
	cancel()
	if runErr != nil {
		sendClosing(ft, encodeError(runErr.Error()))
		return runErr
	}

	// NIST 800-53 Rev5: SC-12 (best effort). The relay has the exported SRTP
	// keys once Ready is written, and this process does not need its copies
	// for the rest of the call: the exporter's output, the Ready frame
	// (built in one buffer) and the framing layer's copy of it
	// (ipc.SendFrame) are overwritten. What stays in this process is pion's
	// DTLS master secret, for as long as the association lives, from which
	// the same keys can be exported again; a memory image of the sidecar
	// taken during a call therefore still yields them (POA&M-330).
	ready := encodeReady(uint16(res.Profile), res.SRTPKeys)
	sendErr := ft.SendFrame(ready)
	clear(ready)
	clear(res.SRTPKeys)
	if sendErr != nil {
		_ = res.Close()
		return fmt.Errorf("send Ready: %w", sendErr)
	}
	return holdAssociation(ctx, ft, ch, res)
}

// holdAssociation keeps the association open after Ready and returns when it
// has ended, having told the peer (close_notify) or the relay (Error) as far
// as the connection still allows. See HandleSession for what ends it.
func holdAssociation(ctx context.Context, ft ipc.FrameTransport, ch *dtlsChannel, res *dtlssession.Result) error {
	// A cancelled ctx interrupts the blocked Read below; the teardown itself
	// runs on this goroutine.
	stop := context.AfterFunc(ctx, func() { _ = res.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	// NIST 800-53 Rev5: AU-2 / SC-5. One line per session, not per datagram.
	defer func() {
		if n := res.DroppedUnprotected(); n > 0 {
			log.Printf("session: %d datagram(s) with an unprotected alert, application-data or malformed "+
				"ChangeCipherSpec record dropped after the handshake (forged from the peer's address)", n)
		}
		if n := res.DroppedHandshake(); n > 0 {
			log.Printf("session: %d datagram(s) with unprotected handshake records dropped after the "+
				"handshake: over the association's budget (forged from the peer's address)", n)
		}
	}()

	buf := make([]byte, discardBuffer)
	alertsBefore := ch.alertsSent()
	for {
		_, err := res.Read(buf)
		if err == nil {
			// Application data. DTLS-SRTP carries none; it is read so that
			// pion's record loop is never held up, and dropped.
			continue
		}
		relayErr := ch.relayEnded()
		switch {
		case ctx.Err() != nil:
			// POAM: POA&M-341 -- a sidecar stop ends the association of
			// every call in progress.
			closeAssociation(ft, res)
			sendClosing(ft, encodeError(ErrShutdown))
			log.Printf("session: association ended: %s", reasonToken(ErrShutdown))
			return nil
		case relayErr != nil:
			// The call is over (or the connection broke). The close_notify
			// reaches the peer if the relay is still reading.
			closeAssociation(ft, res)
			if errors.Is(relayErr, io.EOF) || errors.Is(relayErr, io.ErrUnexpectedEOF) ||
				errors.Is(relayErr, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("relay connection: %w", relayErr)
		case errors.Is(err, io.EOF):
			// The peer ended the association and pion has closed it; nothing
			// more goes to the peer. pion reports close_notify and a fatal
			// alert alike (io.EOF), but it answers a close_notify with one
			// of its own before it closes (conn.go:1177-1183) and a fatal
			// alert with nothing, and after Ready it sends no other alert
			// unless an authenticated record of the peer failed to decode.
			// So an alert record of ours on the wire means close_notify.
			// NIST 800-53 Rev5: AU-3.
			reason := ErrPeerFatalAlert
			if ch.alertsSent() > alertsBefore {
				reason = ErrPeerCloseNotify
			}
			sendClosing(ft, encodeError(reason))
			_ = res.Close()
			log.Printf("session: association ended: %s", reasonToken(reason))
			return nil
		}
		// Anything else is about one record (it failed authentication, it
		// was a warning alert): the association is still up. Such records
		// can be forged by anyone who can send from the peer's address, so
		// they must not be able to end a call.
	}
}

// closeAssociation ends the association from our side: one close_notify.
func closeAssociation(ft ipc.FrameTransport, res *dtlssession.Result) {
	_ = ft.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
	_ = res.Close()
}

// sendClosing writes a last control frame, bounded and best effort.
func sendClosing(ft ipc.FrameTransport, f []byte) {
	_ = ft.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
	_ = ft.SendFrame(f)
}

// reasonToken returns the fixed token an Error message starts with.
func reasonToken(msg string) string {
	token, _, _ := strings.Cut(msg, ":")
	return token
}

// RefuseSession answers a connection that cannot be served because the
// sidecar is at its session limit: Hello as always (the liveness probe reads
// only that, and must keep passing while the sidecar is full), then, once
// the relay has sent Start, Error{ErrSessionLimit}. No DTLS state is
// created. Bounded by refusedStartTimeout; conn is closed on return.
//
// NIST 800-53 Rev5: SC-5 (overload fails new legs, not the calls in
// progress).
func RefuseSession(conn net.Conn, identity *dtlssession.Identity) {
	ft := ipc.NewFramedTransport(conn)
	defer func() { _ = ft.Close() }()
	_ = ft.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
	if err := ft.SendFrame(encodeHello(identity.Fingerprint())); err != nil {
		return
	}
	_ = ft.SetReadDeadline(time.Now().Add(refusedStartTimeout))
	if _, err := ft.RecvFrame(); err != nil {
		return // the probe, or a relay that gave up
	}
	sendClosing(ft, encodeError(ErrSessionLimit))
}
