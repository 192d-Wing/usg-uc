package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	dtlssession "github.com/192d-Wing/usg-uc/sidecar/dtls-terminator"
	"github.com/192d-Wing/usg-uc/sidecar/dtls-terminator/ipc"
)

const (
	// startTimeout bounds how long we wait for the relay's Start after Hello.
	startTimeout = 10 * time.Second
	// handshakeTimeout bounds the DTLS handshake once media records flow.
	handshakeTimeout = 30 * time.Second
)

// HandleSession terminates one DTLS-SRTP leg over conn (one relay IPC
// connection). It announces the sidecar identity's fingerprint, reads the
// relay's Start (role + peer fingerprint), drives the DTLS handshake with
// fingerprint verification, and replies with the exported SRTP keys — or an
// Error frame on failure. conn is closed on return.
func HandleSession(conn net.Conn, identity *dtlssession.Identity) error {
	ft := ipc.NewFramedTransport(conn)
	defer func() { _ = ft.Close() }()

	// Announce our fingerprint; the relay advertises it as the SDP a=fingerprint.
	if err := ft.SendFrame(encodeHello(identity.Fingerprint())); err != nil {
		return fmt.Errorf("send Hello: %w", err)
	}

	// Read the relay's Start (bounded).
	_ = ft.SetReadDeadline(time.Now().Add(startTimeout))
	raw, err := ft.RecvFrame()
	if err != nil {
		// A peer that hangs up before sending Start — e.g. the liveness probe,
		// which connects only to read our Hello and then closes — is not an error.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
			errors.Is(err, net.ErrClosed) {
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

	// Drive the DTLS handshake over the same connection (Dtls frames).
	pc := ipc.NewPacketConn(dtlsChannel{ft})
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()

	res, runErr := dtlssession.Run(ctx, pc, pc.PeerAddr(), dtlssession.Params{
		Identity:        identity,
		Role:            role,
		PeerFingerprint: peerFP,
	})
	if runErr != nil {
		_ = ft.SendFrame(encodeError(runErr.Error()))
		return runErr
	}
	// Send Ready before tearing down the DTLS conn (Close closes the transport).
	sendErr := ft.SendFrame(encodeReady(uint16(res.Profile), res.SRTPKeys))
	_ = res.Close()
	if sendErr != nil {
		return fmt.Errorf("send Ready: %w", sendErr)
	}
	return nil
}
