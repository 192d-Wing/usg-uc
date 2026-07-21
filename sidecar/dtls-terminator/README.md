# usg-dtls-terminator (sidecar)

DTLS-SRTP **key-agreement** sidecar for the SBC media plane.

The Rust media relay cannot perform FIPS-validated DTLS-SRTP: the Rust
ecosystem has no FIPS DTLS (rustls has no DTLS; `aws-lc-fips-sys` ships no
libssl; the `openssl` crate is non-FIPS). Go's native **FIPS 140-3 module**
(`GOFIPS140`) plus `pion/dtls` does — restricted to P-384 / AES-256-GCM, all
crypto runs in the certified module. So DTLS termination lives here, in Go, and
the Rust relay keeps ownership of the media socket and does the SRTP
encrypt/decrypt itself (via `proto-srtp` → aws-lc-FIPS).

## What this package does (`dtlssession`)

Transport-agnostic core: given a `net.PacketConn` (later backed by the IPC
channel to the Rust relay), it drives one DTLS-SRTP handshake for a media leg
and returns the **exported SRTP keying material** for the Rust side to install.

- `GenerateIdentity()` — ephemeral self-signed **P-384** cert + its RFC 8122
  **SHA-384** SDP fingerprint (the private key never leaves this process).
- `Run(ctx, conn, rAddr, Params{Identity, Role, PeerFingerprint})` — mutual-auth
  DTLS handshake (peer identity checked against the SDP fingerprint), then
  exports the 88-byte `AEAD_AES_256_GCM` SRTP keys.

The `ipc` package adapts that `net.PacketConn` to a channel to the Rust relay:
`NewPacketConn(NewFramedTransport(conn))` lets `Run` drive DTLS over a stream
IPC (a Unix-domain socket) exactly as over UDP. Framing is a uint16 length
prefix per DTLS datagram, decoded by a background reader so a read deadline
never desyncs a partial frame. The same `FrameTransport` interface fits a gRPC
bidi stream; a datagram IPC (`unixgram`) needs no framing at all.

The `service` package + `cmd/dtls-terminator` are the runnable sidecar: it
listens on a Unix-domain socket and terminates one DTLS-SRTP leg per
connection. Wire protocol (typed frames over the IPC): `Hello{fingerprint}` →
`Start{role, peerFP}` → `Dtls{record}` … → `Ready{profile, srtpKeys}` (or
`Error`). It refuses to start outside the FIPS module.

## Fingerprint provisioning (the signaling-time contract)

DTLS-SRTP requires the SBC's `a=fingerprint` to be in the SDP offer/answer, at
**signaling time — before any media/DTLS** (RFC 8122/5763). The fingerprint is
a call-independent property of the sidecar identity, so the sidecar publishes it
to a file at startup (`-fingerprint-file`, default `/run/usg/dtls-terminator.fp`,
written atomically). The SBC reads that file at startup and feeds it to its SDP
rewriter — the same split rtpengine uses (the media element owns the cert and
provides its fingerprint for the signaling element's SDP). The per-call
Unix-socket sessions carry only DTLS records.

Cert rotation must be coordinated: the sidecar holds one identity for its
lifetime; a restart mints a new fingerprint, so in-flight calls whose SDP
advertised the old one would fail the handshake.

Not yet here (next steps): the Rust-relay side (DTLS/SRTP demux on the media
socket + record pump over this IPC, then SRTP protect/unprotect via
`proto-srtp` → aws-lc-FIPS), plus the container/build wiring.

## Building / testing in FIPS mode

Requires Go **1.26+** (the `go` directive in `go.mod`; the module uses the
`crypto/fips140` reporting API and targets the v1.26.0 module. FIPS 140-3
support itself landed in Go 1.24). The compliance posture is
`GODEBUG=fips140=on` (all crypto primitives in the certified module; DTLS's
protocol-mandated deterministic-IV GCM does not pass the stricter `fips140=only`
audit — see `srtp-dtls-termination-plan` notes).

```sh
# Module selection is build-time. v1.26.0 = Go Cryptographic Module frozen from
# Go 1.26 (NIAP-certified per program); `certified` selects the latest CMVP-
# validated module instead.
GOFIPS140=v1.26.0 GODEBUG=fips140=on go test ./...
```

Restricted by config to `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` +
`SRTP_AEAD_AES_256_GCM` (CNSA 2.0); ChaCha20 suites are excluded so no
non-FIPS crypto is reachable.
