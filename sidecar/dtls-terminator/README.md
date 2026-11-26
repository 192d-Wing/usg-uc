# usg-dtls-terminator (sidecar)

DTLS-SRTP **key-agreement** sidecar for the SBC media plane.

The Rust media relay cannot perform DTLS-SRTP on a FIPS module: the Rust
ecosystem has no FIPS DTLS (rustls has no DTLS; `aws-lc-fips-sys` ships no
libssl; the `openssl` crate is non-FIPS). Go's native **FIPS 140-3 module**
(`GOFIPS140`) plus `pion/dtls` does — restricted to the CNSA 2.0 profile
described below, with the cryptographic primitives running in the Go FIPS
module (see "What 'runs in the module' covers" for the limits of that
statement). So DTLS termination lives here, in Go, and the Rust relay keeps
ownership of the media socket and does the SRTP encrypt/decrypt itself (via
`proto-srtp` → aws-lc-FIPS).

Since 2026-11-16 the repository also has a Rust DTLS 1.2 association
(`crates/proto/proto-dtls`, on aws-lc-rs FIPS). It is a library for the soft
client, is used by no binary yet, and does not replace this sidecar.

## What this package does (`dtlssession`)

Transport-agnostic core: given a `net.PacketConn` (later backed by the IPC
channel to the Rust relay), it drives one DTLS-SRTP handshake for a media leg
and returns the **exported SRTP keying material** for the Rust side to install.

- `GenerateIdentity()` — ephemeral self-signed **P-384** cert + its RFC 8122
  **SHA-384** SDP fingerprint (the private key never leaves this process).
- `Run(ctx, conn, rAddr, Params{Identity, Role, PeerFingerprint})` — mutual-auth
  DTLS handshake (peer identity checked against the SDP fingerprint), then
  exports the 88-byte `AEAD_AES_256_GCM` SRTP keys. `ctx` **must carry a
  deadline**; `Run` returns an error if it has none (see below for why).

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
`Error`) → `Dtls{record}` … for the rest of the call. It refuses to start
outside the FIPS module.

## Association lifetime

`Ready` hands over the keys; it does not end the session. The DTLS
association stays open in the sidecar for as long as the relay keeps the IPC
connection open, which the relay does for the whole call, and `Dtls` frames
keep flowing in both directions. Two reasons:

- A peer that reads `close_notify` treats the association, and with it its
  media, as over (the soft client stops its audio and fails the call unless a
  BYE follows within a second). Closing the pion connection sends
  `close_notify`, and the relay forwards every frame to the peer.
- RFC 6347 §4.2.4: the side that sent the last flight must answer a
  retransmission of the peer's last flight. As DTLS server that is the
  sidecar, and it can only answer while the association exists.

Until 2026-11-17 the session closed the association right after `Ready`, so
neither held. What ends a session now:

| Event | What the sidecar does |
|---|---|
| The relay closes the connection, or only its sending half (call over) | sends `close_notify` (it reaches the peer if the relay is still reading, which it is after a half-close), closes |
| The peer sends `close_notify` | pion answers with its own `close_notify`; the sidecar sends `Error{"peer-close-notify: ..."}` to the relay, closes |
| The peer sends a fatal alert | nothing goes back to the peer; the sidecar sends `Error{"peer-fatal-alert: ..."}` to the relay, closes |
| The sidecar is stopping (SIGTERM/SIGINT) | sends `close_notify`, then `Error{"sidecar-shutdown: ..."}`, closes |
| A frame other than `Dtls` after `Start` | sends `close_notify`, closes, logs a session error |

An `Error` text after `Ready` starts with a fixed token, up to the colon. The
relay maps it to the `reason` of its `dtls.association.closed` log record
(`peer-close-notify`, `peer-fatal-alert`, `sidecar-shutdown`). pion reports a
peer's `close_notify` and a fatal alert the same way (`io.EOF`); the sidecar
tells them apart by whether pion answered with an alert of its own, which it
does for `close_notify` only. The sidecar also logs one line per ended
association (`session: association ended: <token>`); it does not know the
call id, the relay's record has it. The `close_notify` / fatal-alert
distinction is therefore an inference: it is wrong if pion earlier sent an
alert of its own on that association, and the relay takes no action on either
beyond its log record (NIST POA&M-340).

The handshake timeout (30 s) covers the handshake only. After `Ready` there is
no idle or lifetime limit in the sidecar: a session lasts as long as the relay
holds the connection, and one session is one goroutine set (the session, the
IPC reader, pion's loops).

### Session limit and sizing (`-max-sessions`)

A session lives for the whole call, so the number of sessions sizes the
process: one per terminated media leg, two per call. Measured in the
performance review of 2026-11-17 (macOS arm64, 100 established sessions after
GC): 5 goroutines and about 70 KiB live per leg, so about **150 KiB per
call**. Linux RSS has not been measured; it will differ somewhat, the order
will not. The sizing below adds an allowance of 16 MiB for the process itself,
which is an assumption, not a measurement.

`-max-sessions N` (default 10000, or `$DTLS_TERMINATOR_MAX_SESSIONS`) caps
concurrent sessions. Set it to **2 x the SBC's `max_calls`**; the Helm chart
does. At the cap a new connection still gets `Hello` (the liveness probe reads
only that and keeps passing), and its `Start` is answered with
`Error{"session-limit: ..."}`: that leg's handshake fails and the call is
refused, the calls in progress are not touched. Refusals are logged (the first
and every 1000th), and once a minute the sidecar logs
`sessions: active=N peak=N max=N refused=N` while it has sessions. That line
is the only view of the count: there is no metric, the sizing below has not
been measured on Linux, and the descriptor limit is not checked against the
cap (NIST POA&M-342).

Memory limit of the container: `16 MiB + max_calls x 150 KiB`, with headroom
for the garbage collector, and `GOMEMLIMIT` set to about 90 % of the limit so
that the collector works harder before the kernel kills the process (an OOM
kill ends every association without `close_notify`). The chart's defaults
(`max_calls: 5000`): 1 GiB limit, `GOMEMLIMIT=920MiB`.

Consequences to know about:

- **Stopping or restarting the sidecar ends the DTLS associations of every
  call in progress**, with `close_notify` towards the peers. The relay keeps
  its SRTP keys and keeps relaying, but a peer that honours `close_notify`
  (the soft client does) ends its side. Before this change a restart only
  affected handshakes in flight. The liveness probe restarts a wedged sidecar,
  so this now reaches live calls (NIST POA&M-341). At shutdown the process
  waits at most 5 s for the sessions to finish their teardown.
- **Unprotected records after the handshake.** pion accepts epoch-0 (plaintext)
  records for the life of a connection, so one forged plaintext `close_notify`
  from the peer's address would end an established association and make pion
  send a genuine `close_notify` to the real peer
  (`TestPionHonoursUnprotectedCloseNotifyAfterHandshake` shows it). With
  associations now living for the whole call, `plaintextgate.go` drops, after
  the handshake, every datagram carrying an epoch-0 record that is not
  handshake or a well-formed ChangeCipherSpec. A ChangeCipherSpec whose body is
  not the single octet `0x01` is dropped too: pion would answer it with a
  protected fatal alert to the real peer
  (`TestMalformedChangeCipherSpecDoesNotAlertThePeer`).
- **Unprotected handshake records after the handshake.** Epoch-0 handshake and
  ChangeCipherSpec records are what a retransmitted final flight consists of,
  so they must pass; but pion keeps every complete epoch-0 handshake message
  for the life of the connection, so an unlimited stream of them from the
  peer's address grew the process without bound. Each association therefore
  accepts at most **32** such datagrams, and only in the first **60 s** after
  its handshake; the rest are dropped and counted
  (`TestHandshakeFloodAfterHandshakeIsBounded`,
  `TestPlaintextGateHandshakeBudget`). The numbers: with a retransmission
  timer that starts at 1 s and doubles, five retransmissions fall inside 60 s
  (sent at about 1, 3, 7, 15 and 31 s), and a final flight is a handful of
  datagrams. Once the budget is spent or the 60 s are over, a datagram that
  carries the epoch-1 `Finished` together with epoch-0 records is dropped
  whole. What is left (NIST POA&M-335): inside the
  budget pion still acts on forged handshake records, and whoever can send
  from the peer's address can use the budget up, after which a lost final
  flight is not recovered and that call's handshake fails on the peer's side
  (fail closed).
- Dropped datagrams of both kinds are counted and logged once per session.
- Key material after `Ready` (best effort): the exporter's output, the `Ready`
  frame and the framing layer's copy of it are overwritten once the frame is
  written. pion keeps the DTLS master secret for as long as the association
  lives, and the same SRTP keys can be exported from it again, so a memory
  image of the sidecar taken during a call still yields them (NIST POA&M-330).
- On a failed handshake the `Error` frame now reaches the relay. Before, pion
  had already closed the connection when the frame was written.

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
`GODEBUG=fips140=on` (crypto primitives from the Go module; DTLS's
protocol-mandated deterministic-IV GCM seal is a non-approved service and does
not pass the stricter `fips140=only` audit, POA&M-400 — see
`srtp-dtls-termination-plan` notes).

```sh
# Module selection is build-time. v1.26.0 = Go Cryptographic Module frozen from
# Go 1.26. Per the Go FIPS 140-3 documentation, `GOFIPS140=certified` selects
# the latest CMVP-validated module; this README asserts no CMVP status for
# either.
GOFIPS140=v1.26.0 GODEBUG=fips140=on go test ./...
```

## CNSA 2.0 profile: what the endpoint enforces

Nothing is negotiated down. A peer outside the profile is refused. This is
stricter than before 2026-11-16, when only the cipher suite, the SRTP profile
and the fingerprint hash were restricted.

| Profile element | Enforced by |
| --- | --- |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` only | pion config |
| SRTP profile `AEAD_AES_256_GCM` only | pion config, re-checked afterwards |
| Extended master secret (RFC 7627) required | pion config |
| Peer cert matches the `sha-384` SDP fingerprint | `VerifyPeerCertificate` |
| Peer certificate key is ECDSA P-384 | `requireP384Key` (same callback) |
| Signatures we verify: ECDSA P-384/SHA-384 only | pion `SignatureSchemes` |
| Our `ServerKeyExchange` is signed with ECDSA P-384/SHA-384 | pion config |
| Our `CertificateVerify` (client role) is ECDSA P-384/SHA-384 | wire guard |
| ECDHE group is secp384r1 | wire guard |

ChaCha20 suites are excluded, so no non-FIPS cipher is reachable. The peer
certificate's own signature, chain and validity period are not checked: the
SDP fingerprint is the trust anchor.

### The wire guard (`groupguard.go`)

pion/dtls v3.1.5 cannot be configured to enforce two of these. As server it
uses the first group in the client's `supported_groups`, whatever
`EllipticCurves` says; as client it uses whatever group the server's
`ServerKeyExchange` names; and as client it signs `CertificateVerify` with
the first scheme of the server's `CertificateRequest` that fits its key. The
negotiated group is not exposed afterwards. Both values cross the transport
in the clear during the handshake, so `groupGuard` wraps the `PacketConn`
handed to pion and checks them there. It is disarmed after the handshake.

The guard is project code on the SBC media path. It is not part of pion and
not part of any validated module. It depends on how pion v3.1.5 reassembles
handshake fragments; the canary test `TestPionReassemblyAssumptions` fails if
the pion version changes or that behaviour changes, and must be re-evaluated
on every pion upgrade.

What it does:

- **Server role, our `ServerKeyExchange`.** If it names a group other than
  secp384r1, the datagram is withheld, one fatal `handshake_failure` alert is
  sent in its place, every later write is swallowed and the handshake is
  aborted.
- **Client role, our `CertificateVerify`.** If its scheme is not ECDSA
  P-384/SHA-384, the same happens. The out-of-profile signature never leaves.
- **Client role, the server's `ServerKeyExchange`.** A datagram holding one
  on another group is dropped and counted. It is not delivered to pion and it
  does not abort the handshake: inbound datagrams at this stage are
  unauthenticated, and aborting on one would let anyone who can spoof the
  peer's address end a handshake with a conformant peer.

### Consequences for peers

- **If a peer sends `supported_groups`, secp384r1 must be first.** As server
  the sidecar refuses a client that supports secp384r1 but lists another
  group (X25519, P-256) ahead of it, with a fatal `handshake_failure`.
  Selecting P-384 from the client's list needs a change in pion (NIST
  POA&M-336).
- **Client role: an out-of-profile server is refused at the handshake
  deadline, with no alert.** Its `ServerKeyExchange` never reaches pion, so
  the handshake cannot complete and ends when `ctx` expires; `Run` then
  reports how many datagrams were dropped. By then pion has closed the
  transport, so no alert can be sent; the server runs into its own timeout.
  This is why `Run` requires a deadline. The dropped-datagram error is
  unauthenticated evidence: it explains a failed handshake, it does not prove
  what the peer sent. (Tracked with NIST POA&M-335.)
- **First-fragment restriction.** A peer whose first `ServerKeyExchange`
  fragment is shorter than three bytes, or that sends a fragment starting at
  offset 1 or 2, is refused, although RFC 6347 §4.2.3 allows such fragments.
  The same rule applies to the first two bytes of our own
  `CertificateVerify`. No stack is known to fragment that way.
- A server that asks for another `CertificateVerify` scheme first is refused,
  not answered with a scheme further down its list.
- A peer that signs with ECDSA/SHA-256 over a P-384 key (stock pion without
  `SignatureSchemes`), has a P-256 or RSA certificate, or does not support
  the extended master secret is refused.

Not changed by the guard (NIST POA&M-335): pion itself ends a handshake on a
forged plaintext fatal alert, treats forged in-profile-looking plaintext
handshake fragments as the peer's, and lets unauthenticated epoch-0 records
move its replay window, so one forged record with a high sequence number can
stall a handshake. The last point is from reading pion's `conn.go` and one
observation; there is no regression test for it.

### What "runs in the module" covers

- The primitives pion uses (AES-256-GCM, SHA-384, HMAC, ECDSA and ECDH on
  P-384, random numbers) run in the Go Cryptographic Module selected with
  `GOFIPS140`, and the service refuses to start outside FIPS mode.
- The TLS 1.2 PRF (master secret, key expansion, `Finished`, the SRTP key
  exporter) is **composed by pion in Go** on top of the module's HMAC. It is
  not a KDF service of the module (NIST POA&M-332 collects the evidence for
  this on both the Go and the Rust side).
- pion's DTLS protocol logic and the wire guard are not part of the module.
- DTLS's deterministic-IV GCM seal (pion `cipher.NewGCM`, caller IV) is a
  non-approved service and does not pass `fips140=only` (POA&M-400).
- This README does not assert a CMVP certificate number or the validation
  status of the `v1.26.0` module; that evidence belongs to the ATO package.

### Tests and what was run

`session_test.go` and `groupguard_test.go` (18 tests in this package). One
per refusal: `TestDtlsSha256SignatureRejected`,
`TestDtlsP256KeyExchangeRejected`,
`TestDtlsServerChoosingNonP384GroupRejected`,
`TestDtlsPeerWithoutExtendedMasterSecretRejected`,
`TestDtlsP256CertificateRejected`, `TestDtlsCertificateVerifySchemeEnforced`,
`TestDtlsClientListingP384SecondIsRefused` (pins the POA&M-336 refusal and
the alert), `TestRunRequiresADeadline`. Guard behaviour:
`TestGuardReadPathDropsWithoutAborting`,
`TestGuardWritePathWithholdsAlertsAndAborts`,
`TestDtlsSpoofedKeyExchangeDoesNotAbortHandshake`,
`TestServerKeyExchangeGroupScanner`, `TestCertificateVerifySchemeScanner`,
`TestPionReassemblyAssumptions`. Acceptance:
`TestDtlsInProfileRawPeerAccepted`, `TestDtlsSrtpMatchingKeys`.

Association lifetime (added 2026-11-17). In this package (`lifetime_test.go`):
`TestForgedUnprotectedAlertsDoNotEndAnEstablishedAssociation`,
`TestPionHonoursUnprotectedCloseNotifyAfterHandshake`,
`TestMalformedChangeCipherSpecDoesNotAlertThePeer`,
`TestHandshakeFloodAfterHandshakeIsBounded`,
`TestPlaintextGateHandshakeBudget`, `TestUnprotectedScanner`. In `service`
(`lifetime_test.go`, `server_test.go`):
`TestNoCloseNotifyAfterReadyWhileIPCOpen` (both roles, 2.5 s),
`TestRetransmittedFinalClientFlightAnsweredAfterReady`,
`TestRelayHalfCloseEndsSessionWithOneCloseNotify`,
`TestRelayCloseEndsSession`, `TestPeerCloseNotifyIsReportedToRelay`,
`TestPeerFatalAlertIsReportedToRelay` (a genuine protected fatal alert),
`TestServerRefusesSessionsAtTheLimit`,
`TestShutdownEndsEstablishedSession`, `TestShutdownEndsSessionBeforeReady`,
`TestHandshakeTimeoutEndsSessionAndReportsError`,
`TestNonDtlsFrameAfterReadyEndsSession`, `TestSessionsLeaveNoGoroutines`. In
`ipc`: `TestReadDeadlineWakesRecv`. A soft-client call through the SBC relay
and this sidecar, held for 2.5 s, with a restart of the clients' media
objects after a sequence wrap, and ended by the SBC, is
`crates/client/client-integration-tests/tests/dtls_sbc_sidecar.rs` (needs `SIDECAR_BIN`;
run by `.github/workflows/srtp-audio.yml`).

When this section was written (2026-11-16) these had passed in local runs
only (go1.27.4, macOS arm64, `GOFIPS140=v1.26.0 GODEBUG=fips140=on go test
-count=1 -race ./...`). `.github/workflows/sidecar-dtls.yml` runs
`go test -race -v ./...` under `fips140=on` with Go 1.26 for changes under
`sidecar/`, but had not yet run on this change. The lifetime tests were run the
same way on 2026-11-17, locally only. Not tested: any peer that is not pion
or the soft client (browsers, phones, other SBCs), Linux outside CI, and a
soft-client call through the SBC with SIP signalling.
