module github.com/192d-Wing/usg-uc/sidecar/srtp-test-peer

go 1.26.0

// A DTLS-SRTP media endpoint used only to test the SBC's termination end to
// end. It is NOT part of the FIPS build — it reuses the sidecar's dtlssession
// for the handshake and adds pion/srtp for media, so pion/srtp stays out of the
// FIPS sidecar's dependency tree.
require (
	github.com/192d-Wing/usg-uc/sidecar/dtls-terminator v0.0.0
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/rtp v1.10.2
	github.com/pion/srtp/v3 v3.0.12
)

require github.com/pion/rtcp v1.2.16

require (
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/192d-Wing/usg-uc/sidecar/dtls-terminator => ../dtls-terminator
