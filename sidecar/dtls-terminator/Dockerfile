# syntax=docker/dockerfile:1.7
# DTLS-SRTP terminator sidecar — the SBC's DTLS endpoint per media leg.
#
# Built in FIPS 140-3 mode with the Go Cryptographic Module (GOFIPS140): every
# crypto primitive runs in the certified module. Unlike sbc-daemon (which must
# stay glibc for aws-lc-fips), Go's FIPS module is pure Go, so a CGO-free static
# binary runs on any base — we use Alpine for a small image with a shell (the
# pod's startupProbe execs `test -f` on the published fingerprint file).
#
# Build (context = this directory):
#   docker build -t localhost/usg-dtls-terminator:local sidecar/dtls-terminator
#
# ## NIST 800-53 Rev5 / CNSA 2.0
# - SC-13 Cryptographic Protection: FIPS 140-3 module (GOFIPS140=v1.26.0)
# - CM-7 Least Functionality: single static binary, nonroot, no shell in PID 1

FROM golang:1.26-bookworm AS build
WORKDIR /src

# Cache module downloads separately from the source build.
COPY go.mod go.sum ./
RUN go mod download

COPY . ./

# GOFIPS140 selects the frozen v1.26.0 module (FIPS on by default at build).
# CGO off → a self-contained static binary (pion/dtls is pure Go).
ENV GOFIPS140=v1.26.0 CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /dtls-terminator ./cmd/dtls-terminator

FROM alpine:3.20
RUN adduser -D -u 65532 sidecar
COPY --from=build /dtls-terminator /usr/local/bin/dtls-terminator

# fips140=on pins the runtime FIPS posture (redundant with the GOFIPS140 build,
# but explicit); main.go fails closed if the module is not active.
ENV GODEBUG=fips140=on
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/dtls-terminator"]
