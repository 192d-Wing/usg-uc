# SBC Stress Testing

## Quick Start

```bash
# Build and run a quick smoke test (10 concurrent calls)
./deploy/test/run-stress-test.sh --rate 5 --total 10

# Moderate load test
./deploy/test/run-stress-test.sh --rate 50 --concurrent 500 --total 5000

# High load test (100 CPS, 1000 concurrent, 30-second calls)
./deploy/test/run-stress-test.sh --rate 100 --concurrent 1000 --total 10000 --duration 30000

# Force rebuild and clean up after
./deploy/test/run-stress-test.sh --rate 10 --total 100 --build --clean
```

## Architecture

```
  ┌─────────────┐     INVITE      ┌─────────────┐     INVITE      ┌─────────────┐
  │  SIPp UAC   │ ──────────────> │  USG SBC    │ ──────────────> │  SIPp UAS   │
  │ (caller)    │ <────────────── │  (DUT)      │ <────────────── │  (callee)   │
  │ 172.28.0.30 │   100/180/200   │ 172.28.0.10 │   200 OK        │ 172.28.0.20 │
  │ :5070       │                 │ :5060       │                 │ :5080       │
  └─────────────┘                 └─────────────┘                 └─────────────┘
       UAC                            B2BUA                           UAS
```

- **SIPp UAC** generates INVITE traffic at the configured rate
- **SBC** routes calls via dial plan to the loopback trunk group
- **SIPp UAS** answers with 200 OK, holds for the call duration, then receives BYE

## Components

| Service | Image | Port | Role |
|---------|-------|------|------|
| `sbc` | Built from repo Dockerfile | 5060/udp, 8080/tcp | SBC under test |
| `sipp-uas` | `ctaloi/sipp:latest` | 5080/udp | Auto-answer UAS |
| `sipp-uac` | `ctaloi/sipp:latest` | 5070/udp | Load generator |

## Test Parameters

| Parameter | Flag | Default | Description |
|-----------|------|---------|-------------|
| Rate | `--rate` | 10 | New calls per second |
| Concurrent | `--concurrent` | 100 | Max simultaneous calls |
| Total | `--total` | 1000 | Total calls to generate |
| Duration | `--duration` | 5000 | Call hold time (ms) |

## Monitoring During Test

```bash
# Watch SBC stats in real-time
watch -n1 'curl -s http://localhost:8080/api/v1/system/stats | python3 -m json.tool'

# Prometheus metrics
curl http://localhost:8080/metrics | grep sbc_

# SBC logs
docker compose -f deploy/test/docker-compose.yml logs -f sbc

# Container resource usage
docker stats sbc-test sipp-uas sipp-uac
```

## Custom SIPp Scenarios

Place custom XML scenario files in `deploy/test/` and use:

```bash
./deploy/test/run-stress-test.sh --scenario sipp-uac-register-call.xml
```

The included `sipp-uac-register-call.xml` scenario:
1. Registers with the SBC
2. Sends INVITE with SDP
3. Expects 100/180/200
4. Sends ACK
5. Holds for call duration
6. Sends BYE

## Interpreting Results

SIPp reports at completion:

```
  Successful call:  999
  Failed call:      1
  ...
  Response time:
    Average:        45ms
    Max:           230ms
```

Key metrics to watch:
- **Failed calls**: Should be 0 for a healthy SBC
- **Response time**: Time from INVITE to 200 OK (includes B-leg setup)
- **Retransmissions**: High retransmissions indicate UDP packet loss or SBC overload
- **SBC CPU/memory**: Monitor via `docker stats`

## Troubleshooting

**SBC won't start**: Check `docker compose logs sbc` for config errors

**All calls failing**: Verify the loopback trunk config points to the UAS IP (172.28.0.20:5080)

**High retransmissions**: Increase rate limiter thresholds in `sbc-test.toml`

**SIPp "No 200 received"**: SBC may be overloaded — reduce `--rate` or `--concurrent`
