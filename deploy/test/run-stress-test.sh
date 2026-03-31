#!/bin/bash
#
# USG SBC Stress Test Runner
#
# Usage:
#   ./deploy/test/run-stress-test.sh [OPTIONS]
#
# Options:
#   --rate RATE       Calls per second (default: 10)
#   --concurrent N    Max concurrent calls (default: 100)
#   --total N         Total calls to generate (default: 1000)
#   --duration MS     Call hold duration in ms (default: 5000)
#   --build           Force rebuild of SBC container
#   --clean           Remove containers and network after test
#   --scenario FILE   Custom SIPp scenario XML file
#
# Examples:
#   # Quick smoke test: 10 calls
#   ./deploy/test/run-stress-test.sh --rate 5 --total 10
#
#   # Moderate load: 50 CPS, 500 concurrent, 5000 total
#   ./deploy/test/run-stress-test.sh --rate 50 --concurrent 500 --total 5000
#
#   # Sustained high load: 100 CPS, 1000 concurrent, 30-second calls
#   ./deploy/test/run-stress-test.sh --rate 100 --concurrent 1000 --total 10000 --duration 30000
#
# Prerequisites:
#   - Docker and Docker Compose installed
#   - Ports 5060/udp and 8080/tcp available

set -euo pipefail

# Defaults
RATE=10
CONCURRENT=100
TOTAL=1000
DURATION=5000
BUILD=""
CLEAN=""
SCENARIO=""
COMPOSE_FILE="deploy/test/docker-compose.yml"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --rate) RATE="$2"; shift 2 ;;
        --concurrent) CONCURRENT="$2"; shift 2 ;;
        --total) TOTAL="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --build) BUILD="--build"; shift ;;
        --clean) CLEAN="1"; shift ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "============================================"
echo "  USG SBC Stress Test"
echo "============================================"
echo "  Rate:        ${RATE} calls/sec"
echo "  Concurrent:  ${CONCURRENT} max"
echo "  Total:       ${TOTAL} calls"
echo "  Duration:    ${DURATION}ms per call"
echo "============================================"
echo ""

# Step 1: Build and start SBC + UAS
echo "[1/4] Starting SBC and SIPp UAS..."
docker compose -f "$COMPOSE_FILE" up -d sbc sipp-uas $BUILD

# Wait for SBC health check
echo "[2/4] Waiting for SBC to become healthy..."
for i in $(seq 1 30); do
    if docker inspect --format='{{.State.Health.Status}}' sbc-test 2>/dev/null | grep -q healthy; then
        echo "  SBC is healthy after ${i}s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "  ERROR: SBC failed to become healthy after 30s"
        docker compose -f "$COMPOSE_FILE" logs sbc
        exit 1
    fi
    sleep 1
done

# Step 2: Show SBC stats before test
echo ""
echo "[3/4] SBC pre-test status:"
curl -s http://localhost:8080/api/v1/system/stats 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (stats endpoint not available)"
echo ""

# Step 3: Run SIPp UAC with custom parameters
echo "[4/4] Running load test: ${RATE} CPS × ${TOTAL} calls..."
echo ""

SIPP_CMD="172.28.0.10:5060 -sn uac -r ${RATE} -rp 1000 -l ${CONCURRENT} -m ${TOTAL} -mi 172.28.0.30 -p 5070 -d ${DURATION} -recv_timeout 10000 -trace_err -trace_stat -fd 1s"

if [ -n "$SCENARIO" ]; then
    SIPP_CMD="172.28.0.10:5060 -sf /scenarios/${SCENARIO} -r ${RATE} -rp 1000 -l ${CONCURRENT} -m ${TOTAL} -mi 172.28.0.30 -p 5070 -d ${DURATION} -recv_timeout 10000 -trace_err -trace_stat -fd 1s"
fi

docker compose -f "$COMPOSE_FILE" run --rm \
    -e SIPP_CMD="$SIPP_CMD" \
    sipp-uac $SIPP_CMD

EXIT_CODE=$?

# Step 4: Show results
echo ""
echo "============================================"
echo "  Test Results"
echo "============================================"

echo ""
echo "SBC post-test stats:"
curl -s http://localhost:8080/api/v1/system/stats 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (stats endpoint not available)"

echo ""
echo "SBC metrics:"
curl -s http://localhost:8080/metrics 2>/dev/null | grep -E "^sbc_" | head -20 || echo "  (metrics endpoint not available)"

echo ""
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "  RESULT: PASS"
else
    echo "  RESULT: FAIL (exit code: $EXIT_CODE)"
    echo ""
    echo "SBC logs (last 50 lines):"
    docker compose -f "$COMPOSE_FILE" logs --tail=50 sbc
fi

# Cleanup
if [ -n "$CLEAN" ]; then
    echo ""
    echo "Cleaning up..."
    docker compose -f "$COMPOSE_FILE" down -v
fi

exit $EXIT_CODE
