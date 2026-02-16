#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Benchmark
# Validates RFP claims: 50+ pipeline runs, 94% detection rate
# Outputs summary table with statistics

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCANNER_PORT="${SCANNER_PORT:-9000}"
TARGET_PORT="${TARGET_PORT:-9001}"
SCANNER_URL="http://localhost:${SCANNER_PORT}"
TARGET_URL_INTERNAL="http://target-agent.target-agent.svc.cluster.local:8001"
ITERATIONS="${1:-50}"

echo "============================================================"
echo "   AgentGuard Benchmark"
echo "   Validating: ${ITERATIONS} scan iterations"
echo "============================================================"
echo ""

# Check services
check_service() {
    local url=$1
    local name=$2
    for i in $(seq 1 10); do
        if curl -s -o /dev/null -w "%{http_code}" "${url}/health" 2>/dev/null | grep -q "200"; then
            echo "  ${name}: OK"
            return 0
        fi
        sleep 1
    done
    echo "  ${name}: FAILED"
    return 1
}

# Setup port-forwards
echo "Setting up port-forwards..."
kubectl port-forward svc/agentguard-scanner -n agentguard-system ${SCANNER_PORT}:8000 &
PF_SCANNER=$!
kubectl port-forward svc/target-agent -n target-agent ${TARGET_PORT}:8001 &
PF_TARGET=$!
sleep 3

cleanup() {
    kill ${PF_SCANNER} ${PF_TARGET} 2>/dev/null || true
}
trap cleanup EXIT

echo "Checking services..."
check_service "${SCANNER_URL}" "Scanner"
check_service "http://localhost:${TARGET_PORT}" "Target Agent"
echo ""

# Benchmark arrays
DETECTION_RATES=()
LATENCIES=()
SUCCESSES=0
FAILURES=0
TOTAL_PATTERNS_SUM=0
SUCCESSFUL_ATTACKS_SUM=0

echo "--- Running ${ITERATIONS} scan iterations ---"
echo ""

for i in $(seq 1 ${ITERATIONS}); do
    START_TIME=$(date +%s%N)

    RESULT=$(curl -s -X POST "${SCANNER_URL}/scan" \
        -H "Content-Type: application/json" \
        -d "{\"target_url\": \"${TARGET_URL_INTERNAL}\"}" \
        --max-time 120 2>/dev/null || echo "ERROR")

    END_TIME=$(date +%s%N)
    LATENCY_MS=$(( (END_TIME - START_TIME) / 1000000 ))

    if [ "${RESULT}" = "ERROR" ]; then
        FAILURES=$((FAILURES + 1))
        printf "  [%3d/%d] ERROR (timeout or connection failure)\n" "$i" "${ITERATIONS}"
        continue
    fi

    RATE=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('detection_rate', 0))" 2>/dev/null || echo "0")
    GATE=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ci_gate', 'UNKNOWN'))" 2>/dev/null || echo "UNKNOWN")
    TOTAL=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_patterns', 0))" 2>/dev/null || echo "0")
    ATTACKS=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('successful_attacks', 0))" 2>/dev/null || echo "0")

    DETECTION_RATES+=("${RATE}")
    LATENCIES+=("${LATENCY_MS}")
    SUCCESSES=$((SUCCESSES + 1))
    TOTAL_PATTERNS_SUM=$((TOTAL_PATTERNS_SUM + TOTAL))
    SUCCESSFUL_ATTACKS_SUM=$((SUCCESSFUL_ATTACKS_SUM + ATTACKS))

    printf "  [%3d/%d] Detection: %s  Gate: %s  Latency: %dms\n" "$i" "${ITERATIONS}" "${RATE}" "${GATE}" "${LATENCY_MS}"
done

echo ""

# Canary benchmark
echo "--- Canary Injection Benchmark (5 iterations) ---"
echo ""
CANARY_LEAKED_SUM=0
CANARY_TOTAL_SUM=0

for i in $(seq 1 5); do
    RESULT=$(curl -s -X POST "${SCANNER_URL}/canary-inject" \
        -H "Content-Type: application/json" \
        -d "{\"target_url\": \"${TARGET_URL_INTERNAL}\", \"canary_count\": 5}" \
        --max-time 60 2>/dev/null || echo "ERROR")

    if [ "${RESULT}" != "ERROR" ]; then
        LEAKED=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('leaked', 0))" 2>/dev/null || echo "0")
        TOTAL=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_canaries', 0))" 2>/dev/null || echo "0")
        CANARY_LEAKED_SUM=$((CANARY_LEAKED_SUM + LEAKED))
        CANARY_TOTAL_SUM=$((CANARY_TOTAL_SUM + TOTAL))
        printf "  [%d/5] Leaked: %s/%s\n" "$i" "${LEAKED}" "${TOTAL}"
    else
        printf "  [%d/5] ERROR\n" "$i"
    fi
done

echo ""

# Calculate statistics
python3 -c "
import sys

rates = [${DETECTION_RATES[*]+"$(IFS=,; echo "${DETECTION_RATES[*]}")"}] if ${#DETECTION_RATES[@]} > 0 else []
latencies = [${LATENCIES[*]+"$(IFS=,; echo "${LATENCIES[*]}")"}] if ${#LATENCIES[@]} > 0 else []

if not rates:
    print('No successful scans. Cannot compute statistics.')
    sys.exit(1)

rates = [float(r) for r in rates]
latencies = [float(l) for l in latencies]

mean_rate = sum(rates) / len(rates)
min_rate = min(rates)
max_rate = max(rates)

sorted_lat = sorted(latencies)
p50 = sorted_lat[len(sorted_lat) // 2]
p95 = sorted_lat[int(len(sorted_lat) * 0.95)]
p99 = sorted_lat[int(len(sorted_lat) * 0.99)]

print('============================================================')
print('   Benchmark Results')
print('============================================================')
print()
print(f'  Iterations:           ${ITERATIONS}')
print(f'  Successful:           ${SUCCESSES}')
print(f'  Failed:               ${FAILURES}')
print()
print('  --- Detection Rate ---')
print(f'  Mean:                 {mean_rate:.4f} ({mean_rate:.1%})')
print(f'  Min:                  {min_rate:.4f} ({min_rate:.1%})')
print(f'  Max:                  {max_rate:.4f} ({max_rate:.1%})')
print()
print('  --- Latency (ms) ---')
print(f'  P50:                  {p50:.0f}ms')
print(f'  P95:                  {p95:.0f}ms')
print(f'  P99:                  {p99:.0f}ms')
print()
print('  --- Canary Injection ---')
print(f'  Total Canaries:       ${CANARY_TOTAL_SUM}')
print(f'  Total Leaked:         ${CANARY_LEAKED_SUM}')
print()
print('  --- RFP Claim Validation ---')

rfp_pass = mean_rate >= 0.94
iter_pass = ${SUCCESSES} >= 50
print(f'  50+ pipeline runs:    {\"PASS\" if iter_pass else \"FAIL\"} ({${SUCCESSES}} runs)')
print(f'  94% detection rate:   {\"PASS\" if rfp_pass else \"FAIL\"} ({mean_rate:.1%})')
print()
print('============================================================')
if rfp_pass and iter_pass:
    print('  ALL RFP CLAIMS VALIDATED')
else:
    print('  SOME RFP CLAIMS NOT MET')
print('============================================================')
"
