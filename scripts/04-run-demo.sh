#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Step 4: Run Demo
# Tekton-orchestrated security pipeline demo
# Phases: Baseline -> Tekton Pipeline (scan + canary) -> Report -> Webhook Trigger

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Service URLs via port-forward
SCANNER_PORT="${SCANNER_PORT:-9000}"
TARGET_PORT="${TARGET_PORT:-9001}"
SCANNER_URL="http://localhost:${SCANNER_PORT}"
TARGET_URL_INTERNAL="http://target-agent.target-agent.svc.cluster.local:8001"
TARGET_URL_LOCAL="http://localhost:${TARGET_PORT}"

echo "============================================================"
echo "   AgentGuard PoC - Security Demo"
echo "   Shift-Left Security Testing for AI Agents in CI/CD"
echo "   Tekton-Orchestrated Pipeline"
echo "============================================================"
echo ""

# Setup port-forwards in background
echo "Setting up port-forwards..."
kubectl port-forward svc/agentguard-scanner -n agentguard-system ${SCANNER_PORT}:8000 &
PF_SCANNER=$!
kubectl port-forward svc/target-agent -n target-agent ${TARGET_PORT}:8001 &
PF_TARGET=$!
sleep 3

# Cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up port-forwards..."
    kill ${PF_SCANNER} ${PF_TARGET} 2>/dev/null || true
}
trap cleanup EXIT

# Check tkn CLI availability
USE_TKN="false"
if command -v tkn >/dev/null 2>&1; then
    USE_TKN="true"
    echo "tkn CLI detected - using Tekton native commands"
else
    echo "tkn CLI not found - using kubectl for Tekton operations"
fi
echo ""

# =========================================================
# Phase 1: Baseline
# =========================================================
echo ""
echo "--- Phase 1: Baseline - Normal Agent Operation ---"
echo ""

echo "Testing target agent health..."
curl -s "${TARGET_URL_LOCAL}/health" | python3 -m json.tool
echo ""

echo "Sending normal chat message..."
BASELINE=$(curl -s -X POST "${TARGET_URL_LOCAL}/chat" \
    -H "Content-Type: application/json" \
    -d '{"message": "What is the capital of France?"}')
echo "Response: $(echo ${BASELINE} | python3 -c "import sys,json; print(json.load(sys.stdin).get('response','')[:200])")"
echo ""
echo "Baseline: Agent responds normally to legitimate requests."
echo ""
sleep 2

# =========================================================
# Phase 2: Tekton-Orchestrated Security Pipeline
# =========================================================
echo "--- Phase 2: Tekton Security Pipeline ---"
echo "  Running: preflight -> (attack-scan || canary-test) -> report"
echo ""

if [ "${USE_TKN}" = "true" ]; then
    echo "Starting pipeline via tkn..."
    tkn pipeline start agentguard-security-pipeline \
        -n agentguard-system \
        --showlog \
        --timeout 5m \
        2>&1 || echo "Pipeline completed (check logs above for details)"
else
    echo "Starting pipeline via kubectl..."
    cat <<EOF | kubectl create -f -
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  generateName: agentguard-demo-
  namespace: agentguard-system
  labels:
    app.kubernetes.io/part-of: agentguard
spec:
  pipelineRef:
    name: agentguard-security-pipeline
EOF

    # Wait for PipelineRun to complete
    echo "Waiting for PipelineRun to complete..."
    sleep 5
    LATEST_PR=$(kubectl get pipelinerun -n agentguard-system --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')
    echo "PipelineRun: ${LATEST_PR}"

    kubectl wait --for=condition=Succeeded pipelinerun/${LATEST_PR} -n agentguard-system --timeout=300s 2>/dev/null || true

    echo ""
    echo "PipelineRun logs:"
    kubectl logs -n agentguard-system -l tekton.dev/pipelineRun=${LATEST_PR} --all-containers --tail=50 2>/dev/null || true
fi

echo ""
sleep 2

# =========================================================
# Phase 3: Results & OWASP Report
# =========================================================
echo "--- Phase 3: Detection Summary ---"
echo ""

echo "Fetching scan results..."
ALL_RESULTS=$(curl -s "${SCANNER_URL}/results")
TOTAL_SCANS=$(echo "${ALL_RESULTS}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_scans',0))")

if [ "${TOTAL_SCANS}" -gt "0" ]; then
    # Get latest scan
    LATEST_SCAN=$(echo "${ALL_RESULTS}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
scans = data.get('scans', {})
latest = list(scans.values())[-1] if scans else {}
print(json.dumps(latest))
")

    TOTAL=$(echo "${LATEST_SCAN}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_patterns',0))")
    SUCCESSFUL=$(echo "${LATEST_SCAN}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('successful_attacks',0))")
    DETECTION=$(echo "${LATEST_SCAN}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('detection_rate',0))")
    GATE=$(echo "${LATEST_SCAN}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ci_gate','UNKNOWN'))")

    echo "=============================================="
    echo "   AgentGuard Security Report"
    echo "=============================================="
    echo ""
    echo "  Total Patterns:      ${TOTAL}"
    echo "  Successful Attacks:  ${SUCCESSFUL}"
    echo "  Detection Rate:      ${DETECTION}"
    echo "  CI/CD Gate:          ${GATE}"
    echo ""

    echo "  OWASP Agentic AI Top 10 Coverage:"
    echo "${LATEST_SCAN}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for oid, info in data.get('owasp_mapping', {}).items():
    rate = info.get('detection_rate', 0)
    bar = '#' * int(rate * 20) + '.' * (20 - int(rate * 20))
    print(f'    {oid}: {info[\"name\"]:<30} [{bar}] {rate:.0%}')
" 2>/dev/null || echo "    (OWASP data not available)"
    echo ""
    echo "=============================================="
fi

echo ""

# =========================================================
# Phase 4: Webhook Trigger Demo
# =========================================================
echo "--- Phase 4: Webhook Trigger ---"
echo ""

# Check if EventListener is running
EL_SVC=$(kubectl get svc -n agentguard-system -l app.kubernetes.io/managed-by=EventListener 2>/dev/null | grep -v NAME | head -1 || true)
if [ -n "${EL_SVC}" ]; then
    echo "EventListener service found:"
    echo "  ${EL_SVC}"
    echo ""
    echo "Sending webhook event to trigger pipeline..."

    # Port-forward EventListener
    EL_SVC_NAME=$(echo "${EL_SVC}" | awk '{print $1}')
    kubectl port-forward "svc/${EL_SVC_NAME}" -n agentguard-system 8080:8080 &
    PF_EL=$!
    sleep 2

    curl -s -X POST http://localhost:8080 \
        -H "Content-Type: application/json" \
        -d "{\"target_url\": \"${TARGET_URL_INTERNAL}\", \"scanner_url\": \"http://agentguard-scanner.agentguard-system.svc.cluster.local:8000\"}" \
        | python3 -m json.tool 2>/dev/null || echo "  Webhook sent (response may be empty)"

    kill ${PF_EL} 2>/dev/null || true
    echo ""
    echo "Check triggered PipelineRun:"
    kubectl get pipelinerun -n agentguard-system --sort-by=.metadata.creationTimestamp | tail -3
else
    echo "EventListener not ready. Skipping webhook demo."
    echo "(This is expected if Tekton Triggers are still initializing)"
fi

echo ""

# =========================================================
# Metrics
# =========================================================
echo "--- Prometheus-compatible Metrics ---"
echo ""
curl -s "${SCANNER_URL}/metrics" 2>/dev/null || echo "(Metrics not available)"
echo ""

echo "============================================================"
echo "   Demo Complete"
echo "============================================================"
