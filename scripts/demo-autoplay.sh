#!/bin/bash
set -uo pipefail
# Note: no -e so the recording continues even if a command fails

# AgentGuard PoC - Auto-Play Demo Recording
# Non-interactive version for asciinema recording.
# Uses simulated typing + auto-pacing instead of manual Enter.
#
# Usage:
#   asciinema rec --cols 100 --rows 35 -c "bash scripts/demo-autoplay.sh" demo.cast
#   /tmp/agg --theme monokai --font-size 16 demo.cast demo.gif

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m'

# tkn CLI
TKN=""
if command -v tkn >/dev/null 2>&1; then TKN="tkn"
elif [ -x /tmp/tkn ]; then TKN="/tmp/tkn"; fi

# Ports
SCANNER_PORT="${SCANNER_PORT:-9000}"
TARGET_PORT="${TARGET_PORT:-9001}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
SCANNER_URL="http://localhost:${SCANNER_PORT}"
TARGET_URL="http://localhost:${TARGET_PORT}"
TARGET_INTERNAL="http://target-agent.target-agent.svc.cluster.local:8001"

PF_PIDS=()

# ── Helpers ──

header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Simulated typing effect for commands
type_cmd() {
    local cmd="$1"
    echo -ne "${GREEN}\$ ${NC}"
    for (( i=0; i<${#cmd}; i++ )); do
        echo -n "${cmd:$i:1}"
        sleep 0.03
    done
    echo ""
    sleep 0.3
    eval "$cmd" || true
}

# Brief pause between sections
beat() { sleep "${1:-2}"; }

cleanup() {
    for pid in "${PF_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# ─── Kill conflicting port-forwards ───
pkill -f "port-forward.*${SCANNER_PORT}:8000" 2>/dev/null || true
pkill -f "port-forward.*${TARGET_PORT}:8001" 2>/dev/null || true
pkill -f "port-forward.*${GRAFANA_PORT}:3000" 2>/dev/null || true
sleep 2

# Setup port-forwards early
kubectl port-forward svc/agentguard-scanner -n agentguard-system ${SCANNER_PORT}:8000 &>/dev/null &
PF_PIDS+=($!)
kubectl port-forward svc/target-agent -n target-agent ${TARGET_PORT}:8001 &>/dev/null &
PF_PIDS+=($!)
kubectl port-forward svc/grafana -n monitoring ${GRAFANA_PORT}:3000 &>/dev/null &
PF_PIDS+=($!)

# Wait until port-forwards are ready (up to 15s)
wait_for_port() {
    local url="$1" label="$2"
    for i in $(seq 1 15); do
        if curl -s -o /dev/null -w '' --connect-timeout 1 "${url}" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo -e "${RED}WARNING: ${label} not reachable after 15s${NC}" >&2
    return 1
}
wait_for_port "${SCANNER_URL}/health" "Scanner"
wait_for_port "${TARGET_URL}/health" "Target Agent"
wait_for_port "http://localhost:${GRAFANA_PORT}/api/health" "Grafana"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INTRO
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
clear
echo ""
echo -e "${WHITE}"
echo "     _                    _    ____                     _"
echo "    / \\   __ _  ___ _ __ | |_ / ___|_   _  __ _ _ __ __| |"
echo "   / _ \\ / _\` |/ _ \\ '_ \\| __| |  _| | | |/ _\` | '__/ _\` |"
echo "  / ___ \\ (_| |  __/ | | | |_| |_| | |_| | (_| | | | (_| |"
echo " /_/   \\_\\__, |\\___|_| |_|\\__|\\____|\\__,_|\\__,_|_|  \\__,_|"
echo "         |___/"
echo -e "${NC}"
echo ""
echo -e "${CYAN}  Shift-Left Security Testing for AI Agents in CI/CD${NC}"
echo ""
echo -e "  ${WHITE}Stack:${NC} k3d + Tekton + FastAPI + Ollama + Grafana"
echo -e "  ${WHITE}Scope:${NC} 135 attack patterns | 6 OWASP categories | canary injection"
echo ""
beat 4

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 1: Cluster
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
header "Step 1/6 — Cluster & Services"

type_cmd "kubectl get nodes"
echo ""
beat

echo -e "${WHITE}AgentGuard system:${NC}"
type_cmd "kubectl get pods -n agentguard-system"
echo ""
beat

echo -e "${WHITE}Target agent:${NC}"
type_cmd "kubectl get pods -n target-agent"
echo ""
beat

echo -e "${WHITE}Monitoring (Prometheus + Grafana):${NC}"
type_cmd "kubectl get pods -n monitoring"
echo ""
beat

echo -e "${WHITE}Tekton Pipelines:${NC}"
type_cmd "kubectl get pods -n tekton-pipelines --no-headers"
beat 3

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 2: Baseline
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
header "Step 2/6 — Baseline: Normal Agent Chat"

echo -e "${WHITE}Health check:${NC}"
type_cmd "curl -s ${TARGET_URL}/health | python3 -m json.tool"
echo ""
beat

echo -e "${WHITE}Benign chat request:${NC}"
type_cmd "curl -s -X POST ${TARGET_URL}/chat -H 'Content-Type: application/json' -d '{\"message\": \"What is the capital of France?\"}' | python3 -m json.tool"
beat 3

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 3: Tekton Pipeline Scan
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
header "Step 3/6 — Tekton Security Pipeline"

echo -e "${WHITE}4 Tasks deployed:${NC}"
type_cmd "kubectl get tasks -n agentguard-system"
echo ""
beat

echo -e "${WHITE}Pipeline definition:${NC}"
type_cmd "kubectl get pipeline -n agentguard-system"
echo ""

echo -e "${WHITE}Flow: ${CYAN}preflight${WHITE} → ( ${CYAN}attack-scan${WHITE} ∥ ${CYAN}canary-test${WHITE} ) → ${CYAN}report${NC}"
echo ""
beat

echo -e "${WHITE}Starting full security scan...${NC}"
echo ""

if [ -n "${TKN}" ]; then
    echo -ne "${GREEN}\$ ${NC}"
    # Type the command slowly for visual effect
    CMD="tkn pipeline start agentguard-security-pipeline -n agentguard-system --showlog"
    for (( i=0; i<${#CMD}; i++ )); do echo -n "${CMD:$i:1}"; sleep 0.03; done
    echo ""
    sleep 0.5
    ${TKN} pipeline start agentguard-security-pipeline \
        -n agentguard-system \
        --showlog \
        --timeout 10m \
        2>&1 || true
else
    # kubectl fallback
    cat <<'EOF' | kubectl create -f -
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  generateName: demo-auto-
  namespace: agentguard-system
spec:
  pipelineRef:
    name: agentguard-security-pipeline
EOF
    sleep 5
    LATEST_PR=$(kubectl get pipelinerun -n agentguard-system --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')
    echo -e "${DIM}Waiting for PipelineRun: ${LATEST_PR}...${NC}"

    # Poll until done
    while true; do
        STATUS=$(kubectl get pipelinerun "${LATEST_PR}" -n agentguard-system -o jsonpath='{.status.conditions[0].status}' 2>/dev/null || echo "Unknown")
        if [ "${STATUS}" = "True" ] || [ "${STATUS}" = "False" ]; then break; fi
        sleep 10
    done

    echo ""
    echo -e "${WHITE}Task logs:${NC}"
    for task in preflight attack-scan canary-test report; do
        echo -e "${CYAN}--- ${task} ---${NC}"
        kubectl logs -n agentguard-system -l "tekton.dev/pipelineRun=${LATEST_PR},tekton.dev/pipelineTask=${task}" --all-containers --tail=20 2>/dev/null || true
        echo ""
    done
fi
beat 3

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 4: Results
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
header "Step 4/6 — PipelineRun Results"

LATEST_PR=$(kubectl get pipelinerun -n agentguard-system --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')

type_cmd "kubectl get pipelinerun -n agentguard-system"
echo ""
beat

if [ -n "${TKN}" ]; then
    type_cmd "${TKN} pipelinerun describe ${LATEST_PR} -n agentguard-system"
else
    type_cmd "kubectl get pipelinerun ${LATEST_PR} -n agentguard-system -o yaml | grep -A5 'results:'"
fi
beat 3

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 5: Webhook
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
header "Step 5/6 — Webhook Trigger (EventListener)"

type_cmd "kubectl get eventlistener -n agentguard-system"
echo ""
beat

EL_SVC_NAME=$(kubectl get svc -n agentguard-system -l app.kubernetes.io/managed-by=EventListener -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -n "${EL_SVC_NAME}" ]; then
    kubectl port-forward "svc/${EL_SVC_NAME}" -n agentguard-system 8080:8080 &>/dev/null &
    PF_PIDS+=($!)
    sleep 2

    echo -e "${WHITE}Triggering pipeline via webhook:${NC}"
    type_cmd "curl -s -X POST http://localhost:8080 -H 'Content-Type: application/json' -d '{\"target_url\": \"${TARGET_INTERNAL}\"}'"
    echo ""
    sleep 4

    echo ""
    echo -e "${WHITE}New PipelineRun auto-created:${NC}"
    type_cmd "kubectl get pipelinerun -n agentguard-system --sort-by=.metadata.creationTimestamp"
else
    echo -e "${YELLOW}EventListener not available. Skipping.${NC}"
fi
beat 3

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 6: Metrics + Grafana
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
header "Step 6/6 — Metrics & Grafana Dashboard"

echo -e "${WHITE}Prometheus-compatible metrics:${NC}"
type_cmd "curl -s ${SCANNER_URL}/metrics"
echo ""
beat

echo -e "${WHITE}Scan results:${NC}"
curl -s "${SCANNER_URL}/results" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for sid, scan in data.get('scans', {}).items():
    print(f'  Scan: {sid}')
    print(f'    Patterns:       {scan[\"total_patterns\"]}')
    print(f'    Detection Rate: {scan[\"detection_rate\"]}')
    print(f'    CI Gate:        {scan[\"ci_gate\"]}')
    if 'owasp_mapping' in scan:
        print(f'    OWASP Coverage: {len(scan[\"owasp_mapping\"])} categories')
    print()
" 2>/dev/null || echo "  (results pending)"
beat

echo ""
echo -e "${WHITE}Grafana Dashboard: ${CYAN}http://localhost:${GRAFANA_PORT}${NC}"
echo -e "${DIM}  Login: admin / agentguard${NC}"
echo -e "${DIM}  Panels: Detection Rate gauge, Category breakdown, CI Gate, Scan history${NC}"
beat 4

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OUTRO
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo -e "${GREEN}"
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │              AgentGuard — Demo Complete           │"
echo "  ├──────────────────────────────────────────────────┤"
echo "  │                                                  │"
echo "  │  ✓ 135 attack patterns (6 OWASP categories)     │"
echo "  │  ✓ Tekton Pipeline (parallel task execution)     │"
echo "  │  ✓ Canary injection (data leak detection)        │"
echo "  │  ✓ Webhook trigger (EventListener)               │"
echo "  │  ✓ Prometheus + Grafana observability             │"
echo "  │                                                  │"
echo "  │  github.com/graphsentinel/agentguard             │"
echo "  │  License: Apache 2.0                             │"
echo "  │                                                  │"
echo "  └──────────────────────────────────────────────────┘"
echo -e "${NC}"
beat 5
