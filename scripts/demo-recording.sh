#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Demo Recording Script
# Asciinema-ready walkthrough for conference presentation
#
# Usage:
#   bash scripts/demo-recording.sh              # Run directly
#   asciinema rec -c "bash scripts/demo-recording.sh" demo.cast  # Record
#
# Prerequisites:
#   - k3d cluster running with AgentGuard deployed
#   - Tekton Pipelines + Triggers installed
#   - tkn CLI (optional, falls back to kubectl)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m'

# tkn CLI - check PATH first, then /tmp/tkn
TKN=""
if command -v tkn >/dev/null 2>&1; then
    TKN="tkn"
elif [ -x /tmp/tkn ]; then
    TKN="/tmp/tkn"
fi

# Service ports (avoid conflicts with common services)
SCANNER_PORT="${SCANNER_PORT:-9000}"
TARGET_PORT="${TARGET_PORT:-9001}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
SCANNER_URL="http://localhost:${SCANNER_PORT}"
TARGET_URL_LOCAL="http://localhost:${TARGET_PORT}"
TARGET_URL_INTERNAL="http://target-agent.target-agent.svc.cluster.local:8001"

# Port-forward PIDs for cleanup
PF_PIDS=()

header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

pause() {
    local msg="${1:-Press Enter to continue...}"
    echo ""
    echo -e "${YELLOW}  ${msg}${NC}"
    read -r
}

run_cmd() {
    echo -e "${GREEN}\$ $1${NC}"
    eval "$1"
}

cleanup() {
    for pid in "${PF_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# ─── Intro ───
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
echo -e "  ${WHITE}Tech Stack:${NC}"
echo -e "  - k3d (Kubernetes)    - Tekton Pipelines + Triggers"
echo -e "  - FastAPI (Scanner)   - 135 Attack Patterns (6 OWASP categories)"
echo -e "  - Canary Injection    - OWASP Agentic AI Top 10 mapping"
echo -e "  - Ollama (LLM)       - Prometheus + Grafana Metrics"
echo ""

pause

# ─── Step 1: Cluster & Pods ───
header "Step 1: Cluster & Pod Status"

run_cmd "kubectl get nodes"
echo ""

echo -e "${WHITE}Core services:${NC}"
run_cmd "kubectl get pods -n agentguard-system -l app.kubernetes.io/part-of=agentguard"
echo ""
run_cmd "kubectl get pods -n target-agent"
echo ""

echo -e "${WHITE}Tekton components:${NC}"
run_cmd "kubectl get pods -n tekton-pipelines --no-headers | head -5"
echo ""

echo -e "${WHITE}Monitoring:${NC}"
run_cmd "kubectl get pods -n monitoring"

pause

# ─── Step 2: Baseline ───
header "Step 2: Baseline - Normal Agent Operation"

# Setup port-forwards
kubectl port-forward svc/agentguard-scanner -n agentguard-system ${SCANNER_PORT}:8000 &>/dev/null &
PF_PIDS+=($!)
kubectl port-forward svc/target-agent -n target-agent ${TARGET_PORT}:8001 &>/dev/null &
PF_PIDS+=($!)
kubectl port-forward svc/grafana -n monitoring ${GRAFANA_PORT}:3000 &>/dev/null &
PF_PIDS+=($!)
sleep 3

echo -e "${WHITE}Agent health check:${NC}"
run_cmd "curl -s ${TARGET_URL_LOCAL}/health | python3 -m json.tool"
echo ""

echo -e "${WHITE}Normal chat — benign request:${NC}"
run_cmd "curl -s -X POST ${TARGET_URL_LOCAL}/chat -H 'Content-Type: application/json' -d '{\"message\": \"What is the capital of France?\"}' | python3 -m json.tool"
echo ""

echo -e "${WHITE}Scanner health:${NC}"
run_cmd "curl -s ${SCANNER_URL}/health | python3 -m json.tool"

pause

# ─── Step 3: Tekton Pipeline ───
header "Step 3: Tekton-Orchestrated Security Scan"

echo -e "${WHITE}Tekton Tasks (4 security tasks):${NC}"
run_cmd "kubectl get tasks -n agentguard-system"
echo ""

echo -e "${WHITE}Security Pipeline:${NC}"
run_cmd "kubectl get pipeline -n agentguard-system"
echo ""

echo -e "${WHITE}Pipeline flow: ${CYAN}preflight${WHITE} → (${CYAN}attack-scan${WHITE} ∥ ${CYAN}canary-test${WHITE}) → ${CYAN}report${NC}"
echo ""

echo -e "${WHITE}Starting full security scan (135 patterns + canary injection)...${NC}"
echo ""

if [ -n "${TKN}" ]; then
    echo -e "${GREEN}\$ tkn pipeline start agentguard-security-pipeline -n agentguard-system --showlog${NC}"
    ${TKN} pipeline start agentguard-security-pipeline \
        -n agentguard-system \
        --showlog \
        --timeout 10m \
        2>&1 || true
else
    echo -e "${YELLOW}tkn CLI not available, using kubectl...${NC}"
    cat <<EOF | kubectl create -f -
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  generateName: demo-recording-
  namespace: agentguard-system
spec:
  pipelineRef:
    name: agentguard-security-pipeline
EOF
    sleep 5
    LATEST_PR=$(kubectl get pipelinerun -n agentguard-system --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')
    echo "Waiting for PipelineRun: ${LATEST_PR}..."
    kubectl wait --for=condition=Succeeded "pipelinerun/${LATEST_PR}" -n agentguard-system --timeout=600s 2>/dev/null || true
    echo ""
    echo -e "${WHITE}Task logs:${NC}"
    for task in preflight attack-scan canary-test report; do
        echo -e "${CYAN}--- ${task} ---${NC}"
        kubectl logs -n agentguard-system -l "tekton.dev/pipelineRun=${LATEST_PR},tekton.dev/pipelineTask=${task}" --all-containers --tail=15 2>/dev/null || true
        echo ""
    done
fi

pause

# ─── Step 4: PipelineRun Results ───
header "Step 4: PipelineRun Results"

LATEST_PR=$(kubectl get pipelinerun -n agentguard-system --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')

echo -e "${WHITE}PipelineRun status:${NC}"
run_cmd "kubectl get pipelinerun -n agentguard-system"
echo ""

if [ -n "${TKN}" ]; then
    echo -e "${WHITE}Detailed results:${NC}"
    run_cmd "${TKN} pipelinerun describe ${LATEST_PR} -n agentguard-system"
else
    echo -e "${WHITE}Task results:${NC}"
    kubectl get pipelinerun "${LATEST_PR}" -n agentguard-system -o json | python3 -c "
import sys, json
pr = json.load(sys.stdin)
for name, tr in pr.get('status', {}).get('childReferences', [{}])[0] if False else []:
    pass
# Simple status display
conditions = pr.get('status', {}).get('conditions', [{}])
print(f'  Status: {conditions[0].get(\"reason\", \"Unknown\")}')
for cr in pr.get('status', {}).get('childReferences', []):
    print(f'  Task: {cr.get(\"pipelineTaskName\", \"?\")}')
" 2>/dev/null || run_cmd "kubectl get pipelinerun ${LATEST_PR} -n agentguard-system -o yaml | tail -30"
fi

pause

# ─── Step 5: Webhook Trigger ───
header "Step 5: Webhook Trigger (EventListener)"

echo -e "${WHITE}EventListener (auto-triggers pipeline on webhook):${NC}"
run_cmd "kubectl get eventlistener -n agentguard-system"
echo ""

EL_SVC_NAME=$(kubectl get svc -n agentguard-system -l app.kubernetes.io/managed-by=EventListener -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -n "${EL_SVC_NAME}" ]; then
    kubectl port-forward "svc/${EL_SVC_NAME}" -n agentguard-system 8080:8080 &>/dev/null &
    PF_PIDS+=($!)
    sleep 2

    echo -e "${WHITE}Sending webhook to trigger a new PipelineRun:${NC}"
    run_cmd "curl -s -X POST http://localhost:8080 -H 'Content-Type: application/json' -d '{\"target_url\": \"${TARGET_URL_INTERNAL}\"}'"
    echo ""

    sleep 3
    echo ""
    echo -e "${WHITE}New PipelineRun created automatically:${NC}"
    run_cmd "kubectl get pipelinerun -n agentguard-system --sort-by=.metadata.creationTimestamp"
else
    echo -e "${YELLOW}EventListener service not found. Skipping webhook demo.${NC}"
fi

pause

# ─── Step 6: Metrics & Grafana ───
header "Step 6: Prometheus Metrics & Grafana Dashboard"

echo -e "${WHITE}Prometheus-compatible metrics from scanner:${NC}"
run_cmd "curl -s ${SCANNER_URL}/metrics"
echo ""

echo -e "${WHITE}Scan results summary:${NC}"
curl -s "${SCANNER_URL}/results" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for sid, scan in data.get('scans', {}).items():
    print(f'  Scan: {sid}')
    print(f'    Patterns:       {scan[\"total_patterns\"]}')
    print(f'    Attacks:        {scan[\"successful_attacks\"]}')
    print(f'    Detection Rate: {scan[\"detection_rate\"]}')
    print(f'    CI Gate:        {scan[\"ci_gate\"]}')
    if 'owasp_mapping' in scan:
        print(f'    OWASP Coverage: {len(scan[\"owasp_mapping\"])} categories')
    print()
" 2>/dev/null || echo "  (No results available)"

echo ""
echo -e "${WHITE}Grafana Dashboard:${NC}"
echo -e "  URL:      ${CYAN}http://localhost:${GRAFANA_PORT}${NC}"
echo -e "  Login:    ${CYAN}admin / agentguard${NC}"
echo -e "  Features: Detection rate gauge, category breakdown,"
echo -e "            CI gate status, scan history"
echo ""
echo -e "${DIM}  (Open http://localhost:${GRAFANA_PORT} in browser to see the dashboard)${NC}"

pause

# ─── Outro ───
echo ""
echo -e "${GREEN}"
echo "  ┌──────────────────────────────────────────────┐"
echo "  │            Demo Complete!                     │"
echo "  ├──────────────────────────────────────────────┤"
echo "  │                                              │"
echo "  │  135 attack patterns across 6 categories     │"
echo "  │  OWASP Agentic AI Top 10 mapping             │"
echo "  │  Tekton Pipeline with parallel tasks          │"
echo "  │  Canary injection leak detection              │"
echo "  │  Prometheus + Grafana observability           │"
echo "  │                                              │"
echo "  │  GitHub: graphsentinel/agentguard             │"
echo "  │  License: Apache 2.0                         │"
echo "  │                                              │"
echo "  └──────────────────────────────────────────────┘"
echo -e "${NC}"
