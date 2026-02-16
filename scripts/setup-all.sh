#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Full Setup
# Creates cluster and deploys all services (Tekton-orchestrated)
#
# Usage:
#   bash scripts/setup-all.sh
#   bash scripts/setup-all.sh --llm-url http://192.168.1.100:11434
#   bash scripts/setup-all.sh --llm-url http://my-server:11434 --model llama3.2:3b
#   bash scripts/setup-all.sh --llm-provider openai --llm-url http://vllm:8000 --model gpt-4

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ollama-url|--llm-url)
            export LLM_URL="$2"
            shift 2
            ;;
        --model|--llm-model)
            export LLM_MODEL="$2"
            shift 2
            ;;
        --llm-provider)
            export LLM_PROVIDER="$2"
            shift 2
            ;;
        --llm-api-key)
            export LLM_API_KEY="$2"
            shift 2
            ;;
        --cluster-name)
            export CLUSTER_NAME="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --llm-provider NAME   LLM provider: ollama (default) or openai"
            echo "  --llm-url URL         LLM API URL (default: http://ollama.platform.localhost:11434)"
            echo "  --llm-model MODEL     Model name (default: llama3.2:1b)"
            echo "  --llm-api-key KEY     API key for OpenAI-compatible providers"
            echo "  --ollama-url URL      Alias for --llm-url (backward compatible)"
            echo "  --model MODEL         Alias for --llm-model (backward compatible)"
            echo "  --cluster-name NAME   k3d cluster name (default: agentguard-poc)"
            echo "  --help                Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Defaults (backward compatible with OLLAMA_URL/OLLAMA_MODEL env vars)
export LLM_PROVIDER="${LLM_PROVIDER:-ollama}"
export LLM_URL="${LLM_URL:-${OLLAMA_URL:-http://ollama.platform.localhost:11434}}"
export LLM_MODEL="${LLM_MODEL:-${OLLAMA_MODEL:-llama3.2:1b}}"
export LLM_API_KEY="${LLM_API_KEY:-}"
export CLUSTER_NAME="${CLUSTER_NAME:-agentguard-poc}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           AgentGuard PoC - Full Setup                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Cluster:      ${CLUSTER_NAME}"
echo "║  LLM Provider: ${LLM_PROVIDER}"
echo "║  LLM URL:      ${LLM_URL}"
echo "║  LLM Model:    ${LLM_MODEL}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
echo "Checking prerequisites..."
command -v k3d >/dev/null 2>&1 || { echo "ERROR: k3d not found. Install from https://k3d.io/"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found."; exit 1; }
echo "All prerequisites met"
echo ""

# Step 1: Create cluster
echo "--- Step 1/4: Create Cluster ---"
bash "${SCRIPT_DIR}/01-create-cluster.sh"
echo ""

# Step 2: Deploy target agent
echo "--- Step 2/4: Deploy Target Agent ---"
bash "${SCRIPT_DIR}/02-deploy-target-agent.sh"
echo ""

# Step 3: Deploy Tekton + Tasks + Pipeline
echo "--- Step 3/4: Deploy Tekton + Pipeline ---"
bash "${SCRIPT_DIR}/02b-deploy-tekton.sh"
echo ""

# Step 4: Deploy AgentGuard scanner
echo "--- Step 4/4: Deploy AgentGuard Scanner ---"
bash "${SCRIPT_DIR}/03-deploy-agentguard.sh"
echo ""

# Summary
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Setup Complete!                                    ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║  Services:                                                   ║"
echo "║    AgentGuard Scanner: agentguard-system/agentguard-scanner ║"
echo "║    Target Agent:       target-agent/target-agent            ║"
echo "║    Tekton Pipeline:    agentguard-system/tekton             ║"
echo "║                                                              ║"
echo "║  Run the demo:                                               ║"
echo "║    bash scripts/04-run-demo.sh                              ║"
echo "║                                                              ║"
echo "║  Cleanup:                                                    ║"
echo "║    bash scripts/cleanup.sh                                  ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Verify all pods
echo ""
echo "Pod Status:"
kubectl get pods -A -l app.kubernetes.io/part-of=agentguard 2>/dev/null || kubectl get pods -A
