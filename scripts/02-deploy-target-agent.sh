#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Step 2: Deploy Target Agent
# Builds and deploys the sample AI agent with pluggable LLM support

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
CLUSTER_NAME="${CLUSTER_NAME:-agentguard-poc}"
LLM_PROVIDER="${LLM_PROVIDER:-ollama}"
LLM_URL="${LLM_URL:-${OLLAMA_URL:-http://ollama.platform.localhost:11434}}"
LLM_MODEL="${LLM_MODEL:-${OLLAMA_MODEL:-llama3.2:1b}}"
LLM_API_KEY="${LLM_API_KEY:-}"

echo "=== AgentGuard PoC - Deploy Target Agent ==="
echo "Cluster:      ${CLUSTER_NAME}"
echo "LLM Provider: ${LLM_PROVIDER}"
echo "LLM URL:      ${LLM_URL}"
echo "LLM Model:    ${LLM_MODEL}"
echo ""

# Build the target agent image
echo "Building target-agent image..."
docker build -t target-agent:latest "${PROJECT_DIR}/src/target-agent/"

# Import into k3d
echo "Importing image into k3d cluster..."
k3d image import target-agent:latest -c "${CLUSTER_NAME}"

# Create namespace
echo "Creating namespace..."
kubectl apply -f "${PROJECT_DIR}/manifests/namespaces/namespaces.yaml"

# Apply deployment
kubectl apply -f "${PROJECT_DIR}/manifests/target-agent/deployment.yaml"

# Patch env vars if non-default values provided
kubectl set env deployment/target-agent -n target-agent \
    LLM_PROVIDER="${LLM_PROVIDER}" \
    LLM_URL="${LLM_URL}" \
    LLM_MODEL="${LLM_MODEL}" \
    LLM_API_KEY="${LLM_API_KEY}"

# Wait for deployment
echo "Waiting for target-agent deployment..."
kubectl rollout status deployment/target-agent -n target-agent --timeout=120s

echo ""
echo "Target agent deployed successfully."
kubectl get pods -n target-agent
