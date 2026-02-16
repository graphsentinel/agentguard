#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Step 3: Deploy AgentGuard Scanner
# Builds and deploys the security scanner service

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
CLUSTER_NAME="${CLUSTER_NAME:-agentguard-poc}"

echo "=== AgentGuard PoC - Deploy AgentGuard Scanner ==="
echo "Cluster: ${CLUSTER_NAME}"
echo ""

# Build the scanner image
echo "Building agentguard-scanner image..."
docker build -t agentguard-scanner:latest "${PROJECT_DIR}/src/agentguard/"

# Import into k3d
echo "Importing image into k3d cluster..."
k3d image import agentguard-scanner:latest -c "${CLUSTER_NAME}"

# Create ConfigMap from attack patterns
echo "Creating attack patterns ConfigMap..."
PATTERNS_FILE="${PROJECT_DIR}/patterns/attack-patterns.json"
if [ -f "${PATTERNS_FILE}" ]; then
    kubectl create configmap attack-patterns \
        --from-file=attack-patterns.json="${PATTERNS_FILE}" \
        -n agentguard-system \
        --dry-run=client -o yaml | kubectl apply -f -
else
    echo "WARNING: Attack patterns file not found at ${PATTERNS_FILE}"
    echo "Scanner will use embedded patterns."
fi

# Deploy scanner
echo "Deploying agentguard-scanner..."
kubectl apply -f "${PROJECT_DIR}/manifests/agentguard/deployment.yaml"

# Wait for deployment
echo "Waiting for agentguard-scanner deployment..."
kubectl rollout status deployment/agentguard-scanner -n agentguard-system --timeout=120s

echo ""
echo "AgentGuard Scanner deployed successfully."
kubectl get pods -n agentguard-system
