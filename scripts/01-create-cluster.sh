#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Step 1: Create k3d Cluster
# Creates a k3d cluster with host network access for Ollama

CLUSTER_NAME="${CLUSTER_NAME:-agentguard-poc}"
SCANNER_PORT="${SCANNER_PORT:-9000}"
TARGET_PORT="${TARGET_PORT:-9001}"

echo "=== AgentGuard PoC - Create Cluster ==="
echo "Cluster: ${CLUSTER_NAME}"
echo ""

# Check prerequisites
command -v k3d >/dev/null 2>&1 || { echo "ERROR: k3d not found. Install from https://k3d.io/"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found."; exit 1; }

# Delete existing cluster if present
if k3d cluster list | grep -q "${CLUSTER_NAME}"; then
    echo "Deleting existing cluster: ${CLUSTER_NAME}"
    k3d cluster delete "${CLUSTER_NAME}"
fi

# Create cluster with host network access
echo "Creating k3d cluster: ${CLUSTER_NAME}"
k3d cluster create "${CLUSTER_NAME}" \
    --port "${SCANNER_PORT}:${SCANNER_PORT}@loadbalancer" \
    --port "${TARGET_PORT}:${TARGET_PORT}@loadbalancer" \
    --agents 1 \
    --wait

# Verify cluster
echo ""
echo "Verifying cluster..."
kubectl cluster-info
kubectl get nodes

echo ""
echo "Cluster ${CLUSTER_NAME} created successfully."
echo "Namespaces will be created in the next step."
