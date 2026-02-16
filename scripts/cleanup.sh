#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Cleanup
# Removes the k3d cluster and all resources

CLUSTER_NAME="${CLUSTER_NAME:-agentguard-poc}"

echo "=== AgentGuard PoC - Cleanup ==="
echo "Cluster: ${CLUSTER_NAME}"
echo ""

# Kill any port-forwards
echo "Stopping port-forwards..."
pkill -f "kubectl port-forward.*agentguard" 2>/dev/null || true
pkill -f "kubectl port-forward.*target-agent" 2>/dev/null || true

# Clean up Tekton resources (before deleting cluster)
if kubectl cluster-info >/dev/null 2>&1; then
    echo "Cleaning up Tekton resources..."
    kubectl delete pipelinerun --all -n agentguard-system 2>/dev/null || true
    kubectl delete eventlistener agentguard-listener -n agentguard-system 2>/dev/null || true
    kubectl delete pipeline agentguard-security-pipeline -n agentguard-system 2>/dev/null || true
    kubectl delete task agentguard-preflight agentguard-attack-scan agentguard-canary-test agentguard-report -n agentguard-system 2>/dev/null || true
    echo "Tekton resources cleaned up."
fi

# Delete cluster
if k3d cluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
    echo "Deleting k3d cluster: ${CLUSTER_NAME}"
    k3d cluster delete "${CLUSTER_NAME}"
    echo "Cluster deleted."
else
    echo "Cluster ${CLUSTER_NAME} not found."
fi

# Clean up local images (optional)
echo ""
echo "Local images (optional cleanup):"
docker images | grep -E "agentguard-scanner|target-agent" || echo "  No local images found."
echo ""
echo "To remove local images:"
echo "  docker rmi agentguard-scanner:latest target-agent:latest"
echo ""
echo "Cleanup complete."
