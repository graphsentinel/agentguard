#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Deploy Grafana
# Deploys Grafana with pre-configured AgentGuard dashboard

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

echo "=== AgentGuard PoC - Deploy Grafana ==="
echo ""

# Apply manifests
echo "Deploying Grafana..."
kubectl apply -f "${PROJECT_DIR}/manifests/monitoring/grafana.yaml"

echo "Waiting for Grafana deployment..."
kubectl rollout status deployment/grafana -n monitoring --timeout=120s

echo ""
echo "Grafana deployed successfully."
echo ""
echo "Access Grafana:"
echo "  kubectl port-forward svc/grafana -n monitoring 3000:3000"
echo "  Open: http://localhost:3000"
echo "  Login: admin / agentguard"
echo ""
kubectl get pods -n monitoring
