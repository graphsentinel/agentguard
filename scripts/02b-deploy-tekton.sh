#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Step 2b: Deploy Tekton + Pipeline + Triggers
# Installs Tekton Pipelines + Triggers and applies AgentGuard tasks/pipeline

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

echo "=== AgentGuard PoC - Deploy Tekton ==="
echo ""

# Tekton versions
TEKTON_PIPELINE_VERSION="v0.62.2"
TEKTON_TRIGGERS_VERSION="v0.28.0"

# Install Tekton Pipelines
# Note: gcr.io is deprecated, images are now on ghcr.io
echo "Installing Tekton Pipelines ${TEKTON_PIPELINE_VERSION}..."
curl -sL "https://storage.googleapis.com/tekton-releases/pipeline/previous/${TEKTON_PIPELINE_VERSION}/release.yaml" \
  | sed 's,gcr.io/tekton-releases,ghcr.io/tektoncd,g' \
  | kubectl apply -f -

echo "Waiting for Tekton Pipelines controller..."
kubectl rollout status deployment/tekton-pipelines-controller -n tekton-pipelines --timeout=180s

echo "Waiting for Tekton Pipelines webhook..."
kubectl rollout status deployment/tekton-pipelines-webhook -n tekton-pipelines --timeout=120s

echo "Tekton Pipelines ready."
echo ""

# Install Tekton Triggers
echo "Installing Tekton Triggers ${TEKTON_TRIGGERS_VERSION}..."
curl -sL "https://storage.googleapis.com/tekton-releases/triggers/previous/${TEKTON_TRIGGERS_VERSION}/release.yaml" \
  | sed 's,gcr.io/tekton-releases,ghcr.io/tektoncd,g' \
  | kubectl apply -f -

echo "Waiting for Tekton Triggers controller..."
kubectl rollout status deployment/tekton-triggers-controller -n tekton-pipelines --timeout=180s

echo "Waiting for Tekton Triggers webhook..."
kubectl rollout status deployment/tekton-triggers-webhook -n tekton-pipelines --timeout=120s

echo "Tekton Triggers ready."
echo ""

# Install Tekton Triggers Interceptors (required for EventListener)
echo "Installing Tekton Triggers Interceptors..."
curl -sL "https://storage.googleapis.com/tekton-releases/triggers/previous/${TEKTON_TRIGGERS_VERSION}/interceptors.yaml" \
  | sed 's,gcr.io/tekton-releases,ghcr.io/tektoncd,g' \
  | kubectl apply -f -

echo "Waiting for interceptors..."
kubectl rollout status deployment/tekton-triggers-core-interceptors -n tekton-pipelines --timeout=120s

echo "Tekton Triggers Interceptors ready."
echo ""

# Apply AgentGuard Tekton resources
echo "Applying AgentGuard Tasks..."
kubectl apply -f "${PROJECT_DIR}/manifests/tekton/tasks.yaml"

echo "Applying AgentGuard Pipeline..."
kubectl apply -f "${PROJECT_DIR}/manifests/tekton/pipeline.yaml"

echo "Applying AgentGuard Triggers..."
kubectl apply -f "${PROJECT_DIR}/manifests/tekton/triggers.yaml"

echo ""
echo "Verifying Tekton resources..."
echo "Tasks:"
kubectl get tasks -n agentguard-system
echo ""
echo "Pipeline:"
kubectl get pipeline -n agentguard-system
echo ""
echo "EventListener:"
kubectl get eventlistener -n agentguard-system
echo ""

echo "Tekton deployment complete."
