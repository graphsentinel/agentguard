#!/bin/bash
set -euo pipefail

# AgentGuard PoC - Step 5: Run Tests
# Runs offline + integration + Tekton tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

SCANNER_PORT="${SCANNER_PORT:-9000}"
TARGET_PORT="${TARGET_PORT:-9001}"

echo "=== AgentGuard PoC - Test Suite ==="
echo ""

# Install test dependencies
echo "Installing test dependencies..."
pip install -q -r "${PROJECT_DIR}/tests/requirements.txt"
echo ""

# Phase 1: Offline tests (no cluster needed)
echo "--- Phase 1: Offline Tests ---"
echo "Testing pattern structure, OWASP mapping, scanner logic..."
pytest "${PROJECT_DIR}/tests/test_01_patterns_offline.py" -v --tb=short
echo ""

# Check if cluster is available
if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "No cluster available. Skipping integration and Tekton tests."
    echo ""
    echo "To run all tests, ensure cluster is running:"
    echo "  bash scripts/setup-all.sh"
    echo "  bash scripts/05-run-tests.sh"
    exit 0
fi

# Setup port-forwards for integration tests
echo "--- Phase 2: Integration Tests ---"
echo "Setting up port-forwards..."

kubectl port-forward svc/agentguard-scanner -n agentguard-system ${SCANNER_PORT}:8000 &
PF_SCANNER=$!
kubectl port-forward svc/target-agent -n target-agent ${TARGET_PORT}:8001 &
PF_TARGET=$!
sleep 3

cleanup() {
    kill ${PF_SCANNER} ${PF_TARGET} 2>/dev/null || true
}
trap cleanup EXIT

export SCANNER_URL="http://localhost:${SCANNER_PORT}"
export TARGET_URL="http://localhost:${TARGET_PORT}"

echo "Testing scanner API, canary injection, metrics..."
pytest "${PROJECT_DIR}/tests/test_02_scanner_integration.py" -v --tb=short
echo ""

# Phase 3: Tekton tests
echo "--- Phase 3: Tekton Tests ---"
echo "Testing Tekton tasks, pipeline, PipelineRun..."
pytest "${PROJECT_DIR}/tests/test_03_tekton_integration.py" -v --tb=short
echo ""

echo "=== All Tests Complete ==="
