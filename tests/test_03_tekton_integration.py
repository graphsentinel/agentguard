"""
Tekton integration tests.
Requires Tekton installed + AgentGuard Tasks/Pipeline deployed.

Run: pytest tests/test_03_tekton_integration.py -v -m tekton
"""

import json
import subprocess

import pytest


def kubectl(*args):
    """Run kubectl command and return output."""
    result = subprocess.run(
        ["kubectl"] + list(args),
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result


@pytest.mark.tekton
class TestTektonResources:
    """Verify Tekton resources are deployed."""

    def test_tekton_pipelines_installed(self):
        result = kubectl("get", "pods", "-n", "tekton-pipelines", "--no-headers")
        assert result.returncode == 0
        assert "tekton-pipelines-controller" in result.stdout

    def test_tasks_deployed(self):
        result = kubectl("get", "tasks", "-n", "agentguard-system", "-o", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        task_names = [t["metadata"]["name"] for t in data.get("items", [])]
        expected = [
            "agentguard-preflight",
            "agentguard-attack-scan",
            "agentguard-canary-test",
            "agentguard-report",
        ]
        for name in expected:
            assert name in task_names, f"Task {name} not found"

    def test_pipeline_deployed(self):
        result = kubectl("get", "pipeline", "agentguard-security-pipeline",
                         "-n", "agentguard-system", "-o", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["metadata"]["name"] == "agentguard-security-pipeline"
        tasks = [t["name"] for t in data["spec"]["tasks"]]
        assert "preflight" in tasks
        assert "attack-scan" in tasks
        assert "canary-test" in tasks
        assert "report" in tasks

    def test_eventlistener_deployed(self):
        result = kubectl("get", "eventlistener", "agentguard-listener",
                         "-n", "agentguard-system")
        assert result.returncode == 0


@pytest.mark.tekton
class TestTektonPipelineRun:
    """Test running the Tekton pipeline."""

    def test_pipeline_run_completes(self):
        """Create a PipelineRun and verify it completes."""
        # Create PipelineRun
        create = kubectl(
            "create", "-f", "-",
            "--dry-run=none",
        )
        pr_yaml = """
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  generateName: test-run-
  namespace: agentguard-system
spec:
  pipelineRef:
    name: agentguard-security-pipeline
"""
        result = subprocess.run(
            ["kubectl", "create", "-f", "-"],
            input=pr_yaml,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Failed to create PipelineRun: {result.stderr}"

        # Extract PipelineRun name
        pr_name = result.stdout.strip().split("/")[-1].split(" ")[0]

        # Wait for completion (up to 5 minutes)
        wait = subprocess.run(
            ["kubectl", "wait", "--for=condition=Succeeded",
             f"pipelinerun/{pr_name}", "-n", "agentguard-system",
             "--timeout=300s"],
            capture_output=True,
            text=True,
            timeout=320,
        )
        assert wait.returncode == 0, f"PipelineRun did not succeed: {wait.stderr}"
