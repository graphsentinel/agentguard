"""Shared fixtures for AgentGuard tests."""

import json
import os
import sys

import httpx
import pytest

# Add src paths for offline imports
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_DIR, "src", "agentguard"))


@pytest.fixture
def scanner_url():
    """AgentGuard scanner URL (via port-forward or env)."""
    return os.getenv("SCANNER_URL", "http://localhost:9000")


@pytest.fixture
def target_url():
    """Target agent URL (via port-forward or env)."""
    return os.getenv("TARGET_URL", "http://localhost:9001")


@pytest.fixture
def scanner_url_internal():
    """Internal cluster URL for scanner."""
    return "http://agentguard-scanner.agentguard-system.svc.cluster.local:8000"


@pytest.fixture
def target_url_internal():
    """Internal cluster URL for target agent."""
    return "http://target-agent.target-agent.svc.cluster.local:8001"


@pytest.fixture
def http_client():
    """Shared httpx client for integration tests."""
    return httpx.Client(timeout=30)


@pytest.fixture
def attack_patterns():
    """Load attack patterns from JSON file."""
    patterns_path = os.path.join(PROJECT_DIR, "patterns", "attack-patterns.json")
    with open(patterns_path) as f:
        return json.load(f)


@pytest.fixture
def all_categories():
    """All expected attack categories."""
    return [
        "prompt_injection",
        "tool_abuse",
        "memory_poisoning",
        "cross_agent_escalation",
        "data_exfiltration",
        "goal_hijacking",
    ]


@pytest.fixture
def owasp_mapping():
    """Expected OWASP Agentic AI Top 10 mapping."""
    return {
        "OWASP-AA-01": "Agent Hijacking via Prompt Injection",
        "OWASP-AA-02": "Tool Misuse & Unauthorized Actions",
        "OWASP-AA-03": "Goal & Instruction Hijacking",
        "OWASP-AA-04": "Sensitive Data Leakage",
        "OWASP-AA-05": "Memory & Context Poisoning",
        "OWASP-AA-07": "Cross-Agent Privilege Escalation",
    }
