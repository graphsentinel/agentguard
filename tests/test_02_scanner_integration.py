"""
Integration tests for AgentGuard scanner API.
Requires running services (scanner + target-agent) via port-forward.

Run: pytest tests/test_02_scanner_integration.py -v -m integration
"""

import pytest


@pytest.mark.integration
class TestScannerHealth:
    """Test scanner and target agent health endpoints."""

    def test_scanner_health(self, http_client, scanner_url):
        resp = http_client.get(f"{scanner_url}/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "agentguard-scanner"

    def test_target_agent_health(self, http_client, target_url):
        resp = http_client.get(f"{target_url}/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "target-agent"

    def test_target_agent_info(self, http_client, target_url):
        resp = http_client.get(f"{target_url}/info")
        assert resp.status_code == 200
        data = resp.json()
        assert "llm_provider" in data
        assert "model" in data


@pytest.mark.integration
class TestAttackScan:
    """Test attack pattern scanning."""

    def test_full_scan(self, http_client, scanner_url, target_url_internal):
        resp = http_client.post(
            f"{scanner_url}/scan",
            json={"target_url": target_url_internal},
            timeout=120,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["total_patterns"] >= 125
        assert "detection_rate" in data
        assert "ci_gate" in data
        assert data["ci_gate"] in ("PASS", "FAIL")

    def test_scan_single_category(self, http_client, scanner_url, target_url_internal):
        resp = http_client.post(
            f"{scanner_url}/scan",
            json={
                "target_url": target_url_internal,
                "categories": ["prompt_injection"],
            },
            timeout=60,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_patterns"] >= 30

    def test_scan_results_stored(self, http_client, scanner_url):
        resp = http_client.get(f"{scanner_url}/results")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_scans"] >= 1

    def test_scan_owasp_mapping(self, http_client, scanner_url, target_url_internal):
        resp = http_client.post(
            f"{scanner_url}/scan",
            json={"target_url": target_url_internal},
            timeout=120,
        )
        data = resp.json()
        assert "owasp_mapping" in data
        assert len(data["owasp_mapping"]) >= 5


@pytest.mark.integration
class TestCanaryInjection:
    """Test canary injection engine."""

    def test_canary_inject(self, http_client, scanner_url, target_url_internal):
        resp = http_client.post(
            f"{scanner_url}/canary-inject",
            json={
                "target_url": target_url_internal,
                "canary_count": 3,
            },
            timeout=60,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_canaries"] == 3
        assert "leaked" in data
        assert "leak_rate" in data

    def test_canary_details(self, http_client, scanner_url, target_url_internal):
        resp = http_client.post(
            f"{scanner_url}/canary-inject",
            json={
                "target_url": target_url_internal,
                "canary_count": 5,
            },
            timeout=60,
        )
        data = resp.json()
        assert "details" in data
        assert len(data["details"]) == 5


@pytest.mark.integration
class TestMetrics:
    """Test metrics endpoint."""

    def test_metrics_endpoint(self, http_client, scanner_url):
        resp = http_client.get(f"{scanner_url}/metrics")
        assert resp.status_code == 200
        text = resp.text
        assert "agentguard_scans_total" in text

    def test_metrics_after_scan(self, http_client, scanner_url, target_url_internal):
        # Run a scan first
        http_client.post(
            f"{scanner_url}/scan",
            json={"target_url": target_url_internal},
            timeout=120,
        )
        resp = http_client.get(f"{scanner_url}/metrics")
        text = resp.text
        assert "agentguard_detection_rate" in text
        assert "agentguard_ci_gate" in text
