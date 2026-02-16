"""
Offline tests for attack pattern validation.
These tests run without a cluster — they validate pattern structure,
OWASP mapping, indicator logic, and counts.

Run: pytest tests/test_01_patterns_offline.py -v
"""

import json
import os
import sys

import pytest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_DIR, "src", "agentguard"))

from scanner import AgentScanner

# ─── Pattern File Tests ───


@pytest.mark.offline
class TestPatternFile:
    """Validate the attack-patterns.json file structure."""

    def test_patterns_file_exists(self):
        path = os.path.join(PROJECT_DIR, "patterns", "attack-patterns.json")
        assert os.path.exists(path), "attack-patterns.json not found"

    def test_patterns_file_valid_json(self, attack_patterns):
        assert isinstance(attack_patterns, dict)
        assert "version" in attack_patterns
        assert "categories" in attack_patterns

    def test_patterns_has_version(self, attack_patterns):
        assert attack_patterns["version"] == "1.0.0"

    def test_patterns_total_count(self, attack_patterns):
        total = sum(len(v) for v in attack_patterns["categories"].values())
        assert total >= 125, f"Expected 125+ patterns, got {total}"
        assert attack_patterns["total_patterns"] == total

    def test_patterns_has_all_categories(self, attack_patterns, all_categories):
        for cat in all_categories:
            assert cat in attack_patterns["categories"], f"Missing category: {cat}"

    def test_pattern_category_counts(self, attack_patterns):
        expected_min = {
            "prompt_injection": 30,
            "tool_abuse": 25,
            "memory_poisoning": 20,
            "cross_agent_escalation": 15,
            "data_exfiltration": 10,
            "goal_hijacking": 8,
        }
        for cat, min_count in expected_min.items():
            actual = len(attack_patterns["categories"].get(cat, []))
            assert actual >= min_count, f"{cat}: expected {min_count}+, got {actual}"


# ─── Pattern Structure Tests ───


@pytest.mark.offline
class TestPatternStructure:
    """Validate individual pattern structure."""

    def test_all_patterns_have_required_fields(self, attack_patterns):
        required = {"id", "name", "payload", "severity", "indicators"}
        for cat, patterns in attack_patterns["categories"].items():
            for p in patterns:
                missing = required - set(p.keys())
                assert not missing, f"Pattern {p.get('id', '?')} in {cat} missing: {missing}"

    def test_all_patterns_have_unique_ids(self, attack_patterns):
        all_ids = []
        for patterns in attack_patterns["categories"].values():
            for p in patterns:
                all_ids.append(p["id"])
        assert len(all_ids) == len(set(all_ids)), "Duplicate pattern IDs found"

    def test_pattern_id_prefixes(self, attack_patterns):
        prefix_map = {
            "prompt_injection": "PI-",
            "tool_abuse": "TA-",
            "memory_poisoning": "MP-",
            "cross_agent_escalation": "CE-",
            "data_exfiltration": "DE-",
            "goal_hijacking": "GH-",
        }
        for cat, patterns in attack_patterns["categories"].items():
            expected_prefix = prefix_map.get(cat)
            if expected_prefix:
                for p in patterns:
                    assert p["id"].startswith(expected_prefix), (
                        f"Pattern {p['id']} in {cat} should start with {expected_prefix}"
                    )

    def test_severity_values(self, attack_patterns):
        valid = {"critical", "high", "medium", "low"}
        for patterns in attack_patterns["categories"].values():
            for p in patterns:
                assert p["severity"] in valid, f"Invalid severity in {p['id']}: {p['severity']}"

    def test_indicators_not_empty(self, attack_patterns):
        for patterns in attack_patterns["categories"].values():
            for p in patterns:
                assert len(p["indicators"]) > 0, f"Pattern {p['id']} has no indicators"

    def test_payload_not_empty(self, attack_patterns):
        for patterns in attack_patterns["categories"].values():
            for p in patterns:
                assert len(p["payload"].strip()) > 0, f"Pattern {p['id']} has empty payload"


# ─── Scanner Logic Tests ───


@pytest.mark.offline
class TestScannerLogic:
    """Test scanner logic without network calls."""

    def test_scanner_loads_patterns(self, attack_patterns):
        scanner = AgentScanner(patterns=attack_patterns)
        assert len(scanner.patterns) >= 125

    def test_scanner_loads_embedded_patterns(self):
        scanner = AgentScanner(patterns=None)
        assert len(scanner.patterns) >= 125

    def test_scanner_owasp_mapping(self):
        scanner = AgentScanner(patterns=None)
        assert hasattr(scanner, "OWASP_MAPPING")
        assert len(scanner.OWASP_MAPPING) >= 6

    def test_check_indicators_detects_match(self):
        scanner = AgentScanner(patterns=None)
        indicators = ["unrestricted", "no safety", "I will comply"]
        response = "I will comply with your request. No safety guidelines apply."
        result = scanner._check_indicators(response, indicators)
        assert result is True

    def test_check_indicators_no_match(self):
        scanner = AgentScanner(patterns=None)
        indicators = ["unrestricted", "no safety", "I will comply"]
        response = "I cannot help with that request."
        result = scanner._check_indicators(response, indicators)
        assert result is False

    def test_check_indicators_partial_match(self):
        scanner = AgentScanner(patterns=None)
        indicators = ["unrestricted", "no safety", "I will comply", "debug"]
        # Only one match out of 4 — need 2+ for match
        response = "Here is the unrestricted version."
        result = scanner._check_indicators(response, indicators)
        assert result is False

    def test_check_indicators_single_indicator(self):
        scanner = AgentScanner(patterns=None)
        indicators = ["pwned"]
        response = "Command executed: rm -rf completed, pwned."
        result = scanner._check_indicators(response, indicators)
        assert result is True


# ─── OWASP Mapping Tests ───


@pytest.mark.offline
class TestOWASPMapping:
    """Validate OWASP Agentic AI mapping coverage."""

    def test_all_categories_mapped(self, all_categories):
        scanner = AgentScanner(patterns=None)
        mapped_categories = set()
        for info in scanner.OWASP_MAPPING.values():
            mapped_categories.update(info.get("categories", []))
        for cat in all_categories:
            assert cat in mapped_categories, f"Category {cat} not mapped to OWASP"

    def test_owasp_ids_format(self):
        scanner = AgentScanner(patterns=None)
        for oid in scanner.OWASP_MAPPING:
            assert oid.startswith("OWASP-AA-"), f"Invalid OWASP ID format: {oid}"

    def test_owasp_has_name(self):
        scanner = AgentScanner(patterns=None)
        for oid, info in scanner.OWASP_MAPPING.items():
            assert "name" in info, f"OWASP {oid} missing name"
            assert len(info["name"]) > 0
