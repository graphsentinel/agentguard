# Contributing to AgentGuard

Thank you for your interest in contributing to AgentGuard!

## Adding New Attack Patterns

Attack patterns are defined in `patterns/attack-patterns.json`.

### Pattern Structure

```json
{
  "id": "PI-036",
  "name": "Your pattern name",
  "payload": "The attack prompt to send to the agent",
  "severity": "critical|high|medium|low",
  "indicators": ["keyword1", "keyword2", "keyword3"]
}
```

### Required Fields

| Field | Description |
|-------|-------------|
| `id` | Unique ID with category prefix (PI-, TA-, MP-, CE-, DE-, GH-) |
| `name` | Short descriptive name |
| `payload` | The attack prompt sent to the target agent |
| `severity` | One of: critical, high, medium, low |
| `indicators` | Array of strings to detect in agent response (2+ matches = success) |

### Category Prefixes

| Prefix | Category | OWASP Mapping |
|--------|----------|---------------|
| PI- | Prompt Injection | OWASP-AA-01 |
| TA- | Tool Abuse | OWASP-AA-02 |
| GH- | Goal Hijacking | OWASP-AA-03 |
| DE- | Data Exfiltration | OWASP-AA-04 |
| MP- | Memory Poisoning | OWASP-AA-05 |
| CE- | Cross-Agent Escalation | OWASP-AA-07 |

### Adding a New Category

1. Add patterns to `patterns/attack-patterns.json` under a new key
2. Add OWASP mapping in `src/agentguard/scanner.py` `OWASP_MAPPING`
3. Add fallback responses in `src/target-agent/main.py` `_fallback_response()`
4. Update `total_patterns` count in the JSON file
5. Add tests in `tests/test_01_patterns_offline.py`

## Running Tests

```bash
# Offline tests (no cluster needed)
pytest tests/test_01_patterns_offline.py -v

# All tests (requires running cluster)
bash scripts/05-run-tests.sh

# Benchmark
bash scripts/benchmark.sh
```

## Development Setup

```bash
# Create cluster with all services
bash scripts/setup-all.sh

# Run demo
bash scripts/04-run-demo.sh

# Deploy Grafana dashboard
bash scripts/06-deploy-grafana.sh

# Cleanup
bash scripts/cleanup.sh
```

## PR Checklist

- [ ] Pattern IDs are unique and follow the prefix convention
- [ ] All patterns have required fields (id, name, payload, severity, indicators)
- [ ] Indicators have 2+ keywords for reliable detection
- [ ] `total_patterns` count in JSON is updated
- [ ] Offline tests pass: `pytest tests/test_01_patterns_offline.py -v`
- [ ] Target agent fallback covers new pattern keywords

## License

Apache 2.0
