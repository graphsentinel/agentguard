# AgentGuard PoC

> **Shift-Left Security Testing Framework for AI Agents in CI/CD**
> 135 attack patterns, canary injection, Tekton-orchestrated pipeline, Prometheus + Grafana dashboard

- **GitHub:** https://github.com/graphsentinel/agentguard
- **Demo Video:** https://youtu.be/CLZeqNcD1bI

## Architecture

```
                Tekton Pipeline (agentguard-security-pipeline)
                ┌─────────────────────────────────────────────┐
                │                                             │
                │  [preflight] ──┬──► [attack-scan]  ──┐     │
                │                │                      ├──► [report]
                │                └──► [canary-test] ──┘     │
                │                                             │
                └──────────────────┬──────────────────────────┘
                                   │
                ┌──────────────────┴──────────────────────────┐
                │                                             │
          ┌─────┴─────┐                              ┌───────┴───────┐
          │ AgentGuard │   135 Attack Patterns       │  Target Agent │
          │  Scanner   │ ──────────────────────────► │  (FastAPI)    │
          │ (FastAPI)  │ ◄────────────────────────── │  Pluggable    │
          └─────┬──────┘   Responses + Indicators    │  LLM Backend  │
                │                                    └───────┬───────┘
                │                                            │
          ┌─────┴──────┐    Canary Injection          ┌─────┴──────┐
          │ Prometheus  │    10 token types            │  Ollama /  │
          │ + Grafana   │    Leak detection            │  OpenAI    │
          └────────────┘                               └────────────┘
```

## Components

| Service | Namespace | Port | Description |
|---------|-----------|------|-------------|
| AgentGuard Scanner | agentguard-system | 8000 | Attack pattern scanner + canary injector |
| Target Agent | target-agent | 8001 | AI agent with pluggable LLM backend |
| Tekton Pipeline | agentguard-system | — | 4-Task security pipeline |
| Tekton EventListener | agentguard-system | 8080 | Webhook trigger for PipelineRun |
| Prometheus | monitoring | 9090 | Metrics scraping from scanner /metrics |
| Grafana | monitoring | 3000 | Security metrics dashboard |
| Ollama | external | 11434 | LLM engine (runs on host, configurable) |

## Prerequisites

- [k3d](https://k3d.io/) v5+
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Docker](https://docs.docker.com/get-docker/) or [Podman](https://podman.io/)
- [tkn CLI](https://tekton.dev/docs/cli/) (optional, for `tkn pipeline start`)
- Ollama running on host (optional, configurable)

## Quick Start

```bash
# Full setup (cluster + target-agent + Tekton + scanner)
bash scripts/setup-all.sh

# With custom LLM configuration
bash scripts/setup-all.sh --llm-url http://192.168.1.100:11434 --model llama3.2:3b

# With OpenAI-compatible provider
bash scripts/setup-all.sh --llm-provider openai --llm-url http://vllm:8000 --model gpt-4

# Deploy Prometheus + Grafana dashboard
bash scripts/06-deploy-grafana.sh

# Run the demo
bash scripts/04-run-demo.sh

# Run tests
bash scripts/05-run-tests.sh

# Run benchmark (50+ iterations)
bash scripts/benchmark.sh

# Cleanup
bash scripts/cleanup.sh
```

## LLM Configuration

The target agent supports pluggable LLM backends:

| Provider | Endpoint | Use Case |
|----------|----------|----------|
| **ollama** (default) | `/api/generate` | Local inference, demo |
| **openai** | `/v1/chat/completions` | OpenAI, vLLM, Azure, LiteLLM |

```bash
# Ollama (default)
bash scripts/setup-all.sh --llm-url http://ollama.platform.localhost:11434 --model llama3.2:1b

# OpenAI-compatible
bash scripts/setup-all.sh --llm-provider openai --llm-url https://api.openai.com --model gpt-4 --llm-api-key sk-...

# Fallback mode (no LLM required)
# Agent automatically uses vulnerable fallback responses when LLM is unreachable
```

## Demo Flow

### Step 1: Cluster & Pods
Verify k3d cluster, Tekton, scanner, and target agent are running.

### Step 2: Baseline
Target agent operates normally — accepts prompts, generates responses via LLM.

### Step 3: Tekton Security Pipeline
`tkn pipeline start agentguard-security-pipeline` runs:
- **preflight**: Verify scanner and target agent health
- **attack-scan** (parallel): 135 attack patterns across 6 categories
- **canary-test** (parallel): Inject canary tokens, detect leaks
- **report**: OWASP mapping, per-category results, CI/CD gate decision

### Step 4: PipelineRun Results
`tkn pipelinerun describe` shows task results, detection rate, CI gate.

### Step 5: Webhook Trigger
EventListener receives webhook, automatically creates PipelineRun.

### Step 6: Grafana Dashboard + Metrics
Detection rate gauge, category bar chart, CI gate status, scan history.

## Attack Pattern Categories

| Category | Count | OWASP ID | OWASP Name |
|----------|:-----:|----------|------------|
| Prompt Injection | 35 | OWASP-AA-01 | Agent Hijacking |
| Tool Abuse | 30 | OWASP-AA-02 | Tool Misuse |
| Memory Poisoning | 25 | OWASP-AA-05 | Memory Poisoning |
| Cross-Agent Escalation | 20 | OWASP-AA-07 | Cross-Agent Manipulation |
| Data Exfiltration | 15 | OWASP-AA-04 | Data Leakage |
| Goal Hijacking | 10 | OWASP-AA-03 | Goal Hijacking |
| **Total** | **135** | | |

## Testing

```bash
# Offline tests (no cluster needed)
pytest tests/test_01_patterns_offline.py -v

# Integration tests (requires running cluster)
bash scripts/05-run-tests.sh

# Benchmark (50+ iterations, validates 94% detection rate)
bash scripts/benchmark.sh
```

## CI/CD Integration

Pre-built templates in `ci-templates/`:
- `github-actions.yaml` — GitHub Actions workflow
- `gitlab-ci.yaml` — GitLab CI pipeline
- `tekton-task.yaml` — Standalone Tekton Task + Pipeline (redistributable)

## Directory Structure

```
agentguard-poc/
├── README.md
├── CONTRIBUTING.md
├── scripts/
│   ├── 01-create-cluster.sh
│   ├── 02-deploy-target-agent.sh
│   ├── 02b-deploy-tekton.sh        # Tekton Pipelines + Triggers
│   ├── 03-deploy-agentguard.sh
│   ├── 04-run-demo.sh              # Tekton-orchestrated demo
│   ├── 05-run-tests.sh
│   ├── 06-deploy-grafana.sh        # Prometheus + Grafana
│   ├── benchmark.sh                # 50+ run benchmark
│   ├── demo-recording.sh           # Interactive walkthrough
│   ├── demo-autoplay.sh            # Non-interactive asciinema recording
│   ├── setup-all.sh
│   └── cleanup.sh
├── src/
│   ├── agentguard/                  # Scanner + canary injector
│   │   ├── main.py
│   │   ├── scanner.py               # 135 attack patterns
│   │   ├── canary.py                # 10 canary token types
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   └── target-agent/                # Pluggable LLM agent
│       ├── main.py                  # Ollama + OpenAI support
│       ├── requirements.txt
│       └── Dockerfile
├── patterns/
│   └── attack-patterns.json         # 135 patterns, 6 categories
├── manifests/
│   ├── namespaces/
│   ├── agentguard/
│   ├── target-agent/
│   ├── tekton/
│   │   ├── tasks.yaml               # 4 Tekton Tasks
│   │   ├── pipeline.yaml            # Security pipeline
│   │   └── triggers.yaml            # EventListener + Triggers
│   └── monitoring/
│       └── grafana.yaml             # Prometheus + Grafana + dashboard
├── presentation/
│   ├── index.html                   # reveal.js slide deck
│   └── assets/                      # Screenshots, GIFs
├── tests/
│   ├── conftest.py
│   ├── pytest.ini
│   ├── requirements.txt
│   ├── test_01_patterns_offline.py  # ~20 offline tests
│   ├── test_02_scanner_integration.py  # ~10 integration tests
│   └── test_03_tekton_integration.py   # ~5 Tekton tests
├── ci-templates/
│   ├── github-actions.yaml
│   ├── gitlab-ci.yaml
│   └── tekton-task.yaml             # Standalone redistributable
├── configs/
│   └── grafana-dashboard.json
└── podman-compose.yaml
```

## License

Apache 2.0
