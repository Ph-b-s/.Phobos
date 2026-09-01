<div align="center">

# PHOBOS

### AI Security Reconnaissance & Attack-Surface Mapping

**Map the system before you attack the model.**

Phobos is an open-source framework for authorized security testing of modern web applications, AI agents, APIs, tools, and the relationships between them.

[![Python](https://img.shields.io/badge/python-3.11%2B-111827?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-TBD-111827?style=flat-square)](#license)
[![Status](https://img.shields.io/badge/status-first%20build-111827?style=flat-square)](#first-build)

</div>

---

## Why Phobos exists

AI security is rarely a single prompt sent to a single model. A real target is a connected system of web applications, APIs, stored content, AI agents, tools, and external resources.

Phobos is being built to discover that system, normalize it into assets, connect those assets in a graph, and eventually reason about attack paths across components.

---

## First build

The first build establishes the **Phobos Core + Target Graph** foundation and a deliberately constrained AI-to-Nmap execution path.

### Web reconnaissance flow

```text
Target URL
    |
    v
CLI -> Configuration -> Scope Validator -> Request Manager
                                      |
                                      v
                               Recon Crawler
                             /      |       \
                         Pages   Forms   Inputs / JS
                             \      |       /
                              v     v      v
                         Unified Asset Model
                                  |
                                  v
                            Execution Graph
                                  |
                                  v
                         JSON evidence artifacts
```

### AI-to-Nmap flow

```text
Natural-language request
          |
          v
  Dolphin Mistral 24B
  Venice Edition (local)
          |
          v
  Structured decision
      /          \
  refuse      nmap_top_ports
                  |
                  v
        Explicit target + scope
                  |
                  v
          Scope Validator
                  |
                  v
           Fixed Nmap runner
                  |
                  v
       nmap -sT --top-ports 100
```

The model never receives shell access and never supplies the Nmap command or arbitrary arguments. Phobos performs the policy decision and constructs the executable command itself.

### Repository architecture

```text
.Phobos/
├── cli.py
├── config.py
├── scope.py
├── request_manager.py
├── models.py
├── crawler.py
├── graph.py
├── nodes.py
├── evidence.py
├── ai.py
├── nmap_runner.py
├── test_core.py
├── test_recon.py
├── test_ai.py
├── .github/workflows/test.yml
├── pyproject.toml
└── README.md
```

---

# How to run

Phobos targets **Python 3.11+**. The AI-to-Nmap feature is designed to run from a Kali Linux terminal with Nmap installed and a local OpenAI-compatible inference server running the requested model.

The selected model is:

**`dphn/Dolphin-Mistral-24B-Venice-Edition`**

The model card recommends vLLM for production-style inference and documents an OpenAI-compatible `/v1/chat/completions` endpoint. The base model is 24B parameters in BF16; the model documentation notes that the full model needs more than 60 GB of GPU memory when run on GPU. citeturn142148view0

## 1. Clone and install Phobos

```bash
git clone -b flat-structure https://github.com/Ph-b-s/.Phobos.git
cd .Phobos

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Verify the CLI and Nmap:

```bash
phobos --help
nmap --version
```

## 2. Install and start Dolphin Mistral locally

Install vLLM:

```bash
python -m pip install --upgrade vllm
```

Start the model server:

```bash
vllm serve "dphn/Dolphin-Mistral-24B-Venice-Edition" \
  --runner generate \
  --port 8000 \
  --tool-call-parser mistral \
  --enable-auto-tool-choice \
  --max-model-len 131072 \
  --limit-mm-per-prompt '{"image": 10}'
```

These launch parameters follow the model author's documented vLLM setup. citeturn142148view0

Leave that terminal running. Phobos expects the local OpenAI-compatible endpoint at:

```text
http://127.0.0.1:8000/v1/chat/completions
```

No OpenAI API key is required for the default local setup.

## 3. Run the AI + Nmap action

Use a target you own or are explicitly authorized to assess.

```bash
phobos ai \
  --target scanme.nmap.org \
  --scope scanme.nmap.org \
  "Run a simple Nmap reconnaissance scan of the target's common TCP ports."
```

What happens:

1. Phobos sends the natural-language request to the local Dolphin model.
2. The model may return only `nmap_top_ports` or `refuse`.
3. Phobos validates the explicit target against the explicit scope.
4. Phobos constructs the Nmap command itself.
5. Nmap executes with `shell=False`, a fixed argument set, and a timeout.
6. The Nmap result is printed in the terminal.

The model cannot choose a different host, add arbitrary Nmap switches, inject shell syntax, or execute another program.

### Private/local targets

Private destinations are blocked by default. For an explicitly authorized local lab target, opt in:

```bash
phobos ai \
  --target 192.168.56.10 \
  --scope 192.168.56.10 \
  --allow-private-targets \
  "Run a simple Nmap reconnaissance scan."
```

## 4. Run web reconnaissance

```bash
phobos scan https://example.com --scope example.com
```

Useful options:

```bash
phobos scan https://example.com \
  --scope example.com \
  --max-pages 250 \
  --timeout 15 \
  --output ./results
```

Multiple scopes can be supplied explicitly:

```bash
phobos scan https://app.example.com \
  --scope example.com \
  --scope api.example.net
```

## 5. Run the test suite

```bash
python -m pytest -q
```

---

# Example output

```text
[PHOBOS AI] Sending request to AI planner...
  Action: nmap_top_ports
  Reason: The request asks for the supported basic TCP reconnaissance action.

[PHOBOS] Executing scoped nmap reconnaissance against https://scanme.nmap.org...

$ /usr/bin/nmap -sT --top-ports 100 --open --reason -- scanme.nmap.org
Starting Nmap ...
...
✓ nmap completed successfully
```

The exact output depends on the target and local Nmap installation.

---

# Security model

Phobos is intended for **authorized security testing only**.

The first build deliberately separates AI planning from system execution:

```text
AI
 |
 | structured decision only
 v
Phobos policy
 |
 +-- explicit target
 +-- explicit scope
 +-- fixed Nmap action
 +-- shell disabled
 |
 v
Nmap
```

The web reconnaissance stack also uses centralized scope enforcement, bounded crawling, response-size limits, redirect validation, and a single outbound request manager.

Do not use Phobos against systems you do not own or do not have explicit permission to assess.

---

# Data model

Every discovered surface becomes a typed asset. Examples include:

```text
website
page
endpoint
form
input
api
javascript
ai_agent
tool
resource
database
```

A simplified asset looks like:

```json
{
  "id": "input_001",
  "type": "input",
  "name": "comment",
  "url": "https://target.example/comments",
  "confidence": 1.0
}
```

---

# Graph model

The first build uses an in-memory directed graph:

```text
[web_input: comment]
          |
          v
[stored_content]
          |
          v
[ai_agent]
          |
          v
[tool: ticketing]
```

The graph can be serialized to JSON so later security modules can operate on relationships instead of isolated URLs.

---

# Roadmap

### Phase I — Core + Target Graph

- [x] CLI
- [x] Configuration
- [x] Central scope enforcement
- [x] Request manager
- [x] Unified asset model
- [x] In-memory execution graph
- [x] Evidence storage
- [x] Initial HTML reconnaissance crawler
- [x] Link, form, input, and JavaScript discovery
- [x] Automated tests and CI foundation
- [x] Local Dolphin Mistral AI planner
- [x] Safe fixed-action Nmap runner

### Phase II — Deeper Reconnaissance

- [ ] API endpoint discovery
- [ ] JavaScript endpoint extraction
- [ ] robots.txt / sitemap awareness
- [ ] Content and technology fingerprinting
- [ ] Authentication-aware crawling
- [ ] richer evidence capture

### Phase III — AI Surface Discovery

- [ ] AI-agent surface detection
- [ ] Chat / completion endpoint detection
- [ ] Streaming response detection
- [ ] tool-use detection
- [ ] model/provider fingerprinting
- [ ] agent → tool → resource relationships

### Phase IV — AI Security Testing

- [ ] Prompt-injection test engine
- [ ] Indirect prompt-injection chains
- [ ] Sensitive-data exposure testing
- [ ] Tool-abuse scenarios
- [ ] Guardrail evaluation
- [ ] Cross-component exploit chaining

### Phase V — Analysis & Reporting

- [ ] Finding correlation
- [ ] Evidence-backed findings
- [ ] attack-path visualization
- [ ] reproducible scan sessions
- [ ] structured reports
- [ ] CI / security-pipeline integration

---

## Project philosophy

```text
Discover → Normalize → Connect → Reason → Test → Correlate
```

The crawler provides the data.

The graph gives that data meaning.

The local AI planner makes a constrained decision.

The execution layer remains deterministic and policy-controlled.

---

## License

The project is currently in early development and does not yet declare a final open-source license.

---

<div align="center">

**PHOBOS — map the attack surface before you attack the model.**

</div>
