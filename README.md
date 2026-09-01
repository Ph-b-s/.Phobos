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
 Venice Uncensored
 (Dolphin Mistral 24B)
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

Phobos targets **Python 3.11+**. The AI-to-Nmap feature runs from a Kali Linux terminal with Nmap installed and an internet connection for the Venice API.

## AI model

Phobos uses **Dolphin Mistral 24B Venice Edition**, exposed by Venice.ai as **`venice-uncensored` / Venice Uncensored**. The integration uses Venice's OpenAI-compatible Chat Completions interface through Python's standard library; no model is hosted locally by Phobos.

## 1. Clone and install Phobos

```bash
git clone -b flat-structure https://github.com/Ph-b-s/.Phobos.git
cd .Phobos

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Verify the installation:

```bash
phobos --help
nmap --version
```

## 2. Get a Venice API key

Create a Venice API key in your Venice account and export it only in your shell session:

```bash
export VENICE_API_KEY="YOUR_VENICE_API_KEY"
```

Phobos reads the key from `VENICE_API_KEY`. It is not stored in the repository.

The default API endpoint is:

```text
https://api.venice.ai/api/v1/chat/completions
```

The default model identifier is:

```text
venice-uncensored
```

## 3. Test the AI path without executing Nmap

For a safe first run, use `--dry-run`. Phobos still validates the explicit target and scope, asks Venice for the decision, and prints the exact fixed command that would be executed.

```bash
phobos ai \
  --target scanme.nmap.org \
  --scope scanme.nmap.org \
  --dry-run \
  "Run a simple Nmap reconnaissance scan of the target's common TCP ports."
```

`--dry-run` never starts Nmap.

## 4. Run the AI + Nmap action

Use a target you own or are explicitly authorized to assess.

```bash
phobos ai \
  --target scanme.nmap.org \
  --scope scanme.nmap.org \
  "Run a simple Nmap reconnaissance scan of the target's common TCP ports."
```

What happens:

1. Phobos sends the natural-language request to Venice Uncensored.
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

## 5. Run web reconnaissance

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

## 6. Run the test suite

```bash
python -m pytest -q
```

---

# Example output

```text
[PHOBOS AI] Sending request to Venice Uncensored...
  Action: nmap_top_ports
  Reason: The request asks for the supported basic TCP reconnaissance action.

[PHOBOS] Prepared scoped nmap reconnaissance against https://scanme.nmap.org...

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

DNS resolution failures are treated as validation failures instead of being silently allowed through. Private/local destinations require an explicit `--allow-private-targets` opt-in.

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
- [x] Venice Uncensored AI planner
- [x] Safe fixed-action Nmap runner
- [x] AI dry-run mode

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

The AI planner makes a constrained decision.

The execution layer remains deterministic and policy-controlled.

---

## License

The project is currently in early development and does not yet declare a final open-source license.

---

<div align="center">

**PHOBOS — map the attack surface before you attack the model.**

</div>
