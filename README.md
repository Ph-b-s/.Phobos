<div align="center">

# PHOBOS

### AI Security Reconnaissance & Attack-Surface Mapping

**Map the system before you attack the model.**

Phobos is an open-source framework for authorized security testing of modern web applications, AI agents, APIs, tools, and the relationships between them.

[![Python](https://img.shields.io/badge/python-3.11%2B-111827?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-TBD-111827?style=flat-square)](#license)
[![Status](https://img.shields.io/badge/status-first-build-111827?style=flat-square)](#first-build)

</div>

---

## Why Phobos exists

AI security is rarely a single prompt sent to a single model.

A real target can look more like:

```text
User Input
    │
    ▼
 Web Application ───────► API
    │                       │
    ▼                       ▼
Stored Content          AI Agent
                            │
                  ┌─────────┼─────────┐
                  ▼         ▼         ▼
                Tool      Data      Resource
                  │
                  ▼
              External System
```

The important security questions are therefore not only:

> “Can I jailbreak the model?”

They are also:

- Which inputs can influence an agent?
- Where can attacker-controlled content be stored?
- Which tools can the agent call?
- Which APIs, resources, or internal systems are reachable?
- Can an attack travel across several components?

**Phobos is being built around that attack surface.**

---

## Core idea

Phobos separates **discovery** from **reasoning**.

The reconnaissance layer discovers the system. The target graph preserves relationships between what was found. Future security modules can then reason over that graph instead of operating on isolated URLs.

```text
                    PHOBOS
                       │
              ┌────────┴────────┐
              │                 │
           Discover           Model
              │                 │
              ▼                 ▼
       Pages / Forms /      Assets / Nodes /
       Inputs / APIs /       Relationships
       JavaScript
              │                 │
              └────────┬────────┘
                       ▼
                 Target Graph
                       │
                       ▼
           Future AI Security Modules
```

The first runnable build now also includes a deliberately constrained AI-to-Nmap execution path. The AI chooses **whether** Phobos should perform its one supported Nmap action; Phobos itself constructs the command, validates scope, and executes it without a shell.

---

# First build

The first build establishes the **Phobos Core + Target Graph** foundation and a minimal AI execution loop.

### Web reconnaissance flow

```text
Target URL
    │
    ▼
CLI
    │
    ▼
Configuration
    │
    ▼
Scope Validator ◄──── every outbound request
    │
    ▼
Request Manager
    │
    ▼
Recon Crawler
    │
    ├── Pages
    ├── Links / Endpoints
    ├── Forms
    ├── Inputs
    └── JavaScript references
    │
    ▼
Unified Asset Model
    │
    ▼
Execution Graph
    │
    ▼
Evidence / JSON artifacts
```

### AI-to-Nmap flow

```text
Natural-language request
          │
          ▼
       AI planner
          │
          ▼
  structured decision
          │
          ├──────────────► refuse
          │
          ▼
   nmap_top_ports
          │
          ▼
 Target + explicit scope
          │
          ▼
   Scope Validator
          │
          ▼
    Nmap Runner
          │
          ▼
      nmap -sT --top-ports 100 --open --reason -- TARGET
```

The AI has no shell access and cannot supply arbitrary Nmap arguments. This keeps the first agent implementation intentionally narrow and auditable.

### Repository architecture

```text
.Phobos/
├── cli.py                    # CLI entry point
├── config.py                 # Scan configuration
├── scope.py                  # Central scope enforcement
├── request_manager.py        # Single outbound HTTP boundary
├── models.py                 # Unified asset / finding models
├── crawler.py                # Bounded HTML reconnaissance
├── graph.py                  # In-memory directed graph
├── nodes.py                  # Graph node / edge definitions
├── evidence.py               # Scan artifacts / evidence storage
├── ai.py                     # AI planner (no shell access)
├── nmap_runner.py            # Safe Nmap execution boundary
├── tests...
├── .github/workflows/
├── pyproject.toml
└── README.md
```

---

# How to run

Phobos targets **Python 3.11+**. The AI-to-Nmap feature is designed to run in a Kali Linux terminal with `nmap` installed.

## 1. Clone and install

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

## 2. Configure the AI provider

The first build uses the OpenAI Responses API through Python's standard library. No OpenAI SDK is required.

Set your API key in the terminal session:

```bash
export OPENAI_API_KEY="YOUR_API_KEY"
```

The default model is `gpt-5.6-luna`. You can override it without changing code:

```bash
export PHOBOS_AI_MODEL="gpt-5.6-luna"
```

For an OpenAI-compatible proxy/provider, the endpoint can also be overridden:

```bash
export PHOBOS_AI_URL="https://your-provider.example/v1/responses"
```

Phobos never stores the API key in the repository.

## 3. Run the AI + Nmap example

Use a target you own or are explicitly authorized to assess. The target is supplied separately from the AI request so the model cannot choose a different host.

Example:

```bash
phobos ai \
  --target scanme.nmap.org \
  --scope scanme.nmap.org \
  "Run a simple Nmap reconnaissance scan of the target's common TCP ports."
```

Phobos will:

1. send the request to the AI planner;
2. accept only the predefined `nmap_top_ports` action or `refuse`;
3. validate the target against the explicit scope;
4. execute Nmap with `shell=False` and a fixed argument set;
5. print the normal Nmap result directly in the terminal.

The AI cannot inject shell syntax, arbitrary Nmap switches, scripts, output paths, or a different target.

For private/local targets, opt in explicitly:

```bash
phobos ai \
  --target 192.168.56.10 \
  --scope 192.168.56.10 \
  --allow-private-targets \
  "Run a simple Nmap reconnaissance scan."
```

## 4. Run the web reconnaissance build

```bash
phobos scan https://example.com --scope example.com
```

Multiple domains can be supplied explicitly:

```bash
phobos scan https://app.example.com \
  --scope example.com \
  --scope api.example.net
```

Control crawler size, timeout, and output location:

```bash
phobos scan https://example.com \
  --scope example.com \
  --max-pages 250 \
  --timeout 15 \
  --output ./results
```

The default scope is the target hostname when `--scope` is omitted.

## 5. Run the tests

```bash
python -m pytest -q
```

You can also run the CLI without arguments to see the command list:

```bash
phobos --help
```

---

# Example output

AI + Nmap:

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

Web reconnaissance:

```text
[PHOBOS] Starting reconnaissance...
  Target: https://example.com
  Scope:  example.com

✓ 34 pages discovered
✓ 12 forms discovered
✓ 47 input parameters discovered
✓ 0 API endpoints discovered
✓ 23 JavaScript files analyzed

Building execution graph...

✓ 124 nodes created
✓ 178 relationships created

Scan complete.
Results saved to .phobos
```

The exact counts and Nmap results depend on the target.

---

# Data model

A discovered asset is normalized into a common structure:

```json
{
  "id": "input_001",
  "type": "input",
  "name": "comment",
  "url": "https://target.example/comments",
  "confidence": 1.0,
  "metadata": {
    "source_form": "form_001",
    "source_page": "https://target.example/comments"
  }
}
```

Forms and endpoints preserve additional information such as method, status code, input names, source relationships, and discovery context.

---

# Graph model

The graph is intentionally in-memory in the first build. A graph database is not required to understand the architecture and would add unnecessary coupling this early.

Nodes and relationships can be serialized deterministically:

```json
{
  "nodes": [
    {
      "id": "input_001",
      "type": "input",
      "label": "comment"
    },
    {
      "id": "agent_001",
      "type": "ai_agent",
      "label": "Support Agent"
    }
  ],
  "edges": [
    {
      "source": "input_001",
      "target": "agent_001",
      "relationship": "influences"
    }
  ]
}
```

This makes it possible to grow from simple web discovery toward richer attack-path analysis without redesigning the data layer.

---

# Security model

Phobos is intended for **authorized security testing only**.

The first build deliberately separates planning from execution:

```text
AI
 │
 │ structured decision only
 ▼
Phobos policy
 │
 ├── explicit target
 ├── scope validation
 ├── fixed Nmap action
 └── shell disabled
      │
      ▼
    Nmap
```

The web reconnaissance stack also uses an explicit scope boundary, bounded crawling, response-size limits, redirect validation, and a single outbound request manager.

Private/local destinations are rejected by default and require an explicit `--allow-private-targets` opt-in.

Do not use Phobos against systems you do not own or do not have explicit permission to assess.

---

# Roadmap

Phobos is intentionally being built in layers.

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
- [x] Minimal AI planner
- [x] Safe fixed-action Nmap runner

### Phase II — Deeper Reconnaissance

- [ ] API endpoint discovery
- [ ] Query/body parameter normalization
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

# Project philosophy

Phobos is not being designed as another collection of disconnected vulnerability scanners.

The goal is a security framework that can understand a target as a **system**:

```text
Discover → Normalize → Connect → Reason → Test → Correlate
```

The crawler provides the data.

The graph gives that data meaning.

The AI planner makes a constrained decision.

The execution layer remains deterministic and policy-controlled.

The security modules come after that foundation.

---

## License

The project is currently in early development and does not yet declare a final open-source license.

---

<div align="center">

**PHOBOS — map the attack surface before you attack the model.**

</div>
