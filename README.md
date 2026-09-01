<div align="center">

# PHOBOS

### Web & AI Security Reconnaissance

**Map the system before you attack the model.**

Phobos is an open-source framework for authorized security testing of modern web applications, APIs, AI agents, tools, and the relationships between them.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/Ph-b-s/.Phobos/test.yml?branch=flat-structure&style=flat-square&label=CI)](https://github.com/Ph-b-s/.Phobos/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-TBD-lightgrey?style=flat-square)](#license)
[![Status](https://img.shields.io/badge/status-early%20development-orange?style=flat-square)](#roadmap)
[![Web Security](https://img.shields.io/badge/focus-Web%20Security-blue?style=flat-square)](#what-phobos-is-building)
[![AI Security](https://img.shields.io/badge/focus-AI%20Security-red?style=flat-square)](#what-phobos-is-building)
[![Red Team](https://img.shields.io/badge/security-Red%20Teaming-darkred?style=flat-square)](#security-model)
[![Attack Surface](https://img.shields.io/badge/capability-Attack%20Surface%20Mapping-purple?style=flat-square)](#first-build)
[![Recon](https://img.shields.io/badge/capability-Reconnaissance-0891B2?style=flat-square)](#first-build)
[![Web Crawling](https://img.shields.io/badge/web-Crawling-0F766E?style=flat-square)](#first-build)
[![AI Agents](https://img.shields.io/badge/target-AI%20Agents-7C3AED?style=flat-square)](#what-phobos-is-building)
[![Prompt Injection](https://img.shields.io/badge/next-Prompt%20Injection-B91C1C?style=flat-square)](#roadmap)
[![APIs](https://img.shields.io/badge/surface-APIs-F59E0B?style=flat-square)](#data-model)
[![GitHub Stars](https://img.shields.io/github/stars/Ph-b-s/.Phobos?style=flat-square)](https://github.com/Ph-b-s/.Phobos/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/Ph-b-s/.Phobos/flat-structure?style=flat-square)](https://github.com/Ph-b-s/.Phobos/commits/flat-structure)

</div>

---

## What Phobos is building

AI security is a system problem, not only a prompt problem. A useful security workflow needs to discover applications, APIs, inputs, AI surfaces, agents, tools, and external resources, then preserve the relationships between them.

Phobos is designed around this pipeline:

```text
Discover → Normalize → Connect → Reason → Test → Correlate
```

The current build focuses on the first foundation: **Phobos Core + Target Graph**, with passive AI-surface discovery built into web reconnaissance and an AI planner that selects only predefined Phobos actions.

---

## First build

### Web reconnaissance

```text
Target URL
    |
    v
CLI
    |
    v
Configuration → Scope Validator → Request Manager
                                      |
                                      v
                               Recon Crawler
                             /      |        \
                         Pages   Forms    Inputs / JS
                             \      |        /
                              v     v       v
                         Unified Asset Model
                                  |
                                  +----> AI Surface Detector
                                  |
                                  v
                            Execution Graph
                                  |
                                  v
                         JSON evidence artifacts
```

The crawler discovers pages, links, forms, inputs, JavaScript references, and conservative signals for likely AI endpoints, AI providers, agent behavior, and AI-oriented inputs.

### AI-assisted planning

```text
Natural-language request
          |
          v
 Venice Uncensored
 (Dolphin Mistral 24B)
          |
          v
  Structured decision
   /       |          \
refuse  web_recon  ai_surface_discovery
            \          /
             v        v
          Explicit target + scope
                   |
                   v
            Phobos policy layer
                   |
                   v
           Fixed reconnaissance path
```

The model never chooses the target, never receives shell access, and never supplies arbitrary HTTP or command arguments. It only selects a predefined Phobos capability.

---

## Repository layout

The project intentionally uses a flat source structure:

```text
.Phobos/
├── ai.py
├── ai_surface.py
├── cli.py
├── config.py
├── crawler.py
├── evidence.py
├── graph.py
├── models.py
├── nodes.py
├── nmap_runner.py
├── request_manager.py
├── scope.py
├── test_ai.py
├── test_core.py
├── test_recon.py
├── test_recon_queue.py
├── pyproject.toml
├── ABOUT.md
├── README.md
└── .github/workflows/test.yml
```

---

# Installation

Phobos requires **Python 3.11+**. The AI path requires internet access to Venice.ai.

## 1. Clone the correct branch

```bash
git clone -b flat-structure https://github.com/Ph-b-s/.Phobos.git
cd .Phobos
```

## 2. Create the virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## 3. Verify the local installation

```bash
phobos --version
phobos --help
phobos doctor
```

`phobos doctor` checks the Python environment and Venice configuration without sending an AI request.

---

# Usage

There are currently **three commands**:

```text
phobos scan     Passive web reconnaissance + AI-surface discovery
phobos ai       AI-planned web reconnaissance
phobos doctor   Local environment diagnostics
```

Run `phobos <command> --help` for the authoritative command-line syntax.

## A. Web reconnaissance

```bash
phobos scan https://example.com --scope example.com
```

Increase the crawl budget when required:

```bash
phobos scan https://app.example.com \
  --scope example.com \
  --max-pages 250 \
  --max-discovered-urls 5000 \
  --timeout 15 \
  --output ./results
```

Results include pages, endpoints, forms, inputs, JavaScript references, and likely AI-related surfaces.

## B. AI-assisted reconnaissance

Configure Venice:

```bash
export VENICE_API_KEY="YOUR_VENICE_API_KEY"
```

Defaults:

```text
Endpoint: https://api.venice.ai/api/v1/chat/completions
Model:    venice-uncensored
```

Ask Phobos to choose a predefined web-security action:

```bash
phobos ai \
  --target https://app.example.com \
  --scope example.com \
  "Map the web surface and look for likely AI endpoints and agent entry points."
```

Use dry-run to verify the AI decision without making web requests:

```bash
phobos ai \
  --target https://app.example.com \
  --scope example.com \
  --dry-run \
  "Look for AI-related attack-surface signals."
```

The AI can currently select only:

```text
web_recon
ai_surface_discovery
refuse
```

The target and scope remain under Phobos control.

## Target and scope rules

Targets must be HTTP(S) web URLs for the web-focused AI path. Private/local destinations are blocked by default.

For an authorized lab target on a private network, explicitly opt in:

```bash
phobos scan \
  https://192.168.56.10 \
  --scope 192.168.56.10 \
  --allow-private-targets
```

The AI request is limited to **4,000 characters** and oversized requests are rejected rather than silently truncated.

---

# Output files

For `phobos scan`, the default directory is `.phobos/` unless `--output` is supplied.

```text
.phobos/
├── scan.json
├── assets.json
├── graph.json
└── findings.json
```

`scan.json` contains the scan status and summary. `assets.json` contains normalized assets. `graph.json` contains graph nodes and relationships. `findings.json` is reserved for the later analysis layer.

---

# Security model

Phobos is intended for **authorized security testing only**. Obtain explicit authorization for systems you do not own before scanning them.

The core execution boundary is:

```text
Natural-language request
          |
          v
        AI planner
          |
          | structured decision only
          v
      Phobos policy
       /        \
 target+scope   fixed action
       \        /
        v      v
      Request Manager
            |
            v
        Recon Crawler
```

The web stack uses centralized scope enforcement, explicit redirect validation, bounded discovery, response-size limits, and a single outbound request manager.

DNS resolution failures are treated as validation failures. Private/local destinations require explicit opt-in.

The first AI-security layer is intentionally passive. It identifies likely AI surfaces from already-fetched content; it does not execute prompts, alter application state, or invoke discovered tools.

---

# Data model

Every discovered surface becomes a typed asset. Current types include:

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

AI-related assets currently include conservative signals such as:

```text
chat_completion_endpoint
responses_endpoint
message_endpoint
generation_endpoint
ai_api_endpoint
provider_signal
agent_signal
ai_input
```

---

# Roadmap

### Phase I — Core + Target Graph

- [x] CLI
- [x] Configuration validation
- [x] Central scope enforcement
- [x] Request manager
- [x] Unified asset model
- [x] In-memory execution graph
- [x] Atomic evidence storage
- [x] HTML reconnaissance crawler
- [x] Link, form, input, endpoint, and JavaScript discovery
- [x] Bounded discovery queue
- [x] Passive AI-surface discovery
- [x] Automated tests and CI
- [x] Venice Uncensored AI planner

### Phase II — Deeper Web Reconnaissance

- [ ] JavaScript endpoint extraction
- [ ] robots.txt / sitemap awareness
- [ ] technology fingerprinting
- [ ] authentication-aware crawling
- [ ] richer evidence capture
- [ ] API schema discovery

### Phase III — AI Surface Analysis

- [ ] AI-agent surface detection improvements
- [ ] Chat / completion endpoint classification
- [ ] streaming response detection
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

## License

The project is currently in early development and does not yet declare a final open-source license.

---

<div align="center">

**PHOBOS — map the system before you attack the model.**

</div>
