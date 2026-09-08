<div align="center">

# PHOBOS

### Web & AI Security Testing Framework

**Discover the system. Test the trust boundaries. Prove the attack path.**

Phobos is an open-source framework for authorized security testing of modern web applications, APIs, AI assistants, AI agents, tools, and the relationships between them.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-early%20development-orange?style=flat-square)](#status)
[![Web Security](https://img.shields.io/badge/focus-Web%20Security-blue?style=flat-square)](#focus)
[![AI Security](https://img.shields.io/badge/focus-AI%20Security-red?style=flat-square)](#focus)

</div>

---

## Status

Phobos is in early development. The current codebase provides bounded web reconnaissance, passive AI-surface discovery, JavaScript/API route discovery, a constrained AI planning layer, a reusable assessment procedure model, a bounded assessment engine, browser execution support, structured evidence handling, and an optional Nmap reconnaissance module.

The project is being prepared for its first real external security-testing work against authorized PortSwigger Web Security Academy labs.

There are no synthetic demo targets in the main project workflow. The objective is to make Phobos useful against real authorized targets rather than optimize the framework around a toy application.

## Focus

Phobos is primarily a **web + AI security** project.

Nmap is intentionally small:

```text
Web discovery       ─┐
AI discovery         ├──> shared attack-surface graph
Nmap (optional)     ─┘
```

Nmap provides basic host/service context when requested. It does not become a separate scanner architecture, and its output is not treated as a vulnerability finding.

The central security model remains:

```text
attacker-controlled input
        ↓
application component
        ↓
AI / API / browser interaction
        ↓
trust boundary
        ↓
security-relevant behavior
        ↓
validated finding
```

---

# Architecture

The repository stays deliberately flat while the logical boundaries remain explicit:

```text
CLI
 │
 ▼
Configuration + Scope
 │
 ├───────────────┬────────────────┐
 ▼               ▼                ▼
Web Discovery  AI Discovery   Nmap Module
 │               │                │
 └───────────────┴────────────────┘
                 ▼
          Attack-Surface Graph
                 │
                 ▼
        Assessment Procedures
                 │
                 ▼
          Assessment Engine
                 │
                 ▼
        HTTP / Browser Adapter
                 │
                 ▼
       Structured Observations
                 │
                 ▼
        Evidence Correlation
                 │
                 ▼
             Findings
```

The important point is that discovery mechanisms produce information for one shared model. A web endpoint, a discovered JavaScript route, a likely AI surface, or an optional open port can all become context for later assessment.

## Discovery

Web discovery currently covers:

```text
pages
links
forms
inputs
JavaScript references
API routes found in JavaScript
query parameters
likely AI endpoints
provider / agent signals
AI-oriented inputs
```

The crawler is bounded and all HTTP destinations remain subject to centralized scope enforcement.

The optional Nmap module performs bounded TCP discovery and normalizes open ports into simple `port` assets. It is primarily useful as supporting context for the target host.

## Assessment

Assessment procedures are reusable investigations rather than hard-coded payload scripts.

A procedure should define:

```text
prerequisites
required observations
safe probe
expected evidence
positive confirmation
optional impact validation
```

The assessment engine executes only declared steps, limits execution and observations, validates adapter output, and separates state-changing validation from normal reconnaissance.

## Evidence

Phobos should distinguish:

```text
observation
   ↓
suspicion
   ↓
strong signal
   ↓
confirmed behavior
```

A suspicious response or matching string is not automatically a vulnerability. The goal is to retain enough evidence to reconstruct how input moved through the application and what security consequence followed.

---

# First PortSwigger target

The immediate development goal is one narrow, repeatable end-to-end test against an authorized PortSwigger lab.

The intended workflow is:

```text
1. Provide lab URL and scope
2. Run web reconnaissance
3. Optionally enrich with Nmap
4. Build the shared attack-surface graph
5. Identify the relevant vulnerability surface
6. Select one assessment procedure
7. Perform the smallest useful probe
8. Capture structured evidence
9. Confirm the vulnerability
10. Produce a reproducible finding
```

Lab-specific URLs, payload strings, and quirks should remain test fixtures. The procedure itself should represent the vulnerability class.

---

# CLI

### Web reconnaissance

```bash
phobos scan https://example.com --scope example.com
```

### Web reconnaissance with optional Nmap enrichment

```bash
phobos scan https://example.com --scope example.com --nmap
```

### AI-assisted reconnaissance planning

```bash
export VENICE_API_KEY="YOUR_VENICE_API_KEY"

phobos ai \
  --target https://example.com \
  --scope example.com \
  "Map the application and identify likely AI attack surfaces."
```

The AI planner is currently constrained to predefined reconnaissance capabilities. It cannot change the target, execute shell commands, or construct arbitrary requests.

---

# Repository layout

```text
.Phobos/
├── ai.py
├── ai_surface.py
├── ai_testing.py
├── assessment_engine.py
├── browser_adapter.py
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
├── web_surface.py
├── tests...
├── pyproject.toml
├── ABOUT.md
├── RECON_ARCHITECTURE.md
└── README.md
```

The flat physical layout is intentional. Strong interfaces matter more than folders at this stage.

---

# Installation

Phobos requires Python 3.11+.

```bash
git clone -b flat-structure https://github.com/Ph-b-s/.Phobos.git
cd .Phobos

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For browser execution:

```bash
python -m pip install -e ".[browser]"
playwright install chromium
```

Verify the installation:

```bash
phobos --version
phobos --help
python -m pytest -q
```

Nmap is an external system dependency and should be installed separately on systems where the optional module is used.

---

# Roadmap

## Foundation

- [x] CLI
- [x] configuration validation
- [x] centralized scope enforcement
- [x] bounded HTTP request manager
- [x] bounded web crawler
- [x] forms / inputs / endpoints / JavaScript discovery
- [x] passive AI-surface discovery
- [x] JavaScript/API route discovery
- [x] shared attack-surface graph
- [x] evidence storage
- [x] optional Nmap reconnaissance module
- [x] automated tests / CI configuration

## First real assessments

- [ ] PortSwigger target integration workflow
- [ ] reusable first vulnerability procedure
- [ ] assessment CLI command
- [ ] authenticated session handling for real targets
- [ ] richer request/response observations
- [ ] reproducible finding output

## AI security

- [ ] direct prompt injection
- [ ] indirect prompt injection variants
- [ ] sensitive information disclosure
- [ ] system-prompt exposure
- [ ] excessive agency
- [ ] tool abuse
- [ ] insecure output handling
- [ ] retrieval/context poisoning
- [ ] cross-user context isolation
- [ ] multi-step attack-chain correlation

## Later

- [ ] authentication-aware crawling
- [ ] agent → tool → resource graphing
- [ ] trust-boundary detection
- [ ] cross-component attack-path construction
- [ ] PortSwigger regression suite
- [ ] reporting / SARIF / CI integration

---

# Safety

Phobos is designed for authorized security research, learning, and defensive engineering. Active testing should only be performed against targets for which testing is permitted.
