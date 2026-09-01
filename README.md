<div align="center">

# PHOBOS

### AI Security Reconnaissance & Attack-Surface Mapping

**Map the system before you attack the model.**

Phobos is an open-source framework for authorized security testing of modern web applications, AI agents, APIs, tools, and the relationships between them.

[![Python](https://img.shields.io/badge/python-3.11%2B-111827?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-TBD-111827?style=flat-square)](#license)
[![Status](https://img.shields.io/badge/status-early%20development-111827?style=flat-square)](#roadmap)

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

This first build deliberately establishes that foundation before adding aggressive security testing.

---

# First build

The current implementation establishes the **Phobos Core + Target Graph** foundation.

### Scan flow

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

### Repository architecture

```text
.Phobos/
├── phobos/
│   ├── cli/
│   │   └── main.py              # CLI entry point
│   │
│   ├── core/
│   │   ├── config.py            # Scan configuration
│   │   ├── scope.py             # Central scope enforcement
│   │   ├── request_manager.py   # Single outbound HTTP boundary
│   │   └── models.py            # Unified asset / finding models
│   │
│   ├── recon/
│   │   └── crawler.py           # Bounded HTML reconnaissance
│   │
│   ├── graph/
│   │   ├── graph.py             # In-memory directed graph
│   │   └── nodes.py              # Graph node / edge definitions
│   │
│   └── storage/
│       └── evidence.py          # Scan artifacts and evidence storage
│
├── tests/
├── .github/workflows/
├── pyproject.toml
└── README.md
```

---

# Design principles

## 1. Scope is a security boundary

There is one request path:

```text
Module → RequestManager → ScopeValidator → HTTP
```

Modules should not perform direct network access.

The scope validator uses hostname boundaries rather than naive string matching, so a target such as `evil-example.com` cannot pass a scope intended for `example.com`.

Redirect destinations are validated **before** Phobos follows them.

## 2. Everything discovered becomes an asset

A page is not just a URL string. A form is not just HTML. An input is potentially an attack surface.

Phobos normalizes discoveries into typed assets such as:

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

That same model is intended to carry forward into AI-specific discovery.

## 3. Relationships matter

The graph is the core of the long-term design.

Example:

```text
[web_input: comment]
          │
          ▼
[stored_content]
          │
          ▼
[ai_agent]
          │
          ▼
[tool: ticketing]
```

A future module can then reason about the path rather than treating each component as an independent target.

## 4. Evidence from the beginning

Every scan produces machine-readable artifacts that can later be used for reporting, correlation, replay, and security findings.

The output directory is designed around:

```text
.phobos/
├── scan.json
├── assets.json
├── graph.json
├── findings.json
└── evidence/
```

---

# Quick start

### Install from a local clone

```bash
git clone https://github.com/Ph-b-s/.Phobos.git
cd .Phobos
python -m pip install -e .
```

### Run a scoped scan

```bash
phobos scan https://example.com --scope example.com
```

Multiple domains can be supplied explicitly:

```bash
phobos scan https://app.example.com \
  --scope example.com \
  --scope api.example.net
```

Control crawler depth and output location:

```bash
phobos scan https://example.com \
  --scope example.com \
  --max-pages 250 \
  --timeout 15 \
  --output ./results
```

The default scope is the target hostname when `--scope` is omitted.

---

# Example output

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

The exact counts depend on the target.

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

# Security model

Phobos is intended for **authorized security testing only**.

The project is designed around an explicit scope boundary, bounded crawling, response-size limits, redirect validation, and a single outbound request manager. Those controls are part of the architecture rather than optional conventions.

Do not use Phobos against systems you do not own or do not have explicit permission to assess.

---

# Development

Phobos targets Python 3.11+ and currently uses the Python standard library for the core reconnaissance stack.

Run the test suite with:

```bash
python -m pytest
```

Run the CLI help with:

```bash
phobos --help
```

---

# Project philosophy

Phobos is not being designed as another collection of disconnected vulnerability scanners.

The goal is a security framework that can understand a target as a **system**:

```text
Discover → Normalize → Connect → Reason → Test → Correlate
```

The crawler provides the data.

The graph gives that data meaning.

The security modules come after that foundation.

---

## License

The project is currently in early development and does not yet declare a final open-source license.

---

<div align="center">

**PHOBOS — map the attack surface before you attack the model.**

</div>
