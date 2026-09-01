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

## What Phobos is building

AI security is a system problem, not only a prompt problem. A useful security workflow needs to discover applications, APIs, inputs, agents, tools, and external resources, then preserve the relationships between them.

Phobos is designed around this pipeline:

```text
Discover → Normalize → Connect → Reason → Test → Correlate
```

The current build focuses on the first foundation: **Phobos Core + Target Graph**, plus a tightly constrained AI-to-Nmap path.

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

### AI-to-Nmap

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
       nmap -sT --top-ports 100 --open --reason
```

The model never receives shell access, never chooses the target, and never supplies Nmap arguments. Phobos validates the explicit target and constructs the command itself.

---

## Repository layout

The project intentionally uses a flat source structure:

```text
.Phobos/
├── ai.py
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
├── pyproject.toml
├── ABOUT.md
├── README.md
└── .github/workflows/test.yml
```

Do not move the Python modules into a nested `phobos/` package unless the project architecture is deliberately changed later.

---

# Installation

Phobos requires **Python 3.11+**. The AI path requires internet access to Venice.ai. Real Nmap execution requires Nmap to be installed and available in `PATH`.

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
nmap --version
```

`phobos doctor` checks the Python version, Nmap availability, and Venice configuration without sending an AI request.

---

# Exact usage

There are currently **three commands**:

```text
phobos scan     Web reconnaissance
phobos ai       AI-planned fixed Nmap reconnaissance
phobos doctor   Local environment diagnostics
```

Run `phobos <command> --help` for the authoritative command-line syntax.

## A. AI + Nmap: recommended first run

### Step 1 — configure Venice

Create a Venice API key and export it in the shell running Phobos:

```bash
export VENICE_API_KEY="YOUR_VENICE_API_KEY"
```

Phobos does not store the key in the repository.

Defaults:

```text
Endpoint: https://api.venice.ai/api/v1/chat/completions
Model:    venice-uncensored
```

The model is Venice's Dolphin Mistral 24B Venice Edition exposed through the Venice API. No local 24B model is required.

### Step 2 — run diagnostics

```bash
phobos doctor
```

A ready environment should show:

```text
✓ Python >= 3.11
✓ Nmap in PATH
✓ VENICE_API_KEY set
✓ Venice endpoint uses HTTPS
✓ AI model configured
```

### Step 3 — use dry-run before a real scan

```bash
phobos ai \
  --target scanme.nmap.org \
  --scope scanme.nmap.org \
  --dry-run \
  "Run a simple TCP reconnaissance scan of the target's common ports."
```

Dry-run performs the AI decision and scope validation but **never starts Nmap**. It prints the exact command Phobos would execute.

### Step 4 — execute the fixed action

```bash
phobos ai \
  --target scanme.nmap.org \
  --scope scanme.nmap.org \
  "Run a simple TCP reconnaissance scan of the target's common ports."
```

The execution path is:

```text
1. Validate the explicit target.
2. Send the natural-language request to Venice.
3. Accept only `nmap_top_ports` or `refuse`.
4. Validate the explicit target against the explicit scope.
5. Construct the fixed Nmap command inside Phobos.
6. Execute with `shell=False` and a bounded timeout.
7. Print Nmap stdout/stderr and its exit status.
```

The fixed command is:

```text
nmap -sT --top-ports 100 --open --reason -- TARGET_HOST
```

The AI cannot add switches, change ports, choose another host, execute a shell command, or start another program.

### Target rules

For `phobos ai`, `--target` must be a hostname or IP address. Do not pass a port, path, query string, or fragment.

Valid:

```bash
--target example.com
--target https://example.com/
--target 203.0.113.10
```

Invalid:

```bash
--target example.com:8080
--target https://example.com/admin
```

### Scope rules

Always prefer an explicit `--scope`:

```bash
phobos ai --target app.example.com --scope example.com --dry-run "Run basic TCP reconnaissance."
```

Subdomains are accepted under the scoped domain, while look-alike domains are rejected. Private/local destinations are blocked by default.

For an authorized lab target on a private network, explicitly opt in:

```bash
phobos ai \
  --target 192.168.56.10 \
  --scope 192.168.56.10 \
  --allow-private-targets \
  --dry-run \
  "Run basic TCP reconnaissance."
```

### Important behavior

The AI request is limited to **4,000 characters**. Phobos rejects longer requests instead of silently truncating them.

The AI response must be a JSON object with exactly these keys:

```json
{
  "action": "nmap_top_ports",
  "reason": "brief explanation"
}
```

Anything else is rejected.

---

## B. Web reconnaissance

Run a scoped crawl against an HTTP(S) application:

```bash
phobos scan https://example.com --scope example.com
```

Increase the crawl budget when required:

```bash
phobos scan https://app.example.com \
  --scope example.com \
  --max-pages 250 \
  --timeout 15 \
  --output ./results
```

Add more than one explicit scope when the application legitimately spans multiple domains:

```bash
phobos scan https://app.example.com \
  --scope example.com \
  --scope api.example.net
```

The crawler currently focuses on pages, links, forms, inputs, endpoints, and JavaScript references. Results are written as JSON evidence.

---

## C. Diagnostics

```bash
phobos doctor
```

For scripts that only need an exit code:

```bash
phobos doctor --quiet
```

Exit code `0` means the local environment is ready. A non-zero code means at least one required check failed.

---

# Output files

For `phobos scan`, the default directory is `.phobos/` unless `--output` is supplied.

Typical artifacts:

```text
.phobos/
├── scan.json
├── assets.json
├── graph.json
└── findings.json
```

`scan.json` contains the scan status and summary. `assets.json` contains normalized assets. `graph.json` contains graph nodes and relationships. `findings.json` is reserved for the later analysis layer and is currently empty in the first build.

---

# Security model

Phobos is intended for **authorized security testing only**. Obtain explicit authorization for systems you do not own before scanning them.

The first build keeps the AI and execution layers separate:

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

The web reconnaissance stack uses centralized scope enforcement, redirect validation, bounded crawling, response-size limits, and one outbound request manager.

DNS resolution failures are treated as validation failures. Private/local destinations require explicit opt-in.

### Public test target

Nmap explicitly documents `scanme.nmap.org` as a target users may scan for testing purposes, with restrictions including Nmap-only testing and a bandwidth-conscious limit of about a dozen scans per day.

Use that host only for the documented Nmap testing purpose; do not treat that permission as permission to exploit or otherwise attack the host.

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

Example:

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

# Roadmap

### Phase I — Core + Target Graph

- [x] CLI
- [x] Configuration
- [x] Central scope enforcement
- [x] Request manager
- [x] Unified asset model
- [x] In-memory execution graph
- [x] Evidence storage
- [x] HTML reconnaissance crawler
- [x] Link, form, input, endpoint, and JavaScript discovery
- [x] Automated tests and CI
- [x] Venice Uncensored AI planner
- [x] Fixed-action Nmap runner
- [x] AI dry-run mode
- [x] Local environment diagnostics

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

## License

The project is currently in early development and does not yet declare a final open-source license.

---

<div align="center">

**PHOBOS — map the attack surface before you attack the model.**

</div>
