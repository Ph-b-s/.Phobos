<div align="center">

# PHOBOS

### Web & AI Security Testing Framework

**Discover the system. Test the trust boundaries. Prove the attack path.**

Phobos is an open-source framework for authorized security testing of modern web applications, APIs, AI assistants, AI agents, tools, and the relationships between them.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-early%20development-orange?style=flat-square)](#status)
[![Web Security](https://img.shields.io/badge/focus-Web%20Security-blue?style=flat-square)](#security-assessment-model)
[![AI Security](https://img.shields.io/badge/focus-AI%20Security-red?style=flat-square)](#security-assessment-model)
[![AI Red Teaming](https://img.shields.io/badge/capability-AI%20Red%20Teaming-7C3AED?style=flat-square)](#roadmap)
[![Prompt Injection](https://img.shields.io/badge/test-Prompt%20Injection-B91C1C?style=flat-square)](#current-assessment)
[![Attack Surface](https://img.shields.io/badge/capability-Attack%20Surface%20Mapping-purple?style=flat-square)](#discovery)

</div>

---

## Status

Phobos is in **early development**. The current codebase provides:

- bounded web reconnaissance
- passive AI-surface discovery
- a constrained AI planning layer
- a reusable vulnerability-assessment procedure model
- a bounded assessment engine
- a Playwright browser/session adapter
- evidence-driven indirect prompt-injection assessment
- a local end-to-end vulnerable target for regression testing

The project is deliberately honest about the boundary between **reconnaissance**, **active assessment**, and **confirmed findings**.

The goal is not to build a payload dictionary or a generic chatbot scanner. The goal is to build a system that can **discover an application's AI attack surface, execute a structured security procedure, correlate observations across multiple requests and components, and report a vulnerability only when the evidence supports it**.

---

# Mission

Modern AI security failures rarely live inside one prompt. They appear at trust boundaries:

```text
Web input
   ↓
Stored application data
   ↓
LLM context
   ↓
Model decision
   ↓
Tool / API
   ↓
Authenticated application state
   ↓
External or internal resource
```

Phobos is designed to test those relationships rather than treating the model as an isolated endpoint.

The core pipeline is:

```text
Discover → Normalize → Connect → Probe → Validate → Correlate → Report
```

A scanner result is therefore not just:

```text
"prompt injection string detected"
```

It should become:

```text
attacker-controlled source
        ↓
consumed by LLM
        ↓
changes model behavior
        ↓
causes security-relevant action
        ↓
impact reproduced
```

That distinction is central to Phobos.

---

# Security assessment model

Phobos separates **mechanism**, **procedure**, **orchestration**, and **finding logic**.

### Mechanism

Browser and HTTP adapters perform navigation, requests, authentication, form interaction, and observation capture. Direct HTTP traffic passes through the central request manager.

### Procedure

A vulnerability-specific workflow describes what must be discovered and tested. Procedures are reusable and are not tied to a single lab URL, product name, or fixed payload.

### Orchestration

The bounded assessment engine dispatches only declared procedure steps, enforces execution and observation limits, rejects malformed adapter output, records step failures, and blocks state-changing validation unless it is explicitly enabled.

### Finding logic

The analyzer correlates observations and determines whether evidence is merely suspicious, strong, or sufficient for confirmation.

```text
                ┌─────────────────────┐
                │  Target + Scope     │
                └─────────┬───────────┘
                          ↓
                ┌─────────────────────┐
                │ Discovery / Mapping │
                └─────────┬───────────┘
                          ↓
                ┌─────────────────────┐
                │ Attack Surface Graph│
                └─────────┬───────────┘
                          ↓
                ┌─────────────────────┐
                │ Assessment Procedure│
                └─────────┬───────────┘
                          ↓
                ┌─────────────────────┐
                │ Assessment Engine   │
                └─────────┬───────────┘
                          ↓
                ┌─────────────────────┐
                │ Browser / HTTP      │
                │ Execution Adapter   │
                └─────────┬───────────┘
                          ↓
                ┌─────────────────────┐
                │ Structured          │
                │ Observations        │
                └─────────┬───────────┘
                          ↓
                ┌─────────────────────┐
                │ Evidence Correlation│
                └─────────┬───────────┘
                          ↓
                   Finding + Proof
```

The AI planner is constrained to predefined Phobos capabilities. It does not control the target, scope, shell, or arbitrary request construction.

---

# Discovery

The reconnaissance engine discovers:

```text
pages
links / endpoints
forms
input parameters
JavaScript references
likely AI endpoints
provider signals
agent/tool signals
AI-oriented inputs
```

AI-surface detection is intentionally conservative. A signal is an indication that deeper testing may be relevant; it is **not a vulnerability finding**.

The crawler preserves assets and relationships in an execution graph and stores bounded JSON evidence.

---

# Current assessment

## Indirect prompt injection

The first active assessment procedure models the investigation required for an indirect prompt-injection vulnerability:

```text
1. Discover the LLM interface
2. Map model-controlled APIs / tools
3. Determine security-relevant arguments
4. Establish the authentication boundary
5. Find attacker-controlled indirect content
6. Capture a clean baseline
7. Seed a unique non-destructive canary
8. Trigger the normal LLM workflow
9. Correlate the exact canary with induced behavior
10. Validate controlled impact when explicitly authorized
```

A successful procedure must establish the relationship between **stored attacker-controlled data** and **later model behavior**.

### Evidence states

Phobos distinguishes:

```text
NOT CONFIRMED
    ↓
SUSPECTED
    ↓
STRONG SIGNAL
    ↓
CONFIRMED
```

A seeded canary is not enough. A response containing a vaguely similar phrase is not enough. The current analyzer requires:

```text
same unique canary
        +
attacker-controlled indirect source
        +
LLM/chat surface
        +
clean baseline comparison
        ↓
confirmed influence
```

A correlated state-changing action can strengthen a proven injection path and provide impact evidence. The assessment module enforces canary format validation and exact seed/observation correlation.

### Execution safety

The assessment engine adds hard execution boundaries:

```text
procedure limit
      +
observation limit
      +
validated adapter output
      +
explicit state-change opt-in
      ↓
bounded assessment run
```

Destructive validation is therefore separate from ordinary reconnaissance.

---

# Local end-to-end demo

Phobos includes a deliberately vulnerable local target that models the indirect-prompt-injection trust boundary. It binds only to `127.0.0.1`, has no external dependencies, and exists to exercise the real browser adapter and assessment engine.

Install browser support:

```bash
python -m pip install -e ".[browser]"
playwright install chromium
```

Run the assessment without impact validation:

```bash
python demo_indirect_injection.py
```

Run the complete controlled demo, including the simulated account state change:

```bash
python demo_indirect_injection.py --impact
```

Expected output is a structured assessment result containing the target, unique canary, finding type, status, confidence, and correlated evidence. The demo uses the same assessment procedure and browser/session abstraction that the production path is intended to use.

The demo server resets its users, reviews, and sessions for every new run so repeated executions remain deterministic.

---

# PortSwigger benchmark philosophy

PortSwigger's Web Security Academy labs are used as **behavioral benchmarks**, not hard-coded solutions.

For each relevant lab we want to extract:

```text
Discovery procedure
Attack-surface assumptions
Trust boundary
Required observations
Minimal safe probe
Positive confirmation condition
Impact condition
Evidence required for reporting
```

The resulting Phobos procedure must work on the **class of vulnerability**, not only on the exact strings, product names, URLs, or lab ordering from one exercise.

The long-term benchmark standard is:

```text
Given only an authorized target,
Phobos should discover the relevant attack surface,
select an applicable procedure,
execute it through a controlled adapter,
reproduce the security behavior,
and explain why the finding is confirmed.
```

The selected PortSwigger labs will become regression benchmarks for the AI-security engine.

---

# Why Phobos is different

Traditional web scanners are strongest when the vulnerability has a recognizable request/response pattern.

AI systems introduce relationships that are harder to model:

```text
content → context
context → model behavior
model behavior → tool selection
tool selection → authenticated action
action → downstream impact
```

Phobos treats those relationships as first-class security evidence.

The target is not merely:

```text
"Can the model be tricked?"
```

It is:

```text
"Can untrusted input cross a trust boundary and cause
an unauthorized or security-relevant model-mediated action?"
```

---

# Architecture

The source layout is intentionally flat while the engine is being established:

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
├── demo_target.py
├── demo_indirect_injection.py
├── evidence.py
├── graph.py
├── models.py
├── nodes.py
├── request_manager.py
├── scope.py
├── tests...
├── pyproject.toml
├── ABOUT.md
└── README.md
```

The core layers are:

```text
CLI
 ↓
Configuration / Scope
 ↓
Request Manager
 ↓
Reconnaissance
 ↓
Asset + Relationship Graph
 ↓
Assessment Procedure
 ↓
Assessment Engine
 ↓
Execution Adapter
 ↓
Observation Stream
 ↓
Evidence Correlation
 ↓
Findings / Reports
```

The request manager remains the single outbound HTTP boundary and enforces scope, redirect validation, request limits, and response limits. Browser requests are independently scope-checked and bounded as well.

---

# Installation

Phobos requires **Python 3.11+**.

```bash
git clone -b flat-structure https://github.com/Ph-b-s/.Phobos.git
cd .Phobos

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Verify the installation:

```bash
phobos --version
phobos --help
phobos doctor
python -m pytest -q
```

For browser execution:

```bash
python -m pip install -e ".[browser]"
playwright install chromium
```

---

# Current CLI

The current CLI exposes the foundation layer:

```text
phobos scan
phobos ai
phobos doctor
```

### Passive reconnaissance

```bash
phobos scan https://example.com --scope example.com
```

### AI-assisted planning

```bash
export VENICE_API_KEY="YOUR_VENICE_API_KEY"

phobos ai \
  --target https://example.com \
  --scope example.com \
  "Map the application and identify likely AI attack surfaces."
```

The current AI planner can select only predefined reconnaissance actions. It cannot change the target, execute shell commands, or provide arbitrary HTTP arguments.

### Current limitation

The main `phobos` CLI has **not yet been promoted to a general autonomous assessment runner**. The assessment engine and browser adapter are functional, and the complete indirect-prompt-injection flow is demonstrated by `demo_indirect_injection.py`. The next integration step is exposing procedure selection and live assessment execution through the main CLI.

That distinction is intentional and keeps the project's public claims aligned with the code.

---

# Output and evidence

Reconnaissance runs store:

```text
.phobos/
├── scan.json
├── assets.json
├── graph.json
└── findings.json
```

Assessment runs use structured objects for:

```text
procedure
steps
observations
canary
finding state
confidence
correlated evidence
impact validation
```

Evidence should preserve enough context to answer:

```text
What happened?
Where did it happen?
What input caused it?
What baseline was compared?
What exact behavior changed?
What security boundary was crossed?
How was impact validated?
Can the result be reproduced?
```

---

# Safety and authorization

Phobos is designed for **authorized security testing only**.

The execution architecture is intentionally bounded:

```text
User-selected target
        ↓
Explicit scope policy
        ↓
Phobos procedure
        ↓
Controlled execution adapter
        ↓
Evidence
```

Private/local targets remain opt-in. The HTTP stack validates scope and redirects and pins direct HTTP connections to validated destinations. Browser requests are independently checked against the configured scope.

Active testing remains distinguishable from passive discovery, and destructive actions require an explicit authorization mode rather than being an accidental side effect of generic scanning.

---

# Roadmap

## Phase I — Core reconnaissance

- [x] CLI
- [x] configuration validation
- [x] centralized scope enforcement
- [x] bounded request manager
- [x] pinned direct HTTP connections
- [x] unified asset model
- [x] execution graph
- [x] atomic evidence storage
- [x] HTML reconnaissance
- [x] forms / inputs / endpoints / JavaScript discovery
- [x] passive AI-surface discovery
- [x] AI-assisted reconnaissance planning
- [x] automated tests / CI

## Phase II — Assessment engine

- [x] assessment procedure model
- [x] observation model
- [x] evidence correlation
- [x] confidence states
- [x] unique canary generation
- [x] indirect prompt-injection procedure
- [x] regression tests for mismatched canaries / missing baselines
- [x] bounded assessment orchestration
- [x] explicit state-change safety gate
- [x] browser/session execution adapter
- [x] authenticated session lifecycle in local demo
- [x] safe form interaction in local demo
- [x] chat interaction in local demo
- [x] controlled state-change verification in local demo
- [ ] generic structured tool-call observation across arbitrary targets
- [ ] general authenticated-session discovery / replay
- [ ] assessment CLI command

## Phase III — AI security procedures

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

## Phase IV — Web + AI attack-path analysis

- [ ] JavaScript/API discovery improvements
- [ ] authentication-aware crawling
- [ ] API schema discovery
- [ ] agent → tool → resource graphing
- [ ] trust-boundary detection
- [ ] cross-component attack-path construction
- [ ] reproducible attack traces

## Phase V — Benchmarking

- [ ] PortSwigger lab regression suite
- [ ] blind / mystery-style benchmark mode
- [ ] false-positive benchmark suite
- [ ] repeatability scoring
- [ ] evidence-quality scoring
- [ ] detection coverage metrics

## Phase VI — Reporting and integration

- [ ] rich vulnerability reports
- [ ] attack-path visualization
- [ ] machine-readable findings
- [ ] CI/CD integration
- [ ] SARIF support
- [ ] exportable evidence packages

---

# Development standard

Every new vulnerability procedure should answer five questions:

```text
1. What is the attack surface?
2. What is the trust boundary?
3. What is the smallest safe probe?
4. What observation proves the behavior?
5. What evidence is required before calling it confirmed?
```

No detector should be considered complete because it recognizes a keyword or payload. The acceptance test is an evidence-backed reproduction against a controlled target.

---

# License

The project is currently in early development and does not yet declare a final open-source license.

---

<div align="center">

**PHOBOS — discover the system. test the trust boundaries. prove the attack path.**

</div>
