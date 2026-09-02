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

Phobos is in **early development**. The current codebase provides a bounded web reconnaissance core, passive AI-surface discovery, an AI planning layer, and the first evidence-driven active assessment procedure for indirect prompt injection.

The goal is not to build a payload dictionary or a generic chatbot scanner. The goal is to build a system that can **discover an application's AI attack surface, execute a structured security procedure, correlate observations across multiple requests and components, and report a vulnerability only when the evidence supports it**.

The current PortSwigger-inspired indirect prompt-injection work is implemented as reusable assessment primitives. An end-to-end browser/session execution adapter is still required to run a live application through the complete procedure.

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

It should eventually become:

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

Phobos separates **mechanism**, **procedure**, and **finding logic**.

### Mechanism

The browser/HTTP layer performs navigation, requests, authentication, form interaction, and observation capture.

### Procedure

A vulnerability-specific workflow describes what must be discovered and tested. Procedures are reusable and are not tied to a single lab URL or product name.

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

The LLM planner is constrained to predefined Phobos capabilities. It does not control the target, scope, shell, or arbitrary request construction. fileciteturn5file0

---

# Discovery

The current reconnaissance engine discovers:

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

AI-surface detection is intentionally conservative. A signal is an indication that deeper testing may be relevant; it is **not a vulnerability finding**. fileciteturn4file0

The current crawler also preserves assets and relationships in an execution graph and stores bounded JSON evidence. fileciteturn6file0 fileciteturn11file0

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
6. Seed a unique non-destructive canary
7. Run a clean baseline
8. Trigger the normal LLM workflow
9. Correlate the exact canary with the induced behavior
10. Validate controlled impact when explicitly authorized
```

This is deliberately broader than a payload check. A successful procedure must establish the relationship between **stored attacker-controlled data** and **later model behavior**.

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

A correlated state-changing action can raise the confidence of an already proven injection path and provide impact evidence. The assessment module enforces canary format validation and exact seed/observation correlation. fileciteturn41file0

### Why this matters

This prevents a common scanner failure mode:

```text
"I found suspicious text"
        ≠
"I proved indirect prompt injection"
```

Phobos should report a vulnerability only when the causal chain is supported by captured evidence.

---

# PortSwigger benchmark philosophy

PortSwigger's Web Security Academy labs are being used as **behavioral benchmarks**, not as hard-coded solutions.

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
execute the applicable procedure,
reproduce the security behavior,
and explain why the finding is confirmed.
```

The four selected labs will become regression benchmarks for the AI-security engine.

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

The current project intentionally keeps the source layout simple while the engine is being established:

```text
.Phobos/
├── ai.py
├── ai_surface.py
├── ai_testing.py
├── cli.py
├── config.py
├── crawler.py
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
Execution Adapter
 ↓
Observation Stream
 ↓
Evidence Correlation
 ↓
Findings / Reports
```

The request manager remains the single outbound HTTP boundary and enforces scope, redirect validation, request limits, and response limits. fileciteturn9file0

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

The current AI planner can select only predefined reconnaissance actions. It cannot change the target, execute shell commands, or provide arbitrary HTTP arguments. fileciteturn5file0

### Important current limitation

The CLI has **not yet been promoted to a full autonomous assessment runner**. The active assessment engine is currently a reusable procedure/correlation layer. A browser/session adapter is the next major implementation step.

That distinction is intentional and documented so the project does not overstate its current capabilities.

---

# Output and evidence

Current reconnaissance runs store:

```text
.phobos/
├── scan.json
├── assets.json
├── graph.json
└── findings.json
```

Active assessments will extend this model with structured evidence such as:

```text
assessment.json
observations.json
attack_path.json
finding.json
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

Private/local targets remain opt-in. The current HTTP stack validates redirects against scope and blocks non-public destinations unless explicitly enabled. fileciteturn13file0

Active testing should remain distinguishable from passive discovery, and destructive actions should require an explicit authorization mode rather than being an accidental side effect of generic scanning.

---

# Roadmap

## Phase I — Core reconnaissance

- [x] CLI
- [x] configuration validation
- [x] centralized scope enforcement
- [x] bounded request manager
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
- [ ] first browser/session execution adapter
- [ ] authenticated session lifecycle
- [ ] safe form interaction
- [ ] chat interaction abstraction
- [ ] structured tool-call observation
- [ ] state-change verification
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
