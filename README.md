<div align="center">

# PHOBOS

### Web & AI Security Testing Framework

**Discover the system. Map the trust boundaries. Test the attack path. Prove the evidence.**

Phobos is an open-source framework for authorized security testing of modern web applications, APIs, AI assistants, AI agents, tools, and the relationships between them.

</div>

---

## Project status

Phobos is in early development. The current build is intentionally focused on the foundation required to test real targets rather than maintaining synthetic demonstration targets.

Implemented foundations include:

- strict target and scope validation
- bounded HTTP reconnaissance
- bounded TCP service discovery through Nmap
- web pages, links, forms, inputs, and JavaScript discovery
- passive API-route discovery from HTML and JavaScript
- passive AI-surface discovery
- a shared asset and relationship graph
- structured evidence storage
- reusable assessment procedures
- a bounded assessment engine
- browser and HTTP execution primitives
- regression coverage for scope, discovery, graphing, and assessment logic

Synthetic vulnerable targets and demo runners are deliberately not part of the project path. Real authorized environments, especially PortSwigger Web Security Academy labs, are the intended validation targets.

## Mission

Modern security failures often cross multiple layers:

```text
Attacker-controlled input
        ↓
Web application
        ↓
API / stored data
        ↓
LLM context
        ↓
Model decision
        ↓
Tool / API call
        ↓
Authenticated state
        ↓
Security impact
```

Phobos is designed to model that chain instead of treating web security and AI security as unrelated scanners.

The long-term pipeline is:

```text
Discover → Normalize → Connect → Probe → Validate → Correlate → Report
```

A finding should therefore explain an observed relationship, not merely match a suspicious string.

---

# Architecture

Phobos keeps a flat source layout while enforcing clear logical boundaries.

```text
                 Target + Scope
                       |
        +--------------+--------------+
        |                             |
        v                             v
 Network Discovery              Web Discovery
      Nmap                    HTTP / Browser
        |                             |
        +--------------+--------------+
                       v
                Attack-Surface Graph
                       |
             +---------+---------+
             |                   |
             v                   v
      AI Surface Discovery   Service Mapping
             |                   |
             +---------+---------+
                       v
              Assessment Procedure
                       |
                       v
                Assessment Engine
                       |
                       v
               Execution Adapter
                       |
                       v
             Structured Observations
                       |
                       v
                Evidence Correlation
                       |
                       v
                   Finding
```

The key design rule is that scanners do not own the final finding. They produce observations that become useful when connected to the unified attack-surface model.

See [`RECON_ARCHITECTURE.md`](RECON_ARCHITECTURE.md) for the detailed reconnaissance design.

---

# Network discovery with Nmap

Nmap is part of Phobos' reconnaissance foundation.

Its purpose is not to turn Phobos into a generic port-scanning wrapper. It answers an upstream question:

> What network services are exposed by the target host, and which of them should influence deeper application discovery?

The current network primitive:

```text
Target URL / hostname
        ↓
      Scope
        ↓
     Nmap TCP
  top 100 ports
        ↓
  normalized ports
        ↓
   attack graph
```

The execution path is deliberately bounded:

- TCP connect scanning (`-sT`)
- top 100 ports
- open-port output only
- XML output parsed into typed observations
- `shell=False`
- explicit timeout
- target host derived from the supplied target URL
- centralized scope validation

An open port is **not automatically a vulnerability**. It is attack-surface information that can reveal another service, an HTTP listener, an administrative interface, or a useful relationship to application behavior.

The next stages can later use these observations to guide service-specific discovery rather than blindly scanning everything.

---

# Web discovery

The crawler discovers:

```text
pages
links
forms
inputs
JavaScript
API routes
query parameters
AI-related signals
```

The JavaScript discovery layer is passive. It extracts likely application routes from patterns such as browser `fetch()` calls, Axios requests, explicit HTTP-method calls, GraphQL endpoints, and conventional API paths.

These routes are normalized into the same endpoint/input model as ordinary HTML-discovered resources.

---

# AI surface discovery

AI discovery is deliberately conservative.

Phobos currently recognizes signals such as:

```text
chat / completion endpoints
provider references
agent / tool terminology
AI-oriented form inputs
```

A signal means:

```text
"this component may be interesting"
```

It does **not** mean:

```text
"a vulnerability was found"
```

The next architectural step is connecting those AI signals to actual application behavior and, where visible, to model-controlled tools and resources.

---

# Assessment model

Phobos separates four concepts:

### Mechanism

HTTP and browser adapters perform bounded actions and emit observations.

### Procedure

A vulnerability procedure defines what needs to be discovered, what must be observed, and what constitutes confirmation.

### Orchestration

The assessment engine executes only declared procedure steps and enforces execution, observation, and state-change limits.

### Finding logic

The analyzer correlates observations and decides whether evidence supports a suspected, strong, or confirmed result.

For AI security, the objective is to demonstrate a relationship such as:

```text
untrusted content
      ↓
LLM context
      ↓
changed model behavior
      ↓
security-relevant action
```

rather than declaring victory because a model echoed a payload.

---

# First real testing target: PortSwigger labs

PortSwigger Web Security Academy is the first external benchmark environment for Phobos.

The important distinction is that Phobos should learn the **vulnerability procedure**, not memorize a lab.

For each target, the intended workflow is:

```text
1. Establish target + scope
2. Discover exposed services
3. Discover web application surface
4. Build the unified graph
5. Identify the relevant AI or web trust boundary
6. Select the applicable procedure
7. Establish a clean baseline
8. Execute the smallest useful active probe
9. Compare observations
10. Confirm the behavior with evidence
11. Record a reproducible finding
```

A lab-specific target, parameter, payload, or URL belongs in a regression fixture. The reusable procedure should describe the class of vulnerability.

---

# Repository structure

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
├── test_*.py
├── RECON_ARCHITECTURE.md
├── ABOUT.md
├── README.md
└── pyproject.toml
```

The layout is physically flat; the architecture is not.

---

# CLI foundation

Current commands are focused on controlled discovery and planning:

```bash
phobos scan https://example.com --scope example.com
phobos ai --target https://example.com --scope example.com "Map the application"
phobos doctor
```

Network discovery is currently exposed as a library primitive rather than pretending that the complete end-to-end assessment CLI is finished.

The future command structure is intended to become:

```text
phobos recon <target>
    ├── network
    ├── web
    └── ai-surface

phobos assess <target> --procedure <procedure>

phobos report <scan-directory>
```

The important point is that `recon` should assemble observations into the attack-surface graph, while `assess` should execute a selected security procedure against that model.

---

# Safety

Phobos is designed for authorized security testing.

Every network capability should remain subject to explicit scope. Active validation should remain separate from passive discovery, and state-changing actions should require explicit authorization.

The project should become more powerful by becoming more structured and evidence-driven, not by removing those boundaries.

---

# Roadmap

## Phase I — Reconnaissance foundation

- [x] CLI foundation
- [x] configuration validation
- [x] centralized scope enforcement
- [x] bounded HTTP request manager
- [x] network discovery primitive
- [x] normalized Nmap port observations
- [x] HTML reconnaissance
- [x] forms / inputs / endpoints / JavaScript discovery
- [x] passive API-route discovery
- [x] passive AI-surface discovery
- [x] unified asset model
- [x] execution graph
- [x] structured evidence storage

## Phase II — Real-target assessment foundation

- [x] reusable assessment procedure model
- [x] bounded assessment engine
- [x] browser/session execution primitive
- [x] evidence correlation
- [x] confidence states
- [ ] generic authenticated-session handling
- [ ] structured tool/API observation
- [ ] unified network + web graph integration
- [ ] assessment CLI

## Phase III — AI security procedures

- [ ] direct prompt injection
- [ ] indirect prompt injection
- [ ] sensitive information disclosure
- [ ] system-prompt exposure
- [ ] excessive agency
- [ ] tool abuse
- [ ] insecure output handling
- [ ] retrieval/context poisoning
- [ ] cross-user context isolation
- [ ] multi-step AI attack-chain correlation

## Phase IV — Benchmarking

- [ ] first PortSwigger AI-security lab
- [ ] additional PortSwigger lab regression fixtures
- [ ] false-positive benchmark suite
- [ ] repeatability scoring
- [ ] evidence-quality scoring
- [ ] detection coverage metrics

## Phase V — Reporting

- [ ] reproducible attack traces
- [ ] rich vulnerability reports
- [ ] attack-path visualization
- [ ] machine-readable findings
- [ ] SARIF export
- [ ] CI/CD integration
