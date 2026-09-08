<div align="center">

# PHOBOS

### AI-Assisted Web Security Scanner

**Find web vulnerabilities. Let AI reason about what to test next.**

Phobos is a security testing framework for **web applications that contain AI functionality**. It assesses the application's web and AI attack surfaces together, using AI reasoning to prioritize vulnerability testing.

</div>

---

## Product definition

Phobos has two target surfaces:

- **Web** — the application's normal web, API, browser, client-side JavaScript, and service-facing functionality.
- **AI** — the application's LLM, agent, tool, retrieval, and AI-mediated functionality.

The AI inside Phobos is the **security brain**. It does not replace scanners and it is not itself the target. It interprets the discovered attack surface, selects useful vulnerability modules, correlates evidence, and chooses the next useful test.

### High-level structure

```text
                         AI-ENABLED WEB APPLICATION
                                      │
                         ┌────────────┴────────────┐
                         ▼                         ▼
                    WEB TARGET                 AI TARGET
                         │                         │
                         └────────────┬────────────┘
                                      ▼
                            ATTACK-SURFACE MODEL
                                      │
                                      ▼
                                  AI "BRAIN"
                                      │
                                      ▼
                           VULNERABILITY MODULES
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
                    ▼                 ▼                 ▼
                WEB MODULES       AI MODULES      CROSS-LAYER
                    │                 │                 │
          HTTP + Browser JS      LLM / Agent       Web ↔ AI
                    │                 │           attack-path
                    └─────────────────┼─────────────────┘
                                      ▼
                              EVIDENCE / FINDINGS
                                      │
                                      ▼
                               AI REEVALUATES
                                      │
                                      ▼
                              NEXT TEST / MODULE
```

**Web and AI are targets. Modules are the capabilities used to search those targets for vulnerabilities.** Nmap is one Web module, not a third target and not a separate scanner architecture.

---

# What Phobos should find

### Web vulnerabilities

```text
Authentication
Authorization / access control
Session weaknesses
HTTP method weaknesses
Security headers / cookies
Input validation
SQL / NoSQL injection
XSS
DOM / client-side JavaScript issues
CSRF
SSRF
Command injection
Path traversal
File upload
XXE
SSTI
Deserialization
CORS
Cache poisoning / deception
HTTP request smuggling
Host-header attacks
JWT weaknesses
GraphQL security
WebSocket security
Race conditions
Business-logic flaws
Information disclosure
Configuration exposure
API security
Service-level weaknesses
```

### AI vulnerabilities

```text
Direct prompt injection
Indirect prompt injection
Sensitive information disclosure
System-prompt exposure
Excessive agency
Tool abuse
Insecure output handling
Retrieval / context poisoning
Cross-user context leakage
Memory / context manipulation
Goal hijacking
Identity / privilege abuse
Multi-step agent attack chains
Resource / cost abuse
```

### Cross-layer vulnerabilities

```text
Web → AI trust-boundary attacks
AI → Web actions
AI → internal-service access
Prompt injection → tool abuse chains
Web/AI authorization failures
Sensitive data crossing Web ↔ AI boundaries
AI output becoming a Web vulnerability
Multi-step Web ↔ AI attack paths
```

---

# Dynamic Web security

Modern Web applications are not fully observable through raw HTTP alone. Phobos therefore has two complementary Web-recon modes.

```text
STATIC HTTP
  HTML / links / forms
  JavaScript references
  API literals
  AI signals

             +

BROWSER RUNTIME
  JavaScript execution
  rendered DOM
  dynamically created links/forms
  runtime API requests
  browser-side state signals

             ↓

       UNIFIED WEB ATTACK SURFACE
```

The browser layer is implemented with Playwright and remains bounded by the same scope controls as the HTTP layer. Browser execution is optional so static reconnaissance remains dependency-light.

Run dynamic Web reconnaissance with:

```bash
phobos scan https://example.com --scope example.com --browser
```

---

# AI as the security brain

Phobos does not give the model unrestricted control of the host. The model receives structured application context and chooses from registered security capabilities.

```text
Reconnaissance
      ↓
Structured Web + AI context
      ↓
Cross-layer attack-path candidates
      ↓
AI prioritization
      ↓
Security module selection
      ↓
Controlled execution
      ↓
Evidence / observations
      ↓
AI reevaluation
      ↓
Next useful test
```

The AI decides **what is worth testing next**. Deterministic modules decide **how the authorized test is executed**. Phobos controls the target, scope, requests, tools, and evidence.

The AI may not change the target, bypass scope, execute arbitrary shell commands, or manufacture findings without evidence.

---

# Vulnerability module architecture

The repository stays physically flat. Logical separation is provided by module contracts and stable IDs.

```text
VULNERABILITY MODULES
│
├── WEB MODULES
│   ├── web.headers
│   ├── web.cookies
│   ├── web.exposure
│   ├── web.methods
│   ├── web.auth
│   ├── web.access_control
│   ├── web.injection
│   ├── web.xss
│   ├── web.sqli / web.nosqli
│   ├── web.ssrf
│   ├── web.file_upload
│   ├── web.api
│   ├── web.client_javascript
│   ├── web.browser_runtime
│   └── web.nmap
│
├── AI MODULES
│   ├── ai.prompt_injection
│   ├── ai.indirect_prompt_injection
│   ├── ai.data_disclosure
│   ├── ai.tool_abuse
│   ├── ai.excessive_agency
│   └── ai.rag / ai.vector / ai.multi_agent / ...
│
└── CROSS-LAYER MODULES
    ├── cross_layer.web_to_ai
    ├── cross_layer.ai_to_web
    ├── cross_layer.auth_boundary
    ├── cross_layer.data_flow
    ├── cross_layer.control_flow
    ├── cross_layer.capability_escalation
    └── cross_layer.attack_path
```

Cross-layer modules are **correlation and attack-path capabilities**. They use evidence produced by Web and AI modules rather than becoming a second collection of scanners.

---

# Cross-layer model

The central cross-layer concept is an attack path:

```text
WEB SOURCE
   ↓
attacker-controlled data
   ↓
AI CONTEXT / DECISION
   ↓
TOOL / API / OUTPUT
   ↓
WEB OR BACKEND SINK
   ↓
IMPACT
```

Phobos models these relationships in the attack-surface graph and produces bounded candidates for follow-up testing. A graph path is **not automatically a vulnerability**; confirmation still requires module evidence.

---

# Architecture

```text
CLI
 │
 ▼
Configuration + Scope
 │
 ▼
Static HTTP Recon ────────┐
 │                        │
 ▼                        ▼
Browser / JavaScript     Runtime Network
 │                        │
 └────────────┬───────────┘
              ▼
       Web + AI Attack Surface
              │
              ▼
        Cross-Layer Graph
              │
              ▼
        AI Planning / Reasoning
              │
              ▼
       Security Module Plan
              │
      ┌───────┼────────┐
      ▼       ▼        ▼
     WEB      AI    CROSS-LAYER
      │       │        │
      └───────┼────────┘
              ▼
 Controlled HTTP / Browser / Nmap execution
              │
              ▼
      Structured observations
              │
              ▼
       Evidence + correlation
              │
              ▼
            Findings
              │
              ▼
        AI reevaluation
```

Nmap is downstream of planning as a **Web security capability**. Browser/JavaScript execution is part of the Web layer, not a separate target.

---

# Nmap's role

Nmap belongs to the **Web module layer**.

It is a tool Phobos can invoke to gather service-level security evidence and, as the module evolves, perform appropriate bounded vulnerability checks against the authorized target. An open port by itself is an observation, not a confirmed vulnerability.

```text
WEB TARGET
    │
    ▼
AI selects useful testing capabilities
    │
    ├── HTTP / browser modules
    └── web.nmap
```

Use it with:

```bash
phobos scan https://example.com --scope example.com --nmap
```

---

# First PortSwigger target

The first real benchmark is an authorized PortSwigger Web Security Academy lab.

The goal is to prove a reusable end-to-end security loop rather than hard-code a lab exploit:

```text
PortSwigger lab
      ↓
Discover Web + AI surface
      ↓
Build application context
      ↓
Cross-layer correlation
      ↓
AI identifies the highest-value test
      ↓
Security module executes procedure
      ↓
Evidence collected
      ↓
AI reevaluates
      ↓
Finding confirmed
```

Nmap is optional and should not be required for the first successful end-to-end vulnerability procedure.

Lab-specific URLs, payloads, credentials, and quirks belong in test fixtures, not in generic module logic.

---

# Development status

### Foundation

- [x] Central scope enforcement
- [x] Bounded HTTP request manager
- [x] Bounded static web crawler
- [x] Optional real-browser JavaScript execution
- [x] Rendered DOM / runtime network observations
- [x] Forms / inputs / endpoint discovery
- [x] JavaScript/API route discovery
- [x] Passive AI-surface discovery
- [x] Shared attack-surface graph
- [x] Cross-layer attack-path correlation primitives
- [x] Evidence storage
- [x] Security-module catalog
- [x] AI planning layer
- [x] Optional Nmap Web module
- [x] Synthetic demo infrastructure removed

### Next implementation target

- [ ] Connect real Web vulnerability modules to the module runner
- [ ] Connect real AI vulnerability modules to the module runner
- [ ] Implement the first full PortSwigger vulnerability procedure
- [ ] Improve request / response observations
- [ ] Build authenticated-session handling
- [ ] Implement AI-guided iterative module selection
- [ ] Expand cross-layer flow, trust, and capability correlation
- [ ] Produce reproducible findings and reports

### Web-security coverage

- [ ] Authentication testing
- [ ] Authorization / access-control testing
- [ ] Injection testing
- [ ] XSS and DOM testing
- [ ] SQL / NoSQL injection testing
- [ ] SSRF testing
- [ ] File-upload testing
- [ ] API security testing
- [ ] Client-side JavaScript testing
- [ ] Browser-driven testing
- [ ] Configuration / exposure testing
- [ ] Service-level checks through Nmap

### AI-security coverage

- [ ] Direct prompt injection
- [ ] Indirect prompt injection
- [ ] AI data disclosure
- [ ] Tool abuse
- [ ] Excessive agency
- [ ] Retrieval / context attacks
- [ ] Cross-user isolation
- [ ] Multi-step AI attack chains

### Cross-layer coverage

- [ ] Web → AI trust-boundary testing
- [ ] AI → Web action testing
- [ ] AI → internal-service access testing
- [ ] Web/AI authorization-boundary testing
- [ ] Data-flow analysis
- [ ] Control-flow analysis
- [ ] Capability escalation analysis
- [ ] Multi-step Web ↔ AI attack chains
