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
                    │                 │           correlation
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

## Cross-layer correlation

Cross-layer analysis is part of the core scan pipeline rather than an afterthought.

```text
Web + AI discovery
       ↓
Attack-surface graph
       ↓
Evidence correlation
       ↓
Web → AI / AI → Web paths
       ↓
Bounded follow-up candidates
       ↓
Security module runner
```

A graph path is **not automatically a vulnerability**. Phobos keeps correlation separate from confirmation: the correlation engine identifies plausible relationships, while security modules collect the evidence needed to support a finding.

---

## Security-module runner

Phobos uses a registry-driven runner with explicit execution stages:

```text
WEB / AI ASSESSMENT
        ↓
FOLLOW-UP / CROSS-LAYER
        ↓
SUPPLEMENTAL (optional Nmap)
```

Each module receives the same shared knowledge state and can emit:

- structured observations
- findings
- bounded follow-up candidates

The runner rejects unknown modules, inactive modules, invalid stage ordering, oversized runs, and malformed module output. The AI can only select module IDs that exist in the catalog; actual execution requires a registered implementation.

The current built-in implementations are the deterministic cross-layer correlation modules. Web and AI vulnerability procedures are added to the same runner as they become real.

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
Cross-layer correlation
      ↓
AI prioritization
      ↓
Security module runner
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
- [x] Cross-layer attack-path correlation
- [x] Cross-layer evidence correlation
- [x] Registry-driven module runner
- [x] Shared knowledge state across modules
- [x] Evidence storage
- [x] Security-module catalog
- [x] AI planning layer
- [x] Optional Nmap Web module

### Current implementation target

- [ ] Connect real Web vulnerability procedures to the runner
- [ ] Connect real AI vulnerability procedures to the runner
- [ ] Implement the first full PortSwigger vulnerability procedure
- [ ] Improve request / response observations
- [ ] Build authenticated-session handling
- [ ] Implement AI-guided iterative module selection
- [ ] Add confirmation/validation stages for high-value findings
- [ ] Produce reproducible findings and reports
- [ ] Build the Desktop App around the same engine

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
