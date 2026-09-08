<div align="center">

# PHOBOS

### AI-Assisted Web Security Scanner

**Find web vulnerabilities. Let AI reason about what to test next.**

Phobos is a security testing framework for **web applications that contain AI functionality**. It assesses the application's web and AI attack surfaces together, using AI reasoning to prioritize vulnerability testing.

</div>

---

## Product definition

Phobos has two target surfaces:

- **Web** — the application's normal web, API, browser, and service-facing functionality.
- **AI** — the application's LLM, agent, tool, retrieval, and AI-mediated functionality.

The AI inside Phobos is the **security brain**. It does not replace the scanners and it is not itself the target. It interprets the discovered attack surface, selects useful vulnerability modules, correlates evidence, and chooses the next useful test.

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
                    │                 │            Web ↔ AI
                    │                 │            AI ↔ Web
                    │                 │                 │
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
Authorization failures across Web and AI
Data leakage across application and AI contexts
Multi-step Web ↔ AI attack chains
```

---

# AI as the security brain

Phobos does not give the model unrestricted control of the host. The model receives structured application context and chooses from registered security capabilities.

```text
Reconnaissance
      ↓
Structured application context
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
│   ├── web.params
│   ├── web.auth
│   ├── web.access_control
│   ├── web.injection
│   ├── web.xss
│   ├── web.sqli
│   ├── web.ssrf
│   ├── web.uploads
│   ├── web.config
│   └── web.nmap
│
├── AI MODULES
│   ├── ai.surface
│   ├── ai.prompt_injection
│   ├── ai.data_disclosure
│   ├── ai.tool_abuse
│   └── ai.excessive_agency
│
└── CROSS-LAYER MODULES
    └── Web ↔ AI security procedures
```

A module is a **testing capability**, not a target. The catalog can contain capabilities that are planned but not yet fully implemented.

---

# Architecture

```text
CLI
 │
 ▼
Configuration + Scope
 │
 ▼
Web + AI Discovery
 │
 ▼
Attack-Surface Graph
 │
 ▼
AI Planning / Reasoning
 │
 ▼
Security Module Plan
 │
 ▼
Module Runner
 │
 ├── Web security modules
 │     ├── HTTP / browser checks
 │     └── Nmap
 │
 ├── AI security modules
 │
 └── Cross-layer security modules
 │
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
 │
 ▼
Next module / test
```

Nmap is therefore downstream of discovery and planning. It is invoked as a Web security capability when useful; it does not own discovery, planning, reporting, or the scan lifecycle.

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
Discover web + AI surface
      ↓
Build application context
      ↓
AI identifies the highest-value test
      ↓
Security module executes procedure
      ↓
Evidence collected
      ↓
AI reevaluates result
      ↓
Finding confirmed
```

Nmap is optional and should not be required for the first successful end-to-end vulnerability procedure.

Lab-specific URLs, payloads, credentials, and quirks belong in test fixtures, not in generic module logic.

---

# Current module direction

### Web

```text
web.headers
web.cookies
web.exposure
web.methods
web.params
web.auth
web.access_control
web.injection
web.xss
web.sqli
web.ssrf
web.uploads
web.config
web.nmap
```

### AI

```text
ai.surface
ai.prompt_injection
ai.data_disclosure
ai.tool_abuse
ai.excessive_agency
```

### Cross-layer

```text
web_ai.auth_boundary
web_ai.prompt_to_web
web_ai.tool_to_web
web_ai.data_flow
```

The module catalog describes the intended security capability surface. It does **not** claim that every listed module is implemented today.

---

# Engineering rules

```text
Scope controls every outbound destination.

Discovery describes the application; it does not automatically prove a flaw.

Security modules perform the actual vulnerability checks.

AI reasons about context, prioritization, correlation, and the next test.

Execution remains bounded and controlled by Phobos.

Evidence is required before a finding is confirmed.

Web and AI are target surfaces; modules are the testing capabilities.
```

---

# Development status

### Foundation

- [x] Central scope enforcement
- [x] Bounded HTTP request manager
- [x] Bounded web crawler
- [x] Forms / inputs / endpoint discovery
- [x] JavaScript/API route discovery
- [x] Passive AI-surface discovery
- [x] Shared attack-surface graph
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
- [ ] Implement cross-layer Web ↔ AI procedures
- [ ] Produce reproducible findings and reports

### Web-security coverage

- [ ] Authentication testing
- [ ] Authorization / access-control testing
- [ ] Injection testing
- [ ] XSS testing
- [ ] SQL / NoSQL injection testing
- [ ] SSRF testing
- [ ] File-upload testing
- [ ] API security testing
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
- [ ] Multi-step Web ↔ AI attack chains
