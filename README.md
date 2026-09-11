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
                    │                 │           Web ↔ AI
          HTTP + Browser JS      LLM / Agent       correlation
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

The runner rejects unknown modules, inactive modules, invalid stage ordering, oversized runs, and malformed module output. The AI can only select module IDs that exist in the catalog and are eligible for the current configured capabilities; actual execution requires a registered implementation.

Implemented procedures currently include Web hardening/visibility checks, non-destructive XSS/SQLi/NoSQL signals, CSRF analysis, client-side JavaScript analysis, JWT/GraphQL checks, SSTI arithmetic probes, Host-header/cache signals, path/upload/WebSocket surface analysis, configured authentication/authorization workflows, and controlled AI prompt/boundary procedures. Passive surface modules also map SSRF, command-execution, XML, deserialization, business-logic, RAG, vector, tool, data-poisoning, resource-limit, and multi-agent surfaces for bounded follow-up testing.

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

# Configuration-dependent testing

Higher-impact workflows are explicitly opt-in and configuration driven. Examples include authenticated-session bootstrap, low/high-privilege authorization comparison, direct prompt-injection canaries, and protected system-prompt marker tests.

```bash
phobos scan https://example.com \
  --scope example.com \
  --auth-config auth.json \
  --access-control-config access.json \
  --prompt-injection-config ai.json \
  --system-prompt-config system-prompt.json
```

These procedures do not invent credentials, selectors, object identifiers, or privileged assumptions. Sensitive values are redacted from evidence wherever possible.

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

### Implemented security procedures

- [x] Security headers
- [x] Cookie security
- [x] Common exposure
- [x] HTTP methods
- [x] Configuration disclosure
- [x] CORS
- [x] Information-disclosure pattern detection
- [x] API baseline
- [x] Reflected XSS signal detection
- [x] SQL injection error/differential signals
- [x] Bounded NoSQL differential testing
- [x] CSRF form analysis
- [x] Client-side JavaScript source/sink analysis
- [x] JWT algorithm signal analysis
- [x] GraphQL introspection analysis
- [x] Low-impact SSTI arithmetic probes
- [x] Host-header trust signals
- [x] Cache-policy/reflection signals
- [x] Configured authentication workflow
- [x] Configured low/high-privilege authorization comparison
- [x] Bounded path-traversal marker checks
- [x] Passive file-upload validation analysis
- [x] WebSocket endpoint discovery
- [x] SSRF sink discovery
- [x] Command-execution sink discovery
- [x] XML-processing surface discovery
- [x] Serialization/deserialization surface discovery
- [x] Business-logic workflow candidate discovery
- [x] Direct prompt-injection canary
- [x] Indirect prompt-injection procedure
- [x] Protected system-prompt marker test
- [x] Protected-data disclosure marker test
- [x] AI output-handling probe
- [x] Goal-hijacking marker procedure
- [x] Context-manipulation marker procedure
- [x] AI tool-surface discovery
- [x] RAG/retrieval surface discovery
- [x] Vector/embedding surface discovery
- [x] Untrusted AI-context source discovery
- [x] AI resource-control visibility analysis
- [x] Multi-agent surface discovery

### Remaining major validation procedures

- [ ] Active SSRF validation
- [ ] Active command-injection validation
- [ ] Active XXE validation
- [ ] Active unsafe-deserialization validation
- [ ] Full cache poisoning/deception confirmation
- [ ] HTTP request smuggling
- [ ] JWT signing/claim validation beyond passive analysis
- [ ] GraphQL authorization/query abuse
- [ ] Active WebSocket authentication/authorization/message testing
- [ ] Race-condition testing
- [ ] Business-logic workflow abuse
- [ ] Full IDOR/object-level authorization testing
- [ ] Active AI tool-abuse validation
- [ ] Active excessive-agency validation
- [ ] Active RAG/vector authorization and isolation testing
- [ ] Active AI data-poisoning validation
- [ ] Resource/cost exhaustion confirmation
- [ ] Active multi-agent trust-boundary testing
- [ ] Full sensitive-information disclosure testing beyond configured markers

### Productization

- [x] Human-readable Markdown report
- [x] Deterministic scan summarizer
- [x] Iterative AI planner with hard iteration cap
- [x] Configuration-aware AI module eligibility
- [x] Optional Nmap module
- [x] Desktop application shell on shared application services
- [x] Automated test suite and CI definition
- [x] Evidence privacy safeguards for secrets and tokens

---

## Current principle

Phobos is developed as a controlled security-testing platform, not an unrestricted autonomous exploit framework. New vulnerability procedures are only marked implemented once they have a bounded execution contract, deterministic evidence logic, appropriate authorization/configuration gates where necessary, and regression coverage. Surface-identification modules may intentionally stop at a high-confidence candidate and hand active confirmation to a later controlled procedure.
