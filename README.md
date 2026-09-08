<div align="center">

# PHOBOS

### AI-Assisted Web Security Scanner

**Find web vulnerabilities. Let AI reason about what to test next.**

Phobos is a security testing framework for **web applications that contain AI functionality**. Its purpose is broad web security assessment: authentication, authorization, injection, XSS, SSRF, file handling, configuration, APIs, exposed services, and AI-specific weaknesses are all part of the same scanner.

The AI is not the only target. **The AI is the brain that helps Phobos understand the application, prioritize security modules, correlate observations, and decide where deeper testing is useful.**

</div>

---

## Product definition

Phobos has one defining constraint:

> **It scans web applications that have meaningful AI functionality, but once inside that application it looks for the full range of relevant web-security weaknesses.**

The architecture is:

```text
                  AI-enabled web application
                             │
                             ▼
                  Web + AI discovery
                             │
                             ▼
                   Attack-surface model
                             │
                             ▼
                      AI security brain
                             │
                   plan / prioritize / reason
                             │
                             ▼
                    Security modules
                             │
                ┌────────────┼────────────┐
                ▼            ▼            ▼
             Web tests    AI tests    Nmap module
                                          (optional)
                └────────────┼────────────┘
                             ▼
                    Evidence / validation
                             │
                             ▼
                           Findings
```

Nmap is **one security module**. It is not a separate discovery pipeline and does not define the architecture.

---

# What Phobos should find

### Standard web vulnerabilities

```text
Authentication
Authorization / access control
Session weaknesses
HTTP method weaknesses
Security-header problems
Cookie security problems
Input-validation flaws
SQL injection
XSS
SSRF
File-upload flaws
Path / file exposure
Configuration exposure
API security problems
Parameter tampering
Service-level weaknesses
```

### AI-related vulnerabilities

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
Multi-step AI attack chains
```

**AI-specific vulnerabilities are an extension of the web-security scanner, not a replacement for it.**

---

# AI as the security brain

Phobos should not give the model unrestricted control of the machine. Instead, the model receives structured application context and chooses from registered security capabilities.

The reasoning loop is:

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
Evidence
      ↓
AI reevaluation
      ↓
Next useful test
```

For example:

```text
Discover login + user input
          ↓
AI identifies authentication / access-control risk
          ↓
Run access-control module
          ↓
Interesting object-level behavior discovered
          ↓
AI prioritizes authorization follow-up
          ↓
Run next test
```

This feedback loop is the reason AI is integrated into Phobos.

The AI chooses from Phobos' registered modules. It does not change the target, bypass scope, execute arbitrary shell commands, or directly manufacture findings.

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
 ├── web.headers
 ├── web.cookies
 ├── web.exposure
 ├── web.methods
 ├── web.params
 ├── web.auth
 ├── web.access_control
 ├── web.injection
 ├── web.xss
 ├── web.sqli
 ├── web.ssrf
 ├── web.uploads
 ├── web.config
 ├── ai.surface
 ├── ai.prompt_injection
 ├── ai.data_disclosure
 ├── ai.tool_abuse
 ├── ai.excessive_agency
 └── web.nmap
 │
 ▼
HTTP / Browser / Nmap execution
 │
 ▼
Structured observations
 │
 ▼
Evidence + correlation
 │
 ▼
Findings
```

The repository remains physically flat. Logical separation comes from module contracts and stable IDs rather than a large folder hierarchy.

---

# Nmap

Nmap is optional and lives inside the normal security-module layer:

```text
Web discovery
      ↓
AI discovery
      ↓
Security testing
      ├── web modules
      ├── AI modules
      └── Nmap module (optional)
```

Use it with:

```bash
phobos scan https://example.com --scope example.com --nmap
```

Its purpose is to add service-level security evidence to the same assessment. An open service is an observation; a vulnerability finding requires the appropriate security check and evidence.

Nmap does not get its own graph, planner, reporting path, or scanner core.

---

# First PortSwigger target

The first real benchmark is an authorized PortSwigger Web Security Academy lab.

The objective is to prove one complete, reusable security-testing loop rather than hard-code a lab exploit:

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

Nmap is available when it adds useful service-level context, but the first end-to-end success should not depend on it.

Lab-specific URLs, payload strings, credentials, and quirks belong in test fixtures, not in the generic security module.

---

# Current module direction

The catalog represents the security coverage Phobos is being built toward:

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

ai.surface
ai.prompt_injection
ai.data_disclosure
ai.tool_abuse
ai.excessive_agency

web.nmap
```

The catalog is a contract, not a claim that every module is already fully implemented.

---

# Engineering rules

```text
Scope controls every outbound destination.

Discovery describes the application; it does not automatically prove a flaw.

Security modules perform the actual security checks.

AI reasons about context, prioritization, correlation, and the next test.

Execution remains bounded and controlled by Phobos.

Evidence is required before a finding is confirmed.
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
- [x] Optional Nmap security module
- [x] Synthetic demo infrastructure removed

### Next implementation target

- [ ] Connect real web-security modules to the module runner
- [ ] Implement the first full PortSwigger vulnerability procedure
- [ ] Improve request/response observations
- [ ] Build authenticated-session handling
- [ ] Implement AI-guided iterative module selection
- [ ] Produce reproducible findings and reports

### Web-security coverage

- [ ] Authentication testing
- [ ] Authorization / access-control testing
- [ ] Injection testing
- [ ] XSS testing
- [ ] SQL injection testing
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
- [ ] Retrieval/context attacks
- [ ] Cross-user isolation
- [ ] Multi-step AI attack chains
