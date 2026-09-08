<div align="center">

# PHOBOS

### AI-Assisted Web Security Scanner

**Find web vulnerabilities. Let AI reason about what to test next.**

Phobos is a security testing framework for **web applications that contain AI functionality**. Its purpose is broad web security assessment: authentication, authorization, injection, XSS, SSRF, file handling, configuration, exposed services, APIs, and AI-specific weaknesses are all part of the same scanner.

The AI is not the only target. **The AI is the brain that helps Phobos understand the application, prioritize security modules, correlate observations, and decide where deeper testing is useful.**

</div>

---

## Product definition

Phobos has one defining constraint:

> **It scans web applications that have meaningful AI functionality, but once inside that application it looks for the full range of web-security weaknesses.**

The resulting architecture is:

```text
                  AI-enabled web application
                             │
                   Discovery / mapping
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
      Web surface        AI surface       Nmap (optional)
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ▼
                   Attack-surface model
                             │
                             ▼
                      AI security brain
                             │
                    module prioritization
                             │
                             ▼
                    Security modules
                             │
                   ┌─────────┴─────────┐
                   ▼                   ▼
              deterministic       AI-specific
               web checks             checks
                   └─────────┬─────────┘
                             ▼
                     Evidence / state
                             │
                             ▼
                    Correlation + finding
```

Nmap is deliberately only one module. It supplies supporting host/service information; it is not the center of the project.

---

# What Phobos should eventually find

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

The distinction is important: **AI-specific vulnerabilities are an extension of the web-security scanner, not a replacement for it.**

---

# AI as the security brain

The model receives structured observations from Phobos rather than controlling the machine directly.

Its context can contain:

```text
Target + scope
Pages
Endpoints
HTTP methods
Forms and inputs
JavaScript/API routes
Authentication clues
AI surfaces
Observed services
Existing findings
Results from previous modules
```

It returns a constrained plan such as:

```json
{
  "action": "plan_scan",
  "modules": [
    "web.auth",
    "web.access_control",
    "web.injection",
    "web.xss",
    "ai.prompt_injection"
  ],
  "reason": "The application exposes authenticated state and several user-controlled inputs, while an AI interface creates an additional trust boundary."
}
```

Phobos validates the module names against its own catalog. The AI cannot invent capabilities, change the target, bypass scope, execute shell commands, or silently manufacture a finding.

This creates the division of responsibility we want:

```text
AI
 ├── understand
 ├── prioritize
 ├── correlate
 └── reason

Phobos modules
 ├── request
 ├── observe
 ├── test
 └── produce evidence
```

---

# Architecture

```text
CLI
 │
 ▼
Configuration + Scope
 │
 ▼
Reconnaissance
 ├── Web crawler
 ├── JavaScript/API discovery
 ├── AI-surface discovery
 └── Nmap module (optional)
 │
 ▼
Attack-Surface Graph
 │
 ▼
AI Planning Layer
 │
 ▼
Security Module Plan
 │
 ▼
Security Module Runner
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
 └── network.nmap
 │
 ▼
HTTP / Browser execution
 │
 ▼
Structured observations
 │
 ▼
Evidence correlation
 │
 ▼
Findings + reproduction data
```

The flat repository layout stays in place. Logical separation comes from interfaces and stable module IDs, not from creating dozens of directories.

---

# Module system

The scanner now has a common module catalog. Each module has:

```text
stable ID
name
description
category
execution mode
```

The catalog is deliberately broader than the currently implemented checks. This lets us build Phobos incrementally without repeatedly redesigning the scanner core.

The important future behavior is:

```text
Recon discovers a parameter
        ↓
AI sees parameter + application context
        ↓
AI prioritizes injection modules
        ↓
module tests the parameter
        ↓
observation is recorded
        ↓
AI can use that result to prioritize the next test
```

That feedback loop is the actual reason to integrate AI into a web scanner.

---

# Nmap

Nmap is optional:

```bash
phobos scan https://example.com --scope example.com --nmap
```

It provides basic host/service information and feeds it into the same target model as the web discovery results.

For example:

```text
tcp/443 → https
      ↓
web application
      ↓
API / AI surface
```

or:

```text
tcp/22 → ssh
```

An open port is an observation, not a vulnerability by itself.

---

# First real testing target

The first real benchmark target is an authorized **PortSwigger Web Security Academy** lab.

We are not going to hard-code the lab into Phobos. The goal is to prove that the architecture can generalize.

```text
PortSwigger lab
      ↓
Discover
      ↓
Model
      ↓
AI prioritizes
      ↓
Run relevant module
      ↓
Collect evidence
      ↓
Validate finding
      ↓
Report why it is vulnerable
```

The first successful test should establish the whole pipeline, even if only one vulnerability class is implemented at first.

---

# CLI

```bash
phobos scan https://example.com --scope example.com
```

Optional Nmap enrichment:

```bash
phobos scan https://example.com --scope example.com --nmap
```

AI-assisted planning:

```bash
phobos scan https://example.com --scope example.com --ai
```

List modules:

```bash
phobos modules
```

Ask the AI planner directly:

```bash
phobos ai \
  --target https://example.com \
  --scope example.com \
  "Prioritize the most valuable security tests for this application."
```

---

# Engineering rules

```text
Scope controls every outbound destination.

Discovery does not automatically equal a vulnerability.

Security modules perform the actual checks.

AI selects, prioritizes, reasons, and correlates.

Execution remains bounded and controlled by Phobos.

Evidence is required before confirmation.
```

The existing HTTP and browser layers already enforce the target scope at their respective network boundaries. fileciteturn49file0 fileciteturn47file0

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
- [x] Optional Nmap module
- [x] Security-module catalog
- [x] AI module-planning layer

### Next implementation target

- [ ] Connect real security modules to the scanner runner
- [ ] Improve request/response observation model
- [ ] Build authenticated-session workflow
- [ ] Implement first reusable PortSwigger procedure
- [ ] Add active validation for standard web vulnerabilities
- [ ] Add AI-guided iterative test selection
- [ ] Generate structured findings and reports

### AI security

- [ ] Direct prompt injection
- [ ] Indirect prompt injection
- [ ] AI data disclosure
- [ ] Tool abuse
- [ ] Excessive agency
- [ ] Retrieval/context attacks
- [ ] Cross-user isolation
- [ ] Multi-step AI attack chains

### Later

- [ ] Broader PortSwigger regression suite
- [ ] Attack-path visualization
- [ ] SARIF / CI integration
- [ ] Evidence packages
