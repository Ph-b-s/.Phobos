# About Phobos

## The project

Phobos is an AI-assisted security testing framework for **web applications that contain AI functionality**.

The scanner's security scope is broad. Once an AI-enabled web application is identified, Phobos can investigate ordinary web vulnerabilities as well as vulnerabilities created by the application's AI integration.

```text
AI-enabled website
       ↓
   web security
       +
    AI security
```

Nmap is only an optional supporting module for host/service context. It is not the project's primary focus.

## The core idea

> **The modules test. The AI thinks.**

Deterministic Phobos components handle discovery, HTTP/browser execution, known security checks, and evidence collection. The AI acts as the reasoning layer that can prioritize modules, interpret discoveries, connect observations, and determine what should be investigated next.

The AI does not receive unrestricted machine access. Phobos remains responsible for scope, execution, validation, and evidence.

## Security coverage

The intended scanner covers both:

```text
Web security
- authentication
- authorization / access control
- sessions
- input validation
- injection
- XSS
- SSRF
- file uploads
- API security
- configuration exposure
- common web weaknesses

AI security
- prompt injection
- indirect prompt injection
- data disclosure
- system-prompt exposure
- tool abuse
- excessive agency
- insecure output handling
- retrieval/context attacks
- cross-user isolation
```

The important distinction is that AI security is **one part of the overall assessment**, not the only type of vulnerability Phobos looks for.

## Architecture

```text
Target + Scope
      ↓
Discovery
 ├─ Web
 ├─ AI
 └─ Nmap (optional)
      ↓
Attack-Surface Model
      ↓
AI Reasoning / Prioritization
      ↓
Security Modules
      ↓
HTTP / Browser Execution
      ↓
Observations + Evidence
      ↓
Correlation
      ↓
Finding
```

Each module should be independently testable and exposed through a stable interface so the scanner can grow without rebuilding the core.

## First real target

The first validation environment is **authorized PortSwigger Web Security Academy labs**.

The objective is to prove the complete loop on a real target:

```text
Discover
   ↓
Understand
   ↓
Prioritize
   ↓
Test
   ↓
Observe
   ↓
Validate
   ↓
Report
```

The first PortSwigger integration should establish one reusable vulnerability procedure rather than a one-off script for a single lab.

## Development philosophy

Phobos is deliberately being built in layers. The scanner should become useful before it becomes autonomous.

```text
Strong discovery
      ↓
Strong module interfaces
      ↓
Real vulnerability checks
      ↓
Reliable evidence
      ↓
AI-guided iteration
```

The long-term goal is a tool that can look at an AI-enabled web application and continuously answer:

> **What is exposed, what can be attacked, what should I test next, and what evidence proves the result?**

---

Phobos is developed for authorized security research, learning, and defensive engineering.
