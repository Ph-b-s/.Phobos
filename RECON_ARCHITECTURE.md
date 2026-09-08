# Phobos Architecture

Phobos is an **AI-assisted web security scanner for web applications that contain AI functionality**.

The AI presence is the product's scope constraint and strategic advantage. The security scope itself is broad: once the target qualifies as an AI-enabled web application, Phobos should investigate the application's normal web attack surface as well as the AI-specific attack surface.

## 1. Core model

```text
AI-enabled web application
          ↓
      Discovery
          ↓
   Attack-surface model
          ↓
    AI reasoning layer
          ↓
    Security module plan
          ↓
      Module runner
          ↓
   HTTP / Browser execution
          ↓
      Evidence
          ↓
  Correlation / validation
          ↓
        Finding
```

The responsibilities are deliberately separated:

```text
Phobos core  → scope, execution, state, evidence
Modules      → actual security checks
AI           → reasoning, prioritization, correlation
```

The AI is never the authority for target selection or arbitrary machine access.

## 2. Discovery

Discovery builds enough context for both deterministic modules and AI reasoning.

### Web discovery

```text
pages
links
forms
inputs
HTTP methods
JavaScript
API routes
query parameters
```

### AI discovery

```text
AI endpoints
provider signals
chat interfaces
agent/tool signals
AI-oriented inputs
```

Discovery is preparation for the security-testing stage. It is not the product's final objective.

## 3. Security modules

Once the target's web and AI surface is known, Phobos tests it through a common security-module layer.

The intended coverage includes:

```text
Web
├── headers
├── cookies
├── exposure
├── methods
├── parameters
├── authentication
├── access control
├── injection
├── XSS
├── SQL injection
├── SSRF
├── file uploads
└── configuration

AI
├── prompt injection
├── data disclosure
├── tool abuse
└── excessive agency

Additional web/service check
└── Nmap
```

The module layer is where vulnerability testing lives. Nmap is simply one module alongside the other security checks.

## 4. Nmap's exact role

Nmap is **not** a separate reconnaissance pipeline and not a separate security product inside Phobos.

Its place is in the testing stage:

```text
Web discovery
      ↓
AI discovery
      ↓
AI + web security testing
      ↓
Nmap module (when useful)
      ↓
Additional service-level evidence
```

The Nmap module may use service/version discovery and appropriate vulnerability-oriented checks to identify weaknesses that are relevant to the target host. Its results use the same module, evidence, and finding interfaces as every other security test.

It does not own the graph, planner, report generation, or execution engine.

## 5. AI as the security-testing brain

The AI is the reasoning and orchestration layer above the modules.

It should reason over:

```text
reconnaissance
application structure
HTTP responses
browser observations
API behavior
AI surfaces
module findings
previous test results
relationships between assets
```

Its job is to help answer:

```text
What should Phobos test next?
Which vulnerability classes are relevant here?
Which discovered input deserves deeper testing?
Does this result justify another test?
Can multiple weak signals form a stronger attack path?
What evidence is still missing before reporting a finding?
```

The AI chooses from registered Phobos capabilities. The modules remain responsible for actually performing the security checks and producing technical evidence.

## 6. Iterative testing loop

The long-term scanner should not be a rigid list of checks.

```text
Discover
   ↓
AI prioritizes
   ↓
Run module
   ↓
Collect evidence
   ↓
AI reevaluates
   ↓
Run next useful module
   ↓
       ...
   ↓
Confirm findings
   ↓
Report
```

This is where AI provides value over a conventional fixed-order scanner: it can use the result of one security test to decide where another test is more valuable.

## 7. Assessment procedures

Each security module contains reusable procedures for a vulnerability class.

A procedure defines:

```text
prerequisites
applicable assets
probe strategy
observations
confirmation conditions
evidence
optional impact validation
```

PortSwigger lab-specific URLs, payloads, and quirks belong in test fixtures, not inside the generic procedure.

## 8. First PortSwigger milestone

The first real benchmark should prove the complete concept with one vulnerability class:

```text
PortSwigger AI-enabled lab
          ↓
Web + AI discovery
          ↓
Attack-surface context
          ↓
AI prioritization
          ↓
One security module
          ↓
Evidence
          ↓
AI reevaluation
          ↓
Finding
```

Nmap is optional and should only enter when its information can contribute to the security assessment.

## 9. Design rule

> **Phobos is a web-security scanner for AI-enabled applications, with AI integrated as the reasoning brain.**

The fact that a target uses AI determines whether Phobos should engage. It does **not** restrict Phobos to AI vulnerabilities. Once engaged, Phobos should look for the full range of relevant web-security flaws as well as AI-specific flaws.
