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

### Optional Nmap module

Nmap is one small supporting module:

```text
Target host
    ↓
Nmap
    ↓
open TCP ports / service hints
    ↓
shared asset model
```

It exists to add useful network context and potentially expose services worth investigating. It is not a second scanner core.

## 3. Attack-surface model

All discovery results use the same graph:

```text
Target
 ├── exposes → Port
 └── hosts → Web application
                ├── contains → Page
                ├── contains → Form
                ├── links → Endpoint
                ├── loads → JavaScript
                └── signals → AI Surface
```

Later relationships can extend the model to:

```text
Endpoint
   ↓
Authentication boundary
   ↓
AI interface
   ↓
Agent
   ↓
Tool / API
   ↓
Resource
```

## 4. Security-module layer

Phobos does not rely on one monolithic vulnerability scanner. Capabilities are expressed as modules with stable IDs.

The intended coverage includes:

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

network.nmap
```

The catalog is the stable contract. Individual modules can mature independently.

## 5. AI reasoning loop

The AI should not simply receive a natural-language command and choose one scanner.

The intended loop is:

```text
Recon result
    ↓
Structured target context
    ↓
AI prioritization
    ↓
Module selection
    ↓
Module execution
    ↓
New evidence
    ↓
AI reevaluates context
    ↓
Next highest-value test
```

This is the core advantage of Phobos over a conventional fixed-order scanner.

For example:

```text
1. Discover login + user-controlled parameter
2. AI prioritizes authentication and access-control checks
3. Access-control module finds an interesting object reference
4. New evidence is added
5. AI prioritizes authorization testing around that object
6. A confirmed access-control issue becomes the basis for further investigation
```

The AI should guide the sequence; deterministic modules should establish the technical evidence.

## 6. Assessment procedures

A module may contain one or more reusable assessment procedures.

A procedure defines:

```text
prerequisites
required assets
safe probe
observations to collect
confirmation logic
optional impact validation
```

A PortSwigger lab should be treated as a benchmark fixture, not as the implementation itself.

## 7. First PortSwigger milestone

The first real benchmark should prove the complete pipeline with one vulnerability class:

```text
PortSwigger lab
      ↓
Recon
      ↓
Relevant surface identified
      ↓
AI chooses / prioritizes module
      ↓
Procedure executes
      ↓
Evidence collected
      ↓
Finding confirmed
```

After that works reliably, the same architecture can be used to add more vulnerability classes.

## 8. Design rule

> **Phobos is not an AI vulnerability scanner with web features. It is a web security scanner for AI-enabled applications, with AI integrated as the reasoning brain.**

That distinction should guide every future architectural decision.
