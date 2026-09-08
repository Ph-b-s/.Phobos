# Phobos Module Architecture

## Purpose

Phobos scans **AI-enabled web applications**. The application exposes two target areas:

- **Web** — pages, APIs, forms, parameters, sessions, files, protocols, and web-facing services.
- **AI** — models, prompts, agents, tools, retrieval, memory, and model-mediated data flows.

Nmap is **not** a target area. It is one security-testing tool exposed through the Web module catalog.

## Target → reasoning → testing model

```text
                         AI-ENABLED WEBSITE
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
               WEB TARGET               AI TARGET
                    │                       │
                    └───────────┬───────────┘
                                ▼
                       ATTACK-SURFACE MODEL
                                │
                                ▼
                            AI "BRAIN"
                                │
                                ▼
                      VULNERABILITY TESTING
                                │
          ┌─────────────────────┼──────────────────────┐
          ▼                     ▼                      ▼
      WEB MODULES           AI MODULES          CROSS-LAYER MODULES
          │                     │                      │
          │                     │                      │
          └─────────────────────┼──────────────────────┘
                                ▼
                         EVIDENCE / FINDINGS
                                │
                                ▼
                         AI REEVALUATES
                                │
                                ▼
                     NEXT TEST / NEXT MODULE
```

## Module domains

### Web modules

Web modules test ordinary web and web-facing service security. Examples include authentication, access control, SQL injection, XSS, SSRF, CSRF, file upload, GraphQL, WebSocket, business logic, configuration, information disclosure, and **Nmap**.

`web.nmap` is a supplemental Web-domain module. It is selected and executed by the same module orchestration layer as every other security module. It must not become a separate discovery pipeline.

### AI modules

AI modules test the model/agent attack surface: direct and indirect prompt injection, system-prompt leakage, data disclosure, unsafe output handling, tool abuse, excessive agency, RAG, vector stores, data poisoning, unbounded consumption, multi-agent trust, goal hijacking, and context manipulation.

### Cross-layer modules

Cross-layer modules test failures that require reasoning across both target areas. Examples include Web-to-AI authorization mistakes, AI-controlled access to web functionality, unsafe prompt-to-web escalation, and sensitive data flowing between Web and AI contexts.

## Execution stages

The orchestration layer uses explicit stages:

1. **Web/AI assessment** — run the relevant core Web, AI, and cross-layer modules selected by the planner.
2. **Follow-up** — use evidence from the first pass to select deeper or chained tests.
3. **Supplemental** — optional supporting tools such as `web.nmap`; these run after the main Web/AI assessment and follow-up work.

This ordering is enforced by the scanner. A supplemental module cannot be placed before a later core or follow-up module.

## Important implementation rule

The module catalog is a **capability map**, not proof that every listed module already exists as runnable attack logic. A module may be documented as planned until a deterministic runner is implemented and registered.

The AI may choose only registered module IDs. It does not create arbitrary tools, shell commands, URLs, requests, or exploit code. Low-level execution remains under Phobos-controlled scope and request/browser boundaries.
