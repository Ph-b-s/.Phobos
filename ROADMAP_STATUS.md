# Phobos Roadmap Status

This document records the implementation state of the product roadmap on the `flat-structure` branch.

## Phase 1 — Foundation

- [x] CLI and configuration
- [x] Central scope validation
- [x] Scope-aware HTTP transport with redirect re-validation and DNS pinning
- [x] Bounded evidence storage
- [x] Registry-driven module architecture
- [x] Shared knowledge store
- [x] Explicit execution limits
- [x] Optional local browser runtime
- [x] Optional local Mistral planning runtime

## Phase 2 — Web Recon

- [x] HTML crawling
- [x] Endpoint discovery
- [x] Form/input discovery
- [x] Embedded API discovery
- [x] JavaScript source discovery
- [x] Dynamic browser DOM discovery
- [x] Browser network observations
- [x] Cross-application candidate discovery

## Phase 3 — AI Discovery

- [x] Passive AI endpoint detection
- [x] Provider hints
- [x] Agent/tool hints
- [x] AI input-surface detection
- [x] Confidence-bearing AI surface assets
- [x] AI evidence carried into the shared knowledge store

## Phase 4 — Controlled AI Testing

- [x] Assessment procedure abstraction
- [x] Bounded assessment engine
- [x] Evidence-driven analyzer
- [x] Explicit state-change gate
- [x] Configurable indirect prompt-injection procedure
- [x] Configurable direct prompt-injection canary
- [x] Configurable system-prompt marker disclosure test
- [x] Browser-backed execution adapter

## Phase 5 — Indirect Injection Tracking

- [x] Unique canary generation/validation
- [x] Controlled content seeding
- [x] Baseline vs induced comparison
- [x] Canary observation
- [x] Optional impact-validation step
- [x] Structured findings and evidence

## Phase 6 — Execution Graph

- [x] Typed graph nodes and edges
- [x] Web/AI relationship modelling
- [x] Bounded path discovery
- [x] Confidence-bearing attack paths
- [x] Shared graph serialization
- [x] Cross-layer observations attached to graph assets

## Phase 7 — Chaining Engine

- [x] Web → AI path correlation
- [x] AI → Web path correlation
- [x] Finding/evidence bridges
- [x] Bounded follow-up candidates
- [x] Separate confidence from severity
- [x] Cross-layer module runner integration

## Web Security Procedures

### Implemented

- [x] Security headers baseline
- [x] Cookie security baseline
- [x] Common exposure checks
- [x] HTTP method checks
- [x] Configuration disclosure checks
- [x] CORS policy checks
- [x] Information-disclosure pattern detection with evidence redaction
- [x] API baseline analysis
- [x] Reflected XSS signal detection
- [x] Error-based SQL injection signal detection
- [x] Passive CSRF protection analysis
- [x] Client-side JavaScript source/sink analysis
- [x] JWT-like token analysis with token redaction
- [x] GraphQL introspection analysis
- [x] Low-impact SSTI arithmetic probes
- [x] Host-header trust signal analysis
- [x] Cache-policy / untrusted-reflection analysis
- [x] Configured authentication workflow bootstrap
- [x] Configured low/high-privilege authorization comparison

### Remaining major procedures

- [ ] NoSQL injection
- [ ] SSRF
- [ ] Command injection
- [ ] Path traversal
- [ ] File-upload security
- [ ] XXE
- [ ] Unsafe deserialization
- [ ] Cache poisoning/deception confirmation
- [ ] HTTP request smuggling
- [ ] JWT signing/claim validation beyond passive header analysis
- [ ] GraphQL authorization/query abuse testing
- [ ] WebSocket security
- [ ] Race-condition testing
- [ ] Business-logic workflow abuse
- [ ] Full authorization/IDOR object-level testing beyond configured response comparison

## AI Security Procedures

### Implemented

- [x] Direct prompt-injection canary procedure
- [x] Indirect prompt-injection procedure
- [x] System-prompt marker disclosure procedure

### Remaining major procedures

- [ ] Sensitive-information disclosure testing
- [ ] Unsafe AI output handling
- [ ] Tool-abuse testing
- [ ] Excessive-agency testing
- [ ] RAG security testing
- [ ] Vector/embedding security testing
- [ ] AI data poisoning
- [ ] Resource/cost abuse testing
- [ ] Multi-agent trust-boundary testing
- [ ] Goal hijacking
- [ ] Memory/context manipulation

## Productization

- [x] Human-readable Markdown report
- [x] Deterministic scan summarizer
- [x] Iterative AI planner with a hard iteration cap
- [x] Eligibility gates for configuration-dependent modules
- [x] Optional Nmap module
- [x] Desktop application shell on shared application services
- [x] Automated test suite and CI definition
- [x] Evidence privacy safeguards for secrets and tokens

## Important implementation boundary

The vulnerability catalog remains intentionally broader than the executable procedure set. A module is marked `implemented=True` only when it has a registered handler, deterministic evidence logic, and regression coverage. Riskier classes remain explicitly unimplemented until they have a bounded execution contract and appropriate authorization/configuration gates.

This distinction is intentional: a module name in the catalog is a planned security capability; a registered, tested module with evidence logic is a shipped capability.
