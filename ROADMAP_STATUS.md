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

## Productization

- [x] Human-readable Markdown report
- [x] Deterministic scan summarizer
- [x] Iterative AI planner with a hard iteration cap
- [x] Optional Nmap module
- [x] Desktop application shell on shared application services
- [x] Automated test suite and CI definition

## Important implementation boundary

The roadmap architecture is implemented, but the vulnerability catalog remains intentionally broader than the set of executable procedures. A vulnerability module is marked `implemented=True` only when it has a registered handler and deterministic evidence logic. Advanced modules such as SQL injection, XSS, access-control testing, SSRF, tool abuse, RAG security, and similar procedures therefore remain explicit implementation backlog items rather than being represented as finished capabilities.

This distinction is intentional: a module name in the catalog is a planned security capability; a registered module with tests and evidence logic is a shipped capability.
