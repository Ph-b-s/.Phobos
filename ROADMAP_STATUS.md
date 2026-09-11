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
- [x] Configurable protected-data disclosure test
- [x] Configurable AI output-handling probe
- [x] Configurable goal-hijacking marker test
- [x] Configurable context-manipulation marker test
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
- [x] AI/Web identifier trust-boundary follow-up signals
- [x] Tool/RAG authorization and data-flow follow-up signals
- [x] Object-authorization findings feeding shared evidence state

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
- [x] OpenAPI/Swagger surface discovery
- [x] Redirect-parameter/open-redirect candidate discovery
- [x] JavaScript source-map exposure discovery
- [x] Sensitive input-name inventory without value storage
- [x] Reflected XSS signal detection
- [x] Error-based SQL injection signal detection
- [x] Bounded NoSQL operator differential testing
- [x] Passive CSRF protection analysis
- [x] Client-side JavaScript source/sink analysis
- [x] JWT-like token analysis with token redaction
- [x] GraphQL introspection analysis
- [x] GraphQL authorization-sensitive surface discovery
- [x] Configured read-only GraphQL low/high-privilege authorization comparison
- [x] Low-impact SSTI arithmetic probes
- [x] Host-header trust signal analysis
- [x] Cache-policy / untrusted-reflection analysis
- [x] Configured authentication workflow bootstrap
- [x] Configured low/high-privilege authorization comparison
- [x] Configured object-level authorization comparison for explicit owned/peer pairs
- [x] Bounded path-traversal marker checks
- [x] Passive file-upload validation analysis
- [x] WebSocket endpoint discovery without active message exchange
- [x] WebSocket authentication-signal inventory
- [x] SSRF sink discovery
- [x] Command-execution sink discovery
- [x] XML-processing surface discovery
- [x] Serialization/deserialization surface discovery
- [x] Business-logic workflow candidate discovery

### Remaining major procedures
- [ ] Active SSRF validation
- [ ] Active command-injection validation
- [ ] Active XXE validation
- [ ] Active unsafe-deserialization validation
- [ ] Cache poisoning/deception confirmation
- [ ] HTTP request smuggling confirmation
- [ ] JWT signing/claim validation beyond passive analysis
- [ ] Broader GraphQL query authorization/abuse testing beyond configured read-only role comparison
- [ ] Active WebSocket authentication/authorization/message testing
- [ ] Race-condition testing
- [ ] Business-logic workflow abuse
- [ ] Full authorization/IDOR object-level testing beyond explicitly configured object-pair comparison

## AI Security Procedures

### Implemented
- [x] Direct prompt-injection canary procedure
- [x] Indirect prompt-injection procedure
- [x] System-prompt marker disclosure procedure
- [x] Protected-data disclosure marker procedure
- [x] AI output-handling render probe
- [x] Goal-hijacking marker procedure
- [x] Context-manipulation marker procedure
- [x] AI tool-surface discovery
- [x] RAG/retrieval surface discovery
- [x] Vector/embedding surface discovery
- [x] Untrusted AI-context source discovery
- [x] AI resource-control visibility analysis
- [x] Multi-agent surface discovery
- [x] AI memory/persistent-context surface discovery
- [x] AI identity/privilege boundary discovery
- [x] AI/Web trust-boundary identifier correlation
- [x] Tool/RAG compound trust-boundary discovery

### Remaining major procedures
- [ ] Active tool-abuse validation
- [ ] Active excessive-agency validation
- [ ] Active RAG authorization/grounding testing
- [ ] Active vector-store isolation testing
- [ ] Active AI data-poisoning validation
- [ ] Resource/cost abuse confirmation
- [ ] Active multi-agent trust-boundary testing
- [ ] Full sensitive-information disclosure testing beyond configured markers

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

The vulnerability catalog intentionally distinguishes **surface identification** from **active vulnerability confirmation**. Passive modules may identify a high-value sink and create a bounded follow-up signal without claiming exploitation. A module is marked `implemented=True` only when it has a registered handler, deterministic evidence logic, and regression coverage. Configuration-dependent authorization modules never invent credentials, selectors, object identifiers, or privilege assumptions.
