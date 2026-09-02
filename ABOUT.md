# PHOBOS

Phobos is an open-source framework for authorized, evidence-driven security testing of modern web applications and AI systems.

The project is evolving from passive reconnaissance toward an assessment engine that can discover AI attack surfaces, execute bounded vulnerability procedures, correlate evidence across requests and components, and produce defensible findings.

## Current direction

Phobos does not aim to be a collection of payloads or a thin wrapper around an LLM. Its core model is:

```text
Discover → Normalize → Connect → Probe → Validate → Correlate → Report
```

The central security object is the **attack path** across trust boundaries:

```text
untrusted input
      ↓
application state
      ↓
LLM context
      ↓
model decision
      ↓
API / tool
      ↓
privileged or security-relevant action
```

## Current implementation

The repository currently contains:

- bounded web reconnaissance
- centralized target/scope enforcement
- a normalized asset and relationship graph
- passive AI-surface discovery
- constrained AI-assisted reconnaissance planning
- evidence storage
- the first evidence-driven active assessment procedure for indirect prompt injection
- regression tests for evidence correlation and false positives

The indirect-prompt-injection procedure is intentionally reusable. It models the security investigation rather than encoding a single training-lab URL, product name, user name, or magic payload.

## Assessment standard

A positive finding should be evidence-backed. In particular, indirect prompt injection should not be reported as confirmed merely because suspicious text is present or because a scanner sees a generic model response.

The current correlation layer requires a relationship between:

```text
attacker-controlled indirect source
        +
unique Phobos canary
        +
LLM interaction
        +
clean baseline comparison
        ↓
confirmed influence
```

A controlled state-changing action may then provide stronger impact evidence.

## Benchmark strategy

PortSwigger Web Security Academy labs are being used as behavioral benchmarks. The objective is to reproduce the **methodology and security reasoning** behind the labs, not their exact solutions.

For each benchmark, Phobos should be evaluated on:

1. attack-surface discovery
2. trust-boundary identification
3. procedure execution
4. evidence capture
5. vulnerability classification
6. reproducibility
7. false-positive resistance

The long-term target is a tool that can be given an authorized target and independently determine which security procedures are relevant, execute them within policy, and explain a confirmed vulnerability with an auditable evidence chain.

## Safety model

Phobos is intended for authorized testing only. Target selection and scope remain outside the AI planner's authority. Network requests pass through a centralized request boundary with scope and redirect validation, and private destinations require explicit opt-in.

Destructive or state-changing tests must be explicit, bounded, and separated from generic passive discovery.
