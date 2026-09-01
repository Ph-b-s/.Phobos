# Phobos

**Modular AI Security Testing Framework**

Phobos is an extensible framework for authorized security testing of AI applications and agents. It combines automated scanners with a common finding model so specialized tests can be composed into larger assessments.

## Architecture

```text
Target
  │
  ▼
Phobos Engine
  ├── Scanner Registry
  ├── Scanner Modules
  │    ├── Prompt Injection
  │    ├── Agent / Tool Abuse
  │    ├── Data / Secret Leakage
  │    └── Guardrail Testing
  └── Normalized Findings
         │
         ▼
      Reporting
```

## Status

Early development. The first milestone establishes the core Python package, scanner abstraction, registry, normalized findings, CLI foundation, and tests.

## Development

Requires Python 3.11+.

```bash
python -m pytest
python -m phobos.cli scanners
```

Only test systems you own or are explicitly authorized to assess.
