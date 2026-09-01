# Phobos

**AI Security Reconnaissance & Attack-Surface Graph**

Phobos is an extensible framework for authorized security testing of web applications and AI systems. The first build establishes the core that every later module will use: scoped HTTP traffic, normalized assets, an execution graph, and evidence-backed scan state.

## First Build

```text
Target URL
    │
    ▼
   CLI
    │
    ▼
 Configuration
    │
    ▼
 Scope Validator
    │
    ▼
 Request Manager ──────► HTTP
    │
    ▼
 Unified Asset Model
    │
    ▼
 Graph Engine
    │
    ▼
 Evidence Storage
```

Every outbound request passes through the centralized scope validator. Redirects are stopped and re-validated before another network request is made.

## Repository Structure

```text
.phobos/
├── phobos/
│   ├── cli/
│   │   └── main.py
│   ├── core/
│   │   ├── config.py
│   │   ├── models.py
│   │   ├── request_manager.py
│   │   └── scope.py
│   ├── graph/
│   │   ├── graph.py
│   │   └── nodes.py
│   └── storage/
│       └── evidence.py
├── tests/
├── pyproject.toml
└── README.md
```

## CLI

```bash
pip install -e .
phobos scan https://example.com
phobos scan https://example.com --scope example.com --output .phobos
```

A scan currently establishes the target, validates scope, performs the first HTTP request, creates the initial website/page assets and graph relationship, and writes:

```text
.phobos/
├── scan.json
├── assets.json
├── graph.json
├── findings.json
└── evidence/
```

The crawler is the next layer. It will populate the same asset and graph model with pages, links, forms, inputs, APIs and JavaScript references rather than introducing a second data model.

## Tests

```bash
python -m pytest
```

Only test systems you own or are explicitly authorized to assess.
