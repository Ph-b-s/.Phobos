# Phobos Reconnaissance Architecture

Phobos is a web and AI security testing framework. Reconnaissance should build one useful target model; individual discovery techniques are modules that feed it.

## 1. Target and scope

The user supplies an authorized target and explicit scope. All discovery modules operate inside that boundary.

```text
Target
  ↓
Scope Validator
  ↓
Discovery modules
```

Nothing below this layer may invent a new target or bypass scope enforcement.

## 2. Discovery modules

The core focus is web and AI security. Nmap is an **optional reconnaissance module**, not a separate scanning subsystem.

```text
                 Reconnaissance
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        Web           AI          Nmap
     discovery     discovery     module
          │            │            │
          └────────────┴────────────┘
                       ▼
                 Attack Graph
```

### Web discovery

The crawler discovers:

```text
pages
links
forms
inputs
JavaScript
API routes
query parameters
```

### AI-surface discovery

AI discovery adds passive signals for likely:

```text
AI endpoints
providers
agent/tool interfaces
AI-oriented inputs
```

These are indicators, not findings.

### Nmap module

Nmap answers one narrow question:

> Which common TCP services are exposed by the target host?

Its output is normalized into simple `port` assets so it can appear in the same graph as web assets.

The intended relationship is deliberately small:

```text
Target host
    │
    └── exposes ──> tcp/443
                       │
                       └── service: https
```

Nmap does **not** control the crawler, choose vulnerabilities, or become a second orchestration layer. Its results simply provide additional context for later testing.

## 3. Unified attack-surface model

All discovery modules feed the same graph:

```text
Target
  │
  ├── exposes ──> Port
  │
  └── hosts ────> Web application
                    │
                    ├── contains ──> Page
                    ├── contains ──> Form
                    ├── links ─────> Endpoint
                    ├── loads ─────> JavaScript
                    └── signals ───> AI surface
```

The graph is deliberately richer than a flat list but remains simple enough to support the first real PortSwigger tests.

## 4. Testing layer

After discovery, Phobos selects a vulnerability-specific procedure.

```text
Attack Graph
     ↓
Applicable procedure
     ↓
Assessment Engine
     ↓
HTTP / Browser adapter
     ↓
Observations
     ↓
Evidence correlation
     ↓
Finding
```

A procedure describes an investigation and confirmation logic. It should not contain lab-specific URLs or depend on Nmap being present unless the vulnerability actually requires that information.

## 5. First real target workflow

For the first PortSwigger lab work, the intended flow is:

```text
1. Enter lab target + scope
2. Run normal web reconnaissance
3. Optionally run the Nmap module
4. Merge discovered assets into the graph
5. Identify the relevant attack surface
6. Select one narrow assessment procedure
7. Execute the smallest useful probe
8. Capture evidence
9. Confirm the vulnerability
10. Produce a reproducible finding
```

Nmap is therefore a **supporting module** in step 3, not the center of the workflow.

## 6. Long-term boundaries

The repository can stay physically flat while keeping these logical responsibilities:

```text
Scope / Policy
      │
      ├── Web Discovery
      ├── AI Surface Discovery
      └── Nmap Module (optional)
                  │
                  ▼
          Attack-Surface Graph
                  │
                  ▼
         Assessment Procedures
                  │
                  ▼
          Assessment Engine
                  │
                  ▼
       Execution Adapters
                  │
                  ▼
       Observations / Evidence
                  │
                  ▼
             Findings
```

The guiding principle is simple: **Nmap enriches Phobos; it does not redefine Phobos.**
