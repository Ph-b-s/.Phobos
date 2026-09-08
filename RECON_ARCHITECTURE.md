# Phobos Reconnaissance Architecture

Phobos is being built as a security testing framework, not as a collection of independent scanners. Every discovery mechanism should produce structured information that can be connected to the same target model.

## 1. Target and scope

The user supplies an authorized target and an explicit scope policy.

```text
Target URL / host
        |
        v
   Scope Validator
        |
   +----+----+
   |         |
 allowed   rejected
```

Nothing below this layer should invent a new target or bypass the scope boundary.

## 2. Network discovery

Nmap is a useful part of the foundation. It answers a different question from the web crawler:

> What network services are exposed by this host?

The current Nmap primitive performs bounded TCP discovery of the top 100 ports and returns normalized open-port observations. It does not run through a shell and does not accept arbitrary port expressions from higher-level automation.

The intended role is:

```text
Host
 |
 +--> Nmap
       |
       +--> open port
       +--> protocol
       +--> service hint
       +--> product/version hint
```

Nmap findings should enrich the attack-surface graph rather than become an isolated report.

For example:

```text
website: lab.example
        |
        +-- exposes --> tcp/443
        |               |
        |               +-- service --> https
        |
        +-- exposes --> tcp/22
                        |
                        +-- service --> ssh
```

An open port is not itself a vulnerability. It is an observation used to decide what should be inspected next.

## 3. Web discovery

The crawler works from HTTP(S) targets and discovers:

```text
pages
links
forms
inputs
JavaScript
API routes
query parameters
AI-related signals
```

JavaScript route discovery is passive. The purpose is to reveal application functionality that is not represented by ordinary HTML links.

## 4. Service-to-application correlation

This is the important next design step.

Network discovery and web discovery should converge into one graph:

```text
                 +----------------+
                 | Target Website |
                 +-------+--------+
                         |
                 +-------+-------+
                 |               |
              Network           Web
             discovery       discovery
                 |               |
              ports         pages/endpoints
                 |               |
                 +-------+-------+
                         |
                    Attack Graph
```

Later, the graph should be capable of representing:

```text
host
  -> port
  -> service
  -> HTTP endpoint
  -> authentication boundary
  -> application input
  -> AI surface
  -> AI agent
  -> tool/API
  -> resource
```

## 5. Assessment procedures

A procedure is a reusable investigation, not a payload.

A procedure should define:

```text
Prerequisites
Discovery requirements
Required observations
Safe probe
Expected evidence
Positive confirmation
Impact validation
```

For the first PortSwigger AI-security work, procedures should be derived from the vulnerability class and then exercised against the lab target. Lab-specific URLs, strings, and ordering should live in test fixtures, not in the procedure itself.

## 6. Execution adapters

The procedure should never directly know how to drive a browser or construct low-level network traffic.

Instead:

```text
Procedure
   |
   v
Assessment Engine
   |
   v
Execution Adapter
   |
   +--> HTTP
   +--> Browser
   +--> future structured tool observation
```

This lets the same security procedure be reused across different targets and execution mechanisms.

## 7. Evidence and correlation

Observations are the bridge between execution and findings.

A useful finding should be reconstructable:

```text
source
  -> transformation
  -> model interaction
  -> observed behavior
  -> security consequence
```

For AI vulnerabilities, this is more important than matching a suspicious string. Phobos should prefer reproducible relationships over lexical guesses.

## 8. The first real target workflow

For a PortSwigger lab, the intended progression is:

```text
1. Enter lab target + scope
2. Discover host/network exposure
3. Discover web application surface
4. Build the unified graph
5. Identify relevant AI surface
6. Select applicable assessment procedure
7. Capture a clean baseline
8. Perform the smallest safe active probe
9. Compare observations
10. Confirm only with sufficient evidence
11. Produce a reproducible finding
```

The first implementation milestone is therefore not "make Phobos autonomous." It is:

> Given one authorized PortSwigger lab, Phobos should build a useful attack-surface model and execute one narrowly scoped security procedure against it.

## 9. Long-term module boundaries

The flat repository can remain physically flat while keeping strong logical boundaries:

```text
Scope / Policy
      |
      +--> Network Discovery
      |
      +--> Web Discovery
      |
      +--> AI Surface Discovery
      |
      v
Attack-Surface Graph
      |
      v
Assessment Procedures
      |
      v
Assessment Engine
      |
      v
Execution Adapters
      |
      v
Observations / Evidence
      |
      v
Finding / Report
```

That architecture keeps Phobos focused on the actual security question: how an attacker-controlled input can move through a real application and cross a trust boundary.