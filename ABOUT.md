# About Phobos

## The project

Phobos is a practical security engineering project focused on understanding how modern web applications and AI systems behave as connected systems, not isolated components.

The framework combines **web security, AI security, offensive security, and software engineering** into one workflow designed to discover attack surfaces, model relationships, preserve evidence, and eventually test security consequences across components.

The goal is not another collection of disconnected scanners. Phobos is intended to become a framework where a discovered web input can eventually be connected to an API, an AI agent, a tool, and the resource that tool can reach — creating a usable model of the real attack path.

## Core principle

> **Map the system before you attack the model.**

That starts with solid engineering fundamentals: strict scope control, a single request boundary, deterministic data models, bounded discovery, evidence-backed results, and an execution graph that can grow as more of the target becomes known.

AI-specific testing comes after that foundation, so findings can be understood in context rather than as isolated prompt behavior.

## Current focus

The current build is centered on:

- passive web reconnaissance
- endpoint, form, input, and JavaScript discovery
- passive detection of likely AI endpoints, providers, agent signals, and AI-oriented inputs
- graph-based representation of discovered relationships
- constrained Venice AI planning that selects only predefined Phobos capabilities

The next major step is deeper AI-agent surface analysis, followed by controlled prompt-injection, tool-abuse, sensitive-data, and guardrail testing on explicitly authorized targets.

## Engineering approach

Phobos is developed incrementally. Each layer should be useful on its own, easy to test, and strong enough to support the layer that comes next.

```text
Discover
   ↓
Normalize
   ↓
Connect
   ↓
Reason
   ↓
Test
   ↓
Correlate
```

The long-term objective is a security framework that can move from **"What is here?"** to **"How are these components connected?"** and finally to **"What security consequences follow from those connections?"**

## Why the name

Phobos is the larger of Mars' two moons and the source of the project's identity: a name associated with proximity and observation of an environment that can be difficult to understand from the surface.

For this project, the name represents the same security principle: get close enough to understand the system before attempting to break it.

---

Phobos is developed for authorized security research, learning, and defensive engineering.
