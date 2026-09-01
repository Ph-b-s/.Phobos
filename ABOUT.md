# About Phobos

## The person behind it

Phobos is being built as a practical security engineering project focused on one problem: understanding how modern AI applications actually behave as systems, not just as isolated language models.

The project combines interests in **AI security, application security, offensive security, networking, and software engineering** into one framework designed to make complex attack surfaces easier to discover, model, test, and reason about.

The goal is not to build another collection of disconnected scanners. Phobos is intended to become a framework where a discovered web input can eventually be connected to stored content, an AI agent, a tool, an API, and the resource that tool can reach — creating a usable model of the real attack path.

## What drives the project

The core idea behind Phobos is simple:

> **Map the system before you attack the model.**

That means starting with solid engineering fundamentals: strict scope control, a single request boundary, deterministic data models, evidence-backed results, and a graph that can grow as more of the target becomes known.

AI-specific testing comes after that foundation.

## Current focus

The project is currently centered on building the reconnaissance and target-graph foundation first, followed by deeper web discovery and AI-agent surface detection. Future work is intended to cover prompt injection, indirect prompt injection, tool abuse, sensitive-data exposure, guardrail testing, and multi-step attack-path analysis.

## Engineering approach

Phobos is deliberately being developed incrementally. Each layer should be useful on its own, easy to test, and strong enough to support the layer that comes next.

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

Phobos is the larger of Mars' two moons and the source of the project's identity: a name associated with proximity, observation, and an environment that is often difficult to fully understand from the surface.

For this project, the name represents the same principle applied to security: get close enough to understand the system before attempting to break it.

---

Phobos is developed for authorized security research, learning, and defensive engineering.
