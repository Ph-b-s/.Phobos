# Phobos Desktop Architecture

## Product boundary

The desktop application is the primary Phobos product shell. The GUI does not implement security logic itself. It owns the user-facing scan lifecycle and composes the same services used by the scanner core.

```text
PHOBOS DESKTOP
      │
      ▼
Application Services
      │
 ┌────┼───────────────┐
 ▼    ▼       ▼       ▼
HTTP Browser Identity Workflow
 │      │       │       │
 └──────┴───────┴───────┘
             │
             ▼
      Attack-Surface Model
             │
             ▼
        AI Security Brain
             │
             ▼
        Module Runner
             │
             ▼
 Evidence → Correlation → Findings
```

## Runtime services

`app_services.py` is the composition boundary for one scan session. It owns the scope validator, request manager, browser session, high-level browser interactor, account manager, workflow engine, and discovered supporting applications.

Security modules receive these capabilities through `ModuleContext`; they must not construct their own HTTP clients, browser sessions, or identity stores.

## Desktop responsibilities

`desktop_app.py` is responsible for:

- target and scope input
- starting and stopping a scan worker without freezing the UI
- progress/activity reporting
- high-level scan metrics
- surfacing findings and scan state
- presenting the application architecture

The desktop application deliberately delegates discovery, correlation, workflows, identity, and module execution to the core services.

## Long-term UI model

The current shell is the foundation for the full desktop product. The intended application views are:

```text
Dashboard
Scans
Attack Surface
Workflows
Findings
Modules
Settings
```

All views should read from the same scan/session state rather than maintaining separate scanner implementations.

## Distribution

The desktop target uses PySide6. Qt for Python provides the native Qt bindings, while PyInstaller is intended for later distribution builds. Windows, macOS, and Linux builds must be produced on their respective platforms; PyInstaller is not a cross-compiler.

The eventual production installer will bundle the Phobos application, its Python runtime, browser dependencies, and the managed local AI runtime so that a normal user can launch Phobos without separately installing Python or configuring an AI service.

## Extension rule

Every future subsystem should answer one question before implementation:

> What application service does this belong to?

Examples:

- authenticated sessions → Identity / Browser services
- email-client workflows → Workflow / Cross-application services
- vulnerability checks → Module Runner
- attack-path reasoning → Cross-layer service
- model selection/runtime → AI service
- reports → Scan/session state and evidence services

This prevents the desktop application from becoming a second implementation of Phobos internals.
