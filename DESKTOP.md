# Phobos Desktop

The desktop application is the user-facing shell around the same Phobos services used by the CLI. It runs the scan outside the Qt event loop and stores local scan artifacts in `.phobos`.

## Windows quick start

From the `flat-structure` checkout in PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_desktop.ps1
```

The script creates an isolated Python 3.11 environment, installs the desktop dependencies, installs Chromium for Playwright, and starts Phobos.

## Manual start

```powershell
py -3.11 -m venv .phobos-desktop-venv
.\.phobos-desktop-venv\Scripts\python.exe -m pip install -e ".[desktop]"
.\.phobos-desktop-venv\Scripts\python.exe -m playwright install chromium
.\.phobos-desktop-venv\Scripts\phobos-desktop.exe
```

The desktop navigation currently exposes:

- **New Scan** — the live scan workspace.
- **Scans** — loads the latest local scan summary from `.phobos/desktop_scan.json`.
- **Modules** — shows the executable security modules registered in the engine.
- **Settings** — shows the active desktop/runtime configuration and safety boundaries.

A scan also writes `findings.json`, `knowledge.json`, `module_run.json`, and `cross_layer.json` to `.phobos` for inspection.

The first desktop release intentionally stays on the existing scanner architecture. No duplicate crawling, scope, module, or evidence implementation is introduced in the GUI layer.
