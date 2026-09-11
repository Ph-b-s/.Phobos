"""User-facing launcher and lightweight navigation for the Phobos desktop app."""
from __future__ import annotations

import json
from pathlib import Path
import sys

from PySide6 import QtCore, QtWidgets

from config import PHOBOS_VERSION
from desktop_app import PhobosWindow
from security_modules import module_specs


class DesktopController:
    """Connect the existing scan workspace to usable product navigation."""

    def __init__(self, window: PhobosWindow) -> None:
        self.window = window
        self._title = window.findChild(QtWidgets.QLabel, "page_title")
        self._subtitle = window.findChild(QtWidgets.QLabel, "page_subtitle")
        window.nav_scan.clicked.connect(self.show_new_scan)
        window.nav_scans.clicked.connect(self.show_scans)
        window.nav_findings.clicked.connect(self.show_findings)
        window.nav_modules.clicked.connect(self.show_modules)
        window.nav_settings.clicked.connect(self.show_settings)

    def _page(self, title: str, subtitle: str) -> None:
        if self._title is not None:
            self._title.setText(title)
        if self._subtitle is not None:
            self._subtitle.setText(subtitle)

    def show_new_scan(self) -> None:
        self._page("Security workspace", "Discover · reason · test · correlate")
        self.window.activity.clear()
        self.window.progress.setValue(0)
        self.window.statusBar().showMessage("Ready")
        self.window.target_input.setFocus()

    def show_scans(self) -> None:
        self._page("Scan history", "Review the latest local assessment")
        self.window.activity.clear()
        report = Path(".phobos") / "desktop_scan.json"
        if not report.exists():
            self.window.activity.setPlainText("No completed desktop scan is stored yet.\n\nStart a scan to create the local history record.")
            self.window.statusBar().showMessage("No scan history")
            return
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            summary = data.get("summary", {})
            lines = [
                f"Target: {data.get('target', 'unknown')}",
                "",
                f"Pages: {summary.get('pages', 0)}",
                f"Endpoints: {summary.get('endpoints', 0)}",
                f"AI surfaces: {summary.get('ai_surfaces', 0)}",
                f"Supporting apps: {summary.get('applications', 0)}",
                f"Cross-layer paths: {summary.get('cross_layer_paths', 0)}",
                f"Modules completed: {summary.get('modules_completed', 0)}",
                f"Findings: {summary.get('findings', 0)}",
                f"Errors: {summary.get('errors', 0)}",
                "",
                "Artifacts: .phobos/desktop_scan.json, findings.json, knowledge.json, module_run.json, cross_layer.json",
            ]
            self.window.activity.setPlainText("\n".join(lines))
            self.window.statusBar().showMessage("Latest scan loaded")
        except (OSError, ValueError, TypeError) as exc:
            self.window.activity.setPlainText(f"Unable to read scan history: {type(exc).__name__}: {exc}")
            self.window.statusBar().showMessage("History error")

    def show_findings(self) -> None:
        self._page("Findings", "Evidence-backed results from the latest local scan")
        path = Path(".phobos") / "findings.json"
        self.window.activity.clear()
        if not path.exists():
            self.window.activity.setPlainText("No findings are stored yet.\n\nRun a scan to populate the findings explorer.")
            self.window.statusBar().showMessage("No findings")
            return
        try:
            findings = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(findings, list):
                raise ValueError("findings.json must contain a list")
        except (OSError, ValueError, TypeError) as exc:
            self.window.activity.setPlainText(f"Unable to read findings: {type(exc).__name__}: {exc}")
            self.window.statusBar().showMessage("Findings error")
            return

        dialog = QtWidgets.QDialog(self.window)
        dialog.setWindowTitle("Phobos Findings")
        dialog.resize(980, 620)
        layout = QtWidgets.QVBoxLayout(dialog)
        list_widget = QtWidgets.QListWidget()
        detail = QtWidgets.QPlainTextEdit()
        detail.setReadOnly(True)
        for item in findings[:256]:
            severity = str(item.get("metadata", {}).get("severity", "unknown")).upper()
            finding_type = str(item.get("type", "unknown"))
            confidence = item.get("confidence", "?")
            list_widget.addItem(f"[{severity}] {finding_type} · confidence {confidence}")

        def select(index: int) -> None:
            if not 0 <= index < len(findings):
                detail.clear()
                return
            item = findings[index]
            metadata = item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
            evidence = item.get("evidence", []) if isinstance(item.get("evidence"), list) else []
            detail.setPlainText(json.dumps({
                "id": item.get("id"),
                "type": item.get("type"),
                "confidence": item.get("confidence"),
                "severity": metadata.get("severity"),
                "status": metadata.get("status"),
                "evidence": evidence,
                "metadata": metadata,
            }, indent=2, ensure_ascii=False))

        list_widget.currentRowChanged.connect(select)
        layout.addWidget(list_widget, 2)
        layout.addWidget(detail, 1)
        if findings:
            list_widget.setCurrentRow(0)
        dialog.exec()
        self.window.statusBar().showMessage(f"{len(findings)} findings loaded")

    def show_modules(self) -> None:
        self._page("Security modules", "Registered capabilities available to the engine")
        self.window.activity.clear()
        specs = [item for item in module_specs() if item.active and item.implemented]
        lines = [f"{len(specs)} executable modules", ""]
        by_domain: dict[str, list[str]] = {}
        for spec in specs:
            by_domain.setdefault(spec.domain.value.upper(), []).append(spec.id)
        for domain, ids in by_domain.items():
            lines.append(domain)
            lines.extend(f"  • {module_id}" for module_id in sorted(ids))
            lines.append("")
        self.window.activity.setPlainText("\n".join(lines))
        self.window.statusBar().showMessage(f"{len(specs)} executable modules")

    def show_settings(self) -> None:
        self._page("Settings", "Local runtime and safety configuration")
        self.window.activity.setPlainText(
            f"Phobos {PHOBOS_VERSION}\n\n"
            "Desktop runtime\n"
            "• PySide6 UI\n"
            "• Playwright browser runtime\n"
            "• Bounded HTTP scope enforcement\n"
            "• Local evidence directory: .phobos\n\n"
            "Safety\n"
            "• Scans require an explicit target and scope\n"
            "• Higher-impact workflows remain configuration-gated\n"
            "• The AI cannot bypass module/scope controls\n\n"
            "Installation\n"
            "pip install -e .[desktop]\n"
            "phobos-desktop"
        )
        self.window.statusBar().showMessage("Settings")


def main() -> int:
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Phobos")
    app.setApplicationVersion(PHOBOS_VERSION)
    app.setOrganizationName("Phobos")
    window = PhobosWindow()
    DesktopController(window)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
