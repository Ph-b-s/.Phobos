"""Native Phobos desktop application.

The GUI is a product shell around the same application services used by the
scanner. Long-running scans execute outside the Qt UI thread and report bounded
progress/events back to the interface. The window deliberately contains no
scanner-specific attack logic; new capabilities belong in the core services and
appear here through their state and events.
"""
from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass
from typing import Any

try:
    from PySide6 import QtCore, QtGui, QtWidgets
except ImportError as exc:  # pragma: no cover - exercised only without the optional UI dependency
    raise SystemExit(
        "PySide6 is required for the Phobos desktop application. "
        "Install the 'desktop' optional dependency."
    ) from exc

from app_services import PhobosServices, create_services, execute_scan
from config import PHOBOS_VERSION
from cross_application import discover_related_applications
from cross_layer import analyze_cross_layer
from evidence import EvidenceStore
from graph import Graph
from knowledge_store import KnowledgeStore, SecurityObservation
from models import Asset, AssetType
from scanner import default_module_selection
from crawler import ReconCrawler


@dataclass(frozen=True, slots=True)
class DesktopScanSummary:
    target: str
    pages: int
    endpoints: int
    ai_surfaces: int
    cross_layer_paths: int
    applications: int
    modules_completed: int
    findings: int
    errors: int


class ScanWorker(QtCore.QThread):
    """Run one scan outside the Qt event loop."""

    progress = QtCore.Signal(int, str)
    result = QtCore.Signal(object)
    failed = QtCore.Signal(str)
    finished_cleanly = QtCore.Signal()

    def __init__(self, target: str, scopes: tuple[str, ...], *, browser: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.target = target
        self.scopes = scopes
        self.browser_enabled = browser

    def run(self) -> None:  # noqa: D401
        services: PhobosServices | None = None
        try:
            self.progress.emit(5, "Preparing scoped application services")
            services = create_services(self.target, self.scopes, browser=self.browser_enabled)
            self.progress.emit(12, "Discovering the application")

            output = EvidenceStore(".phobos")
            output.initialize()
            graph = Graph()
            website = Asset(
                "website_001",
                AssetType.WEBSITE,
                self.target,
                self.target,
                metadata={"scopes": list(services.scope.allowed_domains)},
            )
            graph.add_node(id=website.id, type=website.type.value, label=website.name, attributes=website.metadata)

            recon = ReconCrawler(
                services.requests,
                max_pages=100,
                max_discovered_urls=5_000,
                browser=services.browser,
            ).crawl(self.target, graph=graph)
            self.progress.emit(42, "Building the attack-surface model")

            assets = (website, *recon.assets)
            services.discover_supporting_apps(
                tuple(asset.url for asset in recon.pages if asset.url),
                pages=tuple({"url": asset.url, "text": asset.name} for asset in recon.pages[:100]),
            )
            if services.applications:
                from cross_application import merge_applications_into_graph
                merge_applications_into_graph(graph, website.id, services.applications)

            store = KnowledgeStore()
            store.add_assets(assets)
            for asset in assets:
                if asset.type in {
                    AssetType.PAGE,
                    AssetType.ENDPOINT,
                    AssetType.API,
                    AssetType.FORM,
                    AssetType.INPUT,
                    AssetType.JAVASCRIPT,
                }:
                    store.add_observation(
                        SecurityObservation(
                            id=f"recon.web:{asset.id}",
                            kind=f"recon.web.{asset.type.value}",
                            source="recon.web",
                            description=f"Web reconnaissance discovered {asset.type.value}: {asset.name}",
                            asset_ids=(asset.id,),
                            data={"url": asset.url},
                            confidence=asset.confidence,
                        )
                    )
            for asset in recon.ai_surfaces:
                store.add_observation(
                    SecurityObservation(
                        id=f"recon.ai:{asset.id}",
                        kind="recon.ai_surface",
                        source="recon.ai",
                        description=f"Passive reconnaissance identified a likely AI surface: {asset.name}",
                        asset_ids=(asset.id,),
                        data={"url": asset.url},
                        confidence=asset.confidence,
                    )
                )

            self.progress.emit(55, "Running the module pipeline")
            plan = default_module_selection()
            scan = execute_scan(
                services,
                assets,
                plan,
                knowledge=store,
                graph=graph,
                metadata={"desktop": True, "browser_enabled": self.browser_enabled},
            )

            self.progress.emit(86, "Correlating evidence across the application")
            analysis = analyze_cross_layer(graph, scan.knowledge)
            output.write_json("desktop_scan.json", {
                "schema_version": "1.0",
                "target": self.target,
                "summary": {
                    "pages": len(recon.pages),
                    "endpoints": len(recon.endpoints),
                    "ai_surfaces": len(recon.ai_surfaces),
                    "applications": len(services.applications),
                    "cross_layer_paths": len(analysis.attack_paths),
                    "modules_completed": len(scan.modules_run),
                    "findings": len(scan.findings),
                    "errors": len(scan.errors),
                },
            })
            output.write_json("cross_layer.json", analysis.to_dict())
            output.write_json("module_run.json", scan.module_run.to_dict())
            output.write_json("knowledge.json", scan.knowledge.to_dict())
            output.write_json("findings.json", [item.to_dict() for item in scan.findings])

            summary = DesktopScanSummary(
                self.target,
                len(recon.pages),
                len(recon.endpoints),
                len(recon.ai_surfaces),
                len(analysis.attack_paths),
                len(services.applications),
                len(scan.modules_run),
                len(scan.findings),
                len(scan.errors),
            )
            self.progress.emit(100, "Scan complete")
            self.result.emit(summary)
            self.finished_cleanly.emit()
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc(limit=5)}")
        finally:
            if services is not None:
                services.close()


class PhobosWindow(QtWidgets.QMainWindow):
    """Main Phobos desktop shell."""

    def __init__(self) -> None:
        super().__init__()
        self.worker: ScanWorker | None = None
        self._apply_window()
        self._build_ui()
        self._apply_theme()

    def _apply_window(self) -> None:
        self.setWindowTitle(f"Phobos {PHOBOS_VERSION}")
        self.resize(1440, 900)
        self.setMinimumSize(1080, 720)
        self.setWindowIcon(QtGui.QIcon())

    def _build_ui(self) -> None:
        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        layout = QtWidgets.QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        sidebar = QtWidgets.QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(250)
        side = QtWidgets.QVBoxLayout(sidebar)
        side.setContentsMargins(20, 24, 20, 20)
        side.setSpacing(10)

        brand = QtWidgets.QLabel("PHOBOS")
        brand.setObjectName("brand")
        version = QtWidgets.QLabel(f"AI SECURITY PLATFORM  ·  {PHOBOS_VERSION}")
        version.setObjectName("version")
        side.addWidget(brand)
        side.addWidget(version)
        side.addSpacing(22)

        self.nav_scan = self._nav_button("New Scan")
        self.nav_scans = self._nav_button("Scans")
        self.nav_modules = self._nav_button("Modules")
        self.nav_settings = self._nav_button("Settings")
        for button in (self.nav_scan, self.nav_scans, self.nav_modules, self.nav_settings):
            side.addWidget(button)
        side.addStretch(1)
        status = QtWidgets.QLabel("LOCAL ENGINE\nREADY")
        status.setObjectName("engine_status")
        side.addWidget(status)
        layout.addWidget(sidebar)

        content = QtWidgets.QFrame()
        content_layout = QtWidgets.QVBoxLayout(content)
        content_layout.setContentsMargins(36, 30, 36, 30)
        content_layout.setSpacing(22)

        header = QtWidgets.QHBoxLayout()
        title_box = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel("Security workspace")
        title.setObjectName("page_title")
        subtitle = QtWidgets.QLabel("Discover · reason · test · correlate")
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch(1)
        content_layout.addLayout(header)

        target_card = QtWidgets.QFrame()
        target_card.setObjectName("card")
        form = QtWidgets.QGridLayout(target_card)
        form.setContentsMargins(22, 20, 22, 20)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(12)
        target_label = QtWidgets.QLabel("Target")
        target_label.setObjectName("field_label")
        self.target_input = QtWidgets.QLineEdit()
        self.target_input.setPlaceholderText("https://target.example")
        self.target_input.returnPressed.connect(self.start_scan)
        scope_label = QtWidgets.QLabel("Scope")
        scope_label.setObjectName("field_label")
        self.scope_input = QtWidgets.QLineEdit()
        self.scope_input.setPlaceholderText("target.example, api.target.example")
        self.scope_input.returnPressed.connect(self.start_scan)
        self.scan_button = QtWidgets.QPushButton("Start scan")
        self.scan_button.setObjectName("primary")
        self.scan_button.clicked.connect(self.start_scan)
        form.addWidget(target_label, 0, 0)
        form.addWidget(self.target_input, 0, 1, 1, 2)
        form.addWidget(scope_label, 1, 0)
        form.addWidget(self.scope_input, 1, 1)
        form.addWidget(self.scan_button, 1, 2)
        content_layout.addWidget(target_card)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        content_layout.addWidget(self.progress)

        stats = QtWidgets.QHBoxLayout()
        self.stat_cards = {}
        for key, label in (
            ("pages", "Pages"),
            ("endpoints", "Endpoints"),
            ("ai", "AI surfaces"),
            ("paths", "Attack paths"),
            ("findings", "Findings"),
        ):
            card = QtWidgets.QFrame()
            card.setObjectName("metric")
            box = QtWidgets.QVBoxLayout(card)
            number = QtWidgets.QLabel("—")
            number.setObjectName("metric_value")
            name = QtWidgets.QLabel(label.upper())
            name.setObjectName("metric_label")
            box.addWidget(number)
            box.addWidget(name)
            stats.addWidget(card)
            self.stat_cards[key] = number
        content_layout.addLayout(stats)

        lower = QtWidgets.QHBoxLayout()
        self.activity = QtWidgets.QPlainTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setPlaceholderText("Phobos activity will appear here during scans.")
        self.activity.setObjectName("activity")
        lower.addWidget(self.activity, 2)

        side_info = QtWidgets.QFrame()
        side_info.setObjectName("card")
        info_layout = QtWidgets.QVBoxLayout(side_info)
        info_layout.setContentsMargins(20, 20, 20, 20)
        info_title = QtWidgets.QLabel("Architecture")
        info_title.setObjectName("card_title")
        architecture = QtWidgets.QLabel(
            "WEB TARGET\n"
            "↓\n"
            "ATTACK-SURFACE GRAPH\n"
            "↓\n"
            "AI SECURITY BRAIN\n"
            "↓\n"
            "MODULE RUNNER\n"
            "↓\n"
            "EVIDENCE + CORRELATION\n"
            "↓\n"
            "NEXT TEST"
        )
        architecture.setObjectName("architecture")
        architecture.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        info_layout.addWidget(info_title)
        info_layout.addWidget(architecture, 1)
        lower.addWidget(side_info, 1)
        content_layout.addLayout(lower, 1)

        self.statusBar().showMessage("Ready")
        layout.addWidget(content, 1)

    @staticmethod
    def _nav_button(text: str) -> QtWidgets.QPushButton:
        button = QtWidgets.QPushButton(text)
        button.setObjectName("nav")
        button.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        return button

    def _apply_theme(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QWidget { background: #0d1014; color: #e8edf2; font-family: Segoe UI, Arial; }
            #sidebar { background: #090b0e; border-right: 1px solid #20262d; }
            #brand { font-size: 28px; font-weight: 800; letter-spacing: 3px; }
            #version, #engine_status, #metric_label, #field_label { color: #7f8a96; font-size: 11px; letter-spacing: 1px; }
            #nav { text-align: left; padding: 12px 14px; background: transparent; border: none; border-radius: 8px; color: #9da8b3; font-size: 14px; }
            #nav:hover { background: #151a20; color: #ffffff; }
            #page_title { font-size: 30px; font-weight: 700; }
            #page_subtitle { color: #7f8a96; font-size: 13px; }
            #card, #metric { background: #12161b; border: 1px solid #232b33; border-radius: 12px; }
            #metric { min-width: 150px; }
            #metric_value { font-size: 30px; font-weight: 700; }
            #card_title { font-size: 14px; font-weight: 700; }
            #architecture { color: #9da8b3; line-height: 1.5; }
            QLineEdit { background: #0b0e12; border: 1px solid #29313a; border-radius: 8px; padding: 11px 12px; color: #f4f7fa; }
            QLineEdit:focus { border: 1px solid #6e7b88; }
            #primary { background: #e8edf2; color: #0d1014; border: none; border-radius: 8px; padding: 11px 18px; font-weight: 700; }
            #primary:hover { background: #ffffff; }
            #primary:disabled { background: #363d45; color: #89939d; }
            QProgressBar { background: #171c22; border: none; border-radius: 5px; height: 8px; }
            QProgressBar::chunk { background: #dbe2e8; border-radius: 5px; }
            #activity { background: #0b0e12; border: 1px solid #232b33; border-radius: 12px; padding: 12px; color: #b7c0c9; font-family: Consolas, monospace; }
            QStatusBar { background: #090b0e; color: #7f8a96; }
            """
        )

    @QtCore.Slot()
    def start_scan(self) -> None:
        target = self.target_input.text().strip()
        if not target:
            self.activity.appendPlainText("[error] Enter a target URL.")
            return
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        raw_scopes = [item.strip() for item in self.scope_input.text().split(",") if item.strip()]
        if not raw_scopes:
            from urllib.parse import urlparse
            host = urlparse(target).hostname
            raw_scopes = [host] if host else []
        if not raw_scopes:
            self.activity.appendPlainText("[error] A valid target hostname is required.")
            return
        if self.worker is not None and self.worker.isRunning():
            return

        self.activity.clear()
        self.progress.setValue(0)
        self.scan_button.setEnabled(False)
        self.statusBar().showMessage("Starting scan…")
        self.activity.appendPlainText(f"[scan] Target: {target}")
        self.activity.appendPlainText(f"[scan] Scope: {', '.join(raw_scopes)}")
        self.worker = ScanWorker(target, tuple(raw_scopes), browser=True, parent=self)
        self.worker.progress.connect(self._scan_progress)
        self.worker.result.connect(self._scan_result)
        self.worker.failed.connect(self._scan_failed)
        self.worker.finished_cleanly.connect(self._scan_finished)
        self.worker.start()

    @QtCore.Slot(int, str)
    def _scan_progress(self, percent: int, message: str) -> None:
        self.progress.setValue(percent)
        self.statusBar().showMessage(message)
        self.activity.appendPlainText(f"[{percent:3d}%] {message}")

    @QtCore.Slot(object)
    def _scan_result(self, summary: DesktopScanSummary) -> None:
        self.stat_cards["pages"].setText(str(summary.pages))
        self.stat_cards["endpoints"].setText(str(summary.endpoints))
        self.stat_cards["ai"].setText(str(summary.ai_surfaces))
        self.stat_cards["paths"].setText(str(summary.cross_layer_paths))
        self.stat_cards["findings"].setText(str(summary.findings))
        self.activity.appendPlainText(
            f"[result] {summary.modules_completed} modules completed · "
            f"{summary.findings} findings · {summary.applications} supporting apps"
        )

    @QtCore.Slot(str)
    def _scan_failed(self, message: str) -> None:
        self.progress.setValue(0)
        self.statusBar().showMessage("Scan failed")
        self.activity.appendPlainText("[error] " + message)

    @QtCore.Slot()
    def _scan_finished(self) -> None:
        self.scan_button.setEnabled(True)
        self.statusBar().showMessage("Ready")

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.worker.requestInterruption()
            self.worker.wait(2_000)
        event.accept()


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Phobos")
    app.setApplicationVersion(PHOBOS_VERSION)
    app.setOrganizationName("Phobos")
    window = PhobosWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
