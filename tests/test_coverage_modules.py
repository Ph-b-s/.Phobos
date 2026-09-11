from dataclasses import dataclass

from coverage_modules import run_web_file_upload, run_web_path_traversal, run_web_websocket
from models import Asset, AssetType


@dataclass
class Response:
    status: int
    text: str
    headers: dict[str, str] | None = None


class Requests:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if "PHOBOS_TRAVERSAL_NOT_FOUND" in url:
            return Response(200, "file: PHOBOS_TRAVERSAL_NOT_FOUND")
        return Response(200, "baseline")


def test_path_traversal_requires_marker_in_successful_changed_response():
    requests = Requests()
    asset = Asset("e1", AssetType.ENDPOINT, "download", "https://example.com/download?file=demo.txt")
    context = type("Context", (), {
        "assets": (asset,),
        "target": "https://example.com",
        "metadata": {"request_manager": requests},
    })()

    result = run_web_path_traversal(context)

    assert result.findings
    assert result.findings[0].type == "potential_path_traversal"
    assert all("PHOBOS_TRAVERSAL_NOT_FOUND" not in text for text, _ in [])


def test_file_upload_only_reports_discovered_forms_without_uploading():
    form = Asset(
        "f1", AssetType.FORM, "upload", "https://example.com/upload",
        metadata={"inputs": [{"type": "file", "name": "document"}]},
    )
    context = type("Context", (), {"assets": (form,), "metadata": {}})()

    result = run_web_file_upload(context)

    assert result.observations
    assert result.findings[0].type == "upload_validation_requires_review"


def test_websocket_discovery_does_not_connect():
    asset = Asset(
        "j1", AssetType.JAVASCRIPT, "app.js", "https://example.com/app.js",
        metadata={"source": "const socket = new WebSocket('wss://example.com/socket');"},
    )
    context = type("Context", (), {"assets": (asset,), "metadata": {}})()

    result = run_web_websocket(context)

    assert result.findings[0].type == "websocket_endpoint_detected"
    assert result.findings[0].metadata["requires_protocol_test"] is True
