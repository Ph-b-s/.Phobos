from phobos.core.models import Finding, ScanResult, Severity
from phobos.registry import ScannerRegistry


def test_scan_result_is_vulnerable_when_findings_exist():
    finding = Finding(
        scanner="test",
        category="prompt-injection",
        title="Test finding",
        severity=Severity.HIGH,
        description="A test vulnerability.",
    )
    result = ScanResult(scanner="test", target="demo", findings=(finding,))
    assert result.vulnerable is True


def test_empty_registry():
    assert ScannerRegistry().names() == ()
