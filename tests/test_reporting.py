from cross_layer import CrossLayerAnalysis
from models import Asset, AssetType, Finding
from reporting import render_markdown
from scanner import ScanResult
from summarizer import summarize_scan


def test_report_contains_executive_summary_and_findings():
    scan = ScanResult(
        target="https://example.com",
        assets=(Asset("p1", AssetType.PAGE, "home", "https://example.com"),),
        findings=(Finding("f1", "test_finding", 0.95, metadata={"severity": "medium"}),),
        modules_run=("web.headers",),
    )
    analysis = CrossLayerAnalysis((), (), ())
    summary = summarize_scan(scan, analysis=analysis)
    report = render_markdown(scan, summary, analysis)
    assert "Executive summary" in report
    assert "Test Finding" in report
