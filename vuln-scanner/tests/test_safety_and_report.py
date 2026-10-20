from io import BytesIO
from types import SimpleNamespace
from app.reports import build_scan_pdf
from app.scanner.safety import is_allowed_host

def test_blocked_special_ranges(monkeypatch):
    monkeypatch.setattr("app.scanner.safety.resolve_ipv4", lambda host: "0.0.0.0")
    assert not is_allowed_host("example.invalid", True, True)

def test_pdf_report_is_generated():
    finding = SimpleNamespace(severity="medium", cvss_score=6.5, title="Missing CSP", evidence="header absent", remediation="Add CSP")
    scan = SimpleNamespace(id=1, status="completed", target=SimpleNamespace(name="Lab", host="127.0.0.1", port=8000), findings=[finding])
    pdf = build_scan_pdf(scan)
    assert isinstance(pdf, BytesIO)
    assert pdf.getvalue().startswith(b"%PDF")
