import ssl
import urllib.request
from .base import FindingData, ScannerCheck

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("high", "Enable HSTS on HTTPS services after confirming HTTPS is fully deployed."),
    "Content-Security-Policy": ("medium", "Define a restrictive Content-Security-Policy appropriate for the application."),
    "X-Content-Type-Options": ("low", "Set X-Content-Type-Options to nosniff."),
    "Referrer-Policy": ("low", "Set an explicit restrictive Referrer-Policy."),
}

class HttpSecurityCheck(ScannerCheck):
    check_id = "http-headers"
    def run(self, host: str, port: int, timeout: float):
        findings = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}:{port}/"
            try:
                ctx = ssl.create_default_context() if scheme == "https" else None
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "LabVuln/1.0 authorized-lab-scanner"})
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                    headers = response.headers
                    for header, (severity, remediation) in SECURITY_HEADERS.items():
                        if header not in headers:
                            findings.append(FindingData(f"{self.check_id}:{header.lower()}", f"Missing {header}", severity, f"{url} did not return {header}", remediation))
                    server = headers.get("Server")
                    if server:
                        findings.append(FindingData("http-server-header", "Server header disclosed", "low", f"Server: {server[:200]}", "Minimize unnecessary server/version disclosure."))
                return findings
            except Exception:
                continue
        return findings
