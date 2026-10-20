import httpx
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
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}:{port}/"
                try:
                    response = client.get(url, headers={"User-Agent": "LabVuln/1.1 authorized-lab-scanner"})
                    if 300 <= response.status_code < 400:
                        findings.append(FindingData("http-redirect", "HTTP redirect detected", "info", f"{url} returned {response.status_code}; redirects are not followed", "Review redirect destinations and keep them within the authorized assessment scope."))
                        continue
                    for header, (severity, remediation) in SECURITY_HEADERS.items():
                        if header not in response.headers:
                            findings.append(FindingData(f"{self.check_id}:{header.lower()}", f"Missing {header}", severity, f"{url} did not return {header}", remediation))
                    server = response.headers.get("server")
                    if server:
                        findings.append(FindingData("http-server-header", "Server header disclosed", "low", f"Server: {server[:200]}", "Minimize unnecessary server/version disclosure."))
                    return findings
                except httpx.HTTPError:
                    continue
        return findings
