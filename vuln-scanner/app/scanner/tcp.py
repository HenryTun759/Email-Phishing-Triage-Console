import socket
from .base import FindingData, ScannerCheck

class TcpServiceCheck(ScannerCheck):
    check_id = "tcp-service"
    def run(self, host: str, port: int, timeout: float):
        findings = []
        try:
            with socket.create_connection((host, port), timeout=timeout):
                findings.append(FindingData(self.check_id, f"TCP port {port} is reachable", "info", f"{host}:{port} accepted a TCP connection", "Restrict exposure to required networks and services."))
        except (TimeoutError, OSError):
            findings.append(FindingData(self.check_id, f"TCP port {port} is not reachable", "info", f"No TCP connection established to {host}:{port}", "No action required unless the service should be reachable."))
        return findings
