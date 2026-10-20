from concurrent.futures import ThreadPoolExecutor
from .base import FindingData
from .http_checks import HttpSecurityCheck
from .tcp import TcpServiceCheck

CHECKS = [TcpServiceCheck(), HttpSecurityCheck()]

def run_scan(host: str, port: int, timeout: float, max_workers: int = 2) -> list[FindingData]:
    findings: list[FindingData] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(check.run, host, port, timeout) for check in CHECKS]
        for future in futures:
            try:
                findings.extend(future.result(timeout=timeout + 2))
            except Exception as exc:
                findings.append(FindingData("scanner-error", "Scanner check failed", "low", str(exc)[:500], "Review scanner logs and retry the authorized lab scan."))
    return findings
