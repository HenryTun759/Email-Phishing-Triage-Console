from dataclasses import dataclass

SEVERITIES = {"info", "low", "medium", "high"}

@dataclass(frozen=True)
class FindingData:
    check_id: str
    title: str
    severity: str
    evidence: str
    remediation: str

class ScannerCheck:
    check_id = "base"
    def run(self, host: str, port: int, timeout: float) -> list[FindingData]:
        raise NotImplementedError
