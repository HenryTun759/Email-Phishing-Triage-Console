from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .config import settings
from .models import Finding, Scan
from .cvss import score_for_check
from .scanner.engine import run_scan
from .scanner.safety import is_allowed_host

def now():
    return datetime.now(timezone.utc)

def execute_scan(db: Session, scan_id: int):
    scan = db.get(Scan, scan_id)
    if not scan:
        return
    target = scan.target
    scan.status = "running"
    scan.started_at = now()
    db.commit()
    try:
        if not is_allowed_host(target.host, settings.allow_public_targets, target.authorized):
            raise ValueError("Target is outside the lab safety boundary")
        results = run_scan(target.host, target.port, settings.scan_timeout_seconds)
        for item in results:
            cvss, severity, vector = score_for_check(item.check_id)
            db.add(Finding(scan_id=scan.id, check_id=item.check_id, title=item.title,
                           severity=severity if cvss > 0 else item.severity,
                           cvss_score=cvss, cvss_vector=vector,
                           evidence=item.evidence[:4000], remediation=item.remediation[:4000]))
        scan.status = "completed"
    except Exception as exc:
        scan.status = "failed"
        scan.error = str(exc)[:1000]
    scan.finished_at = now()
    db.commit()
