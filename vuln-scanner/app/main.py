from concurrent.futures import ThreadPoolExecutor
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select
from .config import settings
from .database import Base, engine, get_db, SessionLocal
from .models import Scan, Target
from .schemas import ScanCreate, ScanOut, TargetCreate, TargetOut
from .services import execute_scan

Base.metadata.create_all(bind=engine)
app = FastAPI(title="LabVuln", version="1.0.0", description="Authorized-lab vulnerability scanner")
templates = Jinja2Templates(directory="app/templates")
executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_scans)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    targets = db.scalars(select(Target).order_by(Target.id.desc()).limit(50)).all()
    scans = db.scalars(select(Scan).options(selectinload(Scan.target)).order_by(Scan.id.desc()).limit(50)).all()
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"targets": targets, "scans": scans})

@app.post("/api/targets", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    target = Target(**payload.model_dump())
    db.add(target); db.commit(); db.refresh(target)
    return target

@app.get("/api/targets", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db)):
    return db.scalars(select(Target).order_by(Target.id.desc())).all()

@app.post("/api/scans", response_model=ScanOut, status_code=202)
def create_scan(payload: ScanCreate, background: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    if not target.authorized:
        raise HTTPException(403, "Target must be explicitly marked authorized")
    scan = Scan(target_id=target.id, status="queued")
    db.add(scan); db.commit(); db.refresh(scan)
    background.add_task(_run_background, scan.id)
    return scan

def _run_background(scan_id: int):
    with SessionLocal() as db:
        execute_scan(db, scan_id)

@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)):
    return db.scalars(select(Scan).options(selectinload(Scan.findings)).order_by(Scan.id.desc()).limit(100)).all()

@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.scalar(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan
