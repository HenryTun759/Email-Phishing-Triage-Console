from fastapi import BackgroundTasks, Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from .auth import create_access_token, get_current_user, hash_password, verify_password
from .config import settings
from .database import Base, engine, get_db, SessionLocal
from .migrations import migrate_legacy_schema
from .models import Scan, Target, User
from .reports import build_scan_pdf
from .schemas import ScanCreate, ScanOut, TargetCreate, TargetOut, TokenOut
from .services import execute_scan

migrate_legacy_schema()
Base.metadata.create_all(bind=engine)
app = FastAPI(title="LabVuln", version="1.1.0", description="Authorized-lab vulnerability scanner")
templates = Jinja2Templates(directory="app/templates")

@app.on_event("startup")
def seed_admin():
    with SessionLocal() as db:
        if not db.scalar(select(User).where(User.username == settings.admin_username)):
            db.add(User(username=settings.admin_username, password_hash=hash_password(settings.admin_password.get_secret_value()), role="admin"))
            db.commit()

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    raw = request.cookies.get("access_token")
    if not raw: return templates.TemplateResponse(request=request, name="login.html", context={"error": None})
    try: user = get_current_user(None, raw, db)
    except HTTPException: return templates.TemplateResponse(request=request, name="login.html", context={"error": "Session expired"})
    targets = db.scalars(select(Target).order_by(Target.id.desc()).limit(50)).all()
    scans = db.scalars(select(Scan).options(selectinload(Scan.target)).order_by(Scan.id.desc()).limit(50)).all()
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"targets": targets, "scans": scans, "user": user})

@app.post("/login")
def web_login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid credentials"}, status_code=401)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("access_token", create_access_token(user), httponly=True, secure=settings.app_env == "production", samesite="strict", max_age=settings.access_token_minutes * 60)
    return response

@app.post("/api/auth/login", response_model=TokenOut)
def api_login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == form.username))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    return TokenOut(access_token=create_access_token(user))

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"status": "logged out"}

@app.post("/api/targets", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    target = Target(**payload.model_dump()); db.add(target); db.commit(); db.refresh(target); return target

@app.get("/api/targets", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.scalars(select(Target).order_by(Target.id.desc())).all()

@app.post("/api/scans", response_model=ScanOut, status_code=202)
def create_scan(payload: ScanCreate, background: BackgroundTasks, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    target = db.get(Target, payload.target_id)
    if not target: raise HTTPException(404, "Target not found")
    if not target.authorized: raise HTTPException(403, "Target must be explicitly marked authorized")
    scan = Scan(target_id=target.id, status="queued"); db.add(scan); db.commit(); db.refresh(scan)
    background.add_task(_run_background, scan.id); return scan

def _run_background(scan_id: int):
    with SessionLocal() as db: execute_scan(db, scan_id)

@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(limit: int = 100, offset: int = 0, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    limit, offset = min(max(limit, 1), 100), max(offset, 0)
    return db.scalars(select(Scan).options(selectinload(Scan.findings)).order_by(Scan.id.desc()).offset(offset).limit(limit)).all()

@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    scan = db.scalar(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id))
    if not scan: raise HTTPException(404, "Scan not found")
    return scan

@app.get("/api/scans/{scan_id}/report.pdf")
def scan_report(scan_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    scan = db.scalar(select(Scan).options(selectinload(Scan.findings), selectinload(Scan.target)).where(Scan.id == scan_id))
    if not scan: raise HTTPException(404, "Scan not found")
    return StreamingResponse(build_scan_pdf(scan), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=labvuln-scan-{scan.id}.pdf"})
