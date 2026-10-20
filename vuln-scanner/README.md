# LabVuln 🔐

### Authorized-Lab Vulnerability Scanner

LabVuln is a portfolio-grade cybersecurity project built with **Python, FastAPI and SQLAlchemy**. It provides authenticated vulnerability assessment workflows for controlled laboratory environments, with scan history, CVSS v3.1 scoring, remediation guidance and downloadable PDF reports.

> **Authorized use only.** Scan only systems you own or have explicit permission to assess. LabVuln intentionally excludes exploitation, credential attacks, persistence, payload delivery and destructive testing.

## ✨ Highlights

| Capability | Implementation |
|---|---|
| API | FastAPI + OpenAPI |
| Authentication | JWT bearer tokens + secure HttpOnly dashboard cookie |
| Password storage | Argon2 password hashing via `pwdlib` |
| Database | SQLAlchemy; SQLite for labs, PostgreSQL-ready |
| Scan history | Persistent scan + finding records with pagination |
| Risk rating | CVSS v3.1 base scores + severity bands |
| Scanner checks | TCP reachability + HTTP security headers |
| Reports | Server-generated PDF assessment reports |
| Safety | Private-range default, explicit authorization gate, proxy/redirect protections |
| Testing | Pytest unit/API/security regression tests |
| Deployment | Docker, Compose, non-root container, healthcheck |

## 🏗️ Architecture

```text
                    ┌──────────────────────┐
                    │  Browser / REST API   │
                    └──────────┬───────────┘
                               │ JWT / HttpOnly cookie
                    ┌──────────▼───────────┐
                    │      FastAPI         │
                    │ auth · routes · docs │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │    Service Layer     │
                    │ scan lifecycle + DB  │
                    └──────────┬───────────┘
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼
     ┌─────────────────┐               ┌─────────────────┐
     │ Scanner Engine  │               │  PDF Reporting  │
     │ TCP / HTTP      │               │   ReportLab     │
     └────────┬────────┘               └─────────────────┘
              │
              ▼
     ┌─────────────────┐
     │ SQLAlchemy DB   │
     │ users/targets/  │
     │ scans/findings  │
     └─────────────────┘
```

## 🔎 Security design

The project was reviewed specifically for common web/scanner risks.

### Issues addressed
- **Unauthenticated management API** → JWT authentication is required for targets, scans and reports.
- **Plaintext credential risk** → passwords are Argon2-hashed and never stored in plaintext.
- **SSRF through environment proxies** → scanner HTTP requests bypass ambient proxy configuration.
- **Redirect-based SSRF** → automatic HTTP redirects are disabled.
- **Dangerous special-purpose IP ranges** → scanner rejects unspecified, multicast and reserved IPv4 ranges.
- **Unbounded scan-history queries** → API pagination is capped at 100 records.
- **Evidence/report size growth** → stored evidence and remediation text are bounded.
- **Session exposure** → dashboard authentication uses HttpOnly + SameSite cookies; production mode enables Secure cookies.
- **Container privilege** → Docker runs the application as an unprivileged user.

### Remaining production controls
Before exposing the service beyond a lab, add a reverse proxy/TLS, rate limiting, audit logging, centralized secrets, PostgreSQL migrations, CSRF protection for browser state-changing actions, and network-level egress controls.

## 📁 Project structure

```text
vuln-scanner/
├── app/
│   ├── auth.py              # JWT + password hashing
│   ├── config.py            # Environment configuration
│   ├── cvss.py              # CVSS v3.1 scoring
│   ├── database.py          # SQLAlchemy engine/session
│   ├── main.py              # FastAPI routes and lifecycle
│   ├── migrations.py        # Prototype compatibility migration
│   ├── models.py             # User/Target/Scan/Finding models
│   ├── reports.py            # PDF report generation
│   ├── schemas.py            # Pydantic request/response models
│   ├── services.py           # Scan orchestration
│   ├── scanner/
│   │   ├── base.py
│   │   ├── engine.py
│   │   ├── http_checks.py
│   │   ├── safety.py
│   │   └── tcp.py
│   └── templates/
│       ├── dashboard.html
│       └── login.html
├── tests/
│   ├── conftest.py
│   ├── test_api.py
│   ├── test_api_auth.py
│   ├── test_auth.py
│   ├── test_cvss.py
│   ├── test_safety.py
│   └── test_safety_and_report.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## 🚀 Quick start

### 1. Configure secrets

```bash
cd vuln-scanner
cp .env.example .env
```

Generate a strong JWT secret rather than using the example value:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set the generated value in `JWT_SECRET` and choose a strong `ADMIN_PASSWORD`.

### 2. Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Start

```bash
uvicorn app.main:app --reload
```

Then open `http://127.0.0.1:8000` and sign in with the configured admin credentials.

### 4. Run tests

```bash
pytest -q
```

## 🐳 Docker

```bash
docker compose up --build
```

The container exposes port `8000`, persists its SQLite database in a named volume, runs as a non-root user and includes a healthcheck.

## 🔑 API workflow

### Login

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=YOUR_PASSWORD'
```

Use the returned bearer token for protected API calls.

### Register an authorized lab target

```bash
curl -X POST http://127.0.0.1:8000/api/targets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Local Lab","host":"127.0.0.1","port":8000,"authorized":true}'
```

### Start a scan

```bash
curl -X POST http://127.0.0.1:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target_id":1}'
```

### Review scan history

```bash
curl http://127.0.0.1:8000/api/scans?limit=20 \
  -H "Authorization: Bearer $TOKEN"
```

### Download a PDF report

```bash
curl -o scan-report.pdf \
  http://127.0.0.1:8000/api/scans/1/report.pdf \
  -H "Authorization: Bearer $TOKEN"
```

## 📊 CVSS

Findings receive a CVSS v3.1 base score and vector. The scanner uses conservative vectors for the specific configuration weaknesses it detects; scores should be treated as an initial risk signal and validated against the actual deployment context.

Severity bands follow the CVSS convention: **None (0), Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9), Critical (9.0–10.0).**

## 🧪 Testing strategy

The test suite covers:

- Password hashing and verification
- JWT claims and expiration
- Protected API routes
- Health endpoint availability
- Authorization gate behavior
- Special/reserved IP rejection
- CVSS known-vector calculations
- CVSS severity boundaries
- PDF report creation

## ⚠️ Scope and limitations

LabVuln is deliberately **not** a replacement for Nmap, Nessus, Burp Suite, a commercial vulnerability management platform, or a professional penetration test. Its current checks are intentionally conservative and non-destructive.

The project is designed to demonstrate secure API engineering, vulnerability-scanner architecture, defensive validation, risk scoring, reporting and test discipline in a cybersecurity portfolio.

## 🛣️ Roadmap

- PostgreSQL + Alembic migrations
- Role-based access control
- Scan queues backed by Redis/Celery
- Additional safe checks for TLS, DNS and common HTTP misconfigurations
- Asset tagging and remediation workflow
- Audit log and immutable report metadata
- CI pipeline with linting, SAST and dependency scanning

## 👤 Portfolio talking points

This project demonstrates experience with:

- Secure REST API development
- Authentication and password security
- Vulnerability assessment methodology
- CVSS risk scoring
- SSRF-aware network tooling
- Database-backed security workflows
- Automated testing and security regression testing
- Dockerized deployment
- Security reporting and remediation communication

## License

MIT
