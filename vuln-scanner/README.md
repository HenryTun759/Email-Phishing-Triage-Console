# LabVuln — Authorized Lab Vulnerability Scanner

Production-oriented FastAPI vulnerability scanner for **systems you own or are explicitly authorized to assess**. It performs non-destructive discovery and configuration checks, stores findings, and exposes a small web dashboard.

## Safety boundary
- Default scan targets are restricted to private/loopback/link-local IPv4 ranges.
- Public targets require `ALLOW_PUBLIC_TARGETS=true` and an explicit `authorized=true` request flag.
- No exploitation, credential attacks, persistence, payload delivery, or destructive tests are implemented.
- Keep this service on a trusted network and behind authentication in production.

## Features
- FastAPI REST API with OpenAPI docs
- SQLAlchemy models for targets, scans, and findings
- Background scan execution with bounded thread pool
- TCP service discovery for a conservative port set
- HTTP security-header and TLS metadata checks
- Safe version/banner collection
- Severity scoring and remediation guidance
- Responsive server-rendered dashboard
- Pytest test suite
- Docker + Compose + healthcheck

## Run locally
```bash
cd vuln-scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```
Open `http://127.0.0.1:8000`.

## Docker
```bash
docker compose up --build
```

## API examples
Create a loopback target:
```bash
curl -X POST http://127.0.0.1:8000/api/targets \
  -H 'Content-Type: application/json' \
  -d '{"name":"Local Lab","host":"127.0.0.1","port":8000,"authorized":true}'
```
Start a scan:
```bash
curl -X POST http://127.0.0.1:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target_id":1}'
```

## Architecture
`FastAPI -> service layer -> scanner modules -> SQLAlchemy -> SQLite/PostgreSQL`

The scanner interface is intentionally modular so additional **non-destructive** checks can be added without coupling them to HTTP handlers.

## Production hardening
Use PostgreSQL, a reverse proxy with TLS, application authentication/authorization, secret management, structured log shipping, rate limits, network egress controls, and a dedicated unprivileged container/user. For Internet-facing assessment, use a purpose-built security platform with authorization controls and audit logging.

## License
MIT
