# Security Review

## Review scope
The review covered authentication, authorization, input handling, scanner network behavior, database access, report generation, container configuration and test coverage.

## Findings and remediation

| Risk | Status | Remediation |
|---|---|---|
| Unauthenticated management endpoints | Fixed | JWT authentication required for targets, scans and reports |
| Plaintext password storage | Fixed | Argon2 password hashing with `pwdlib` |
| Proxy-based SSRF | Fixed | HTTP scanner uses `trust_env=False` |
| Redirect-based SSRF | Fixed | HTTP redirects disabled and surfaced as findings |
| Unsafe/reserved IPv4 ranges | Fixed | Scanner blocks unspecified, multicast and reserved ranges |
| Unlimited scan-history retrieval | Fixed | `limit`/`offset` pagination with a maximum page size |
| Oversized evidence persistence | Fixed | Evidence/remediation values are bounded before persistence |
| Privileged container | Fixed | Docker image runs as an unprivileged UID |
| Secret leakage through source | Mitigated | Runtime JWT/admin credentials are environment-provided and `.env` is ignored |

## Threat model

LabVuln is intended for a trusted operator assessing authorized laboratory assets. The primary security boundary is the target authorization flag plus the default private-network policy. The application should still be deployed behind TLS, a reverse proxy, rate limiting and network egress controls.

## Recommended production controls

1. Use PostgreSQL with Alembic migrations.
2. Store secrets in a managed secret store.
3. Add role-based access control and audit logging.
4. Add CSRF protection to browser state-changing endpoints.
5. Add login throttling/account lockout and security event monitoring.
6. Restrict outbound network traffic at the container/firewall layer.
7. Run dependency, SAST and container scans in CI.
8. Keep the scanner service isolated from sensitive internal networks.

This document describes the security posture of the portfolio implementation; it is not a guarantee that the software is vulnerability-free.
