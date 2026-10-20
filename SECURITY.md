# Security model

This application is intended for local, single-user education and portfolio demonstrations.

## Controls

- Loopback-only binding; Host allowlist reduces DNS-rebinding exposure.
- Origin validation and a required non-simple upload content type reject ordinary cross-origin browser submissions. No CORS permissions are granted.
- Fixed static route allowlist; no user-controlled filesystem paths.
- 2 MiB upload limit and socket timeouts.
- No network enrichment, URL retrieval, remote images, raw HTML rendering, attachment execution. Persistence occurs only when the analyst saves a case.
- Security headers include CSP, frame denial, no-sniff and no-store.
- Logs do not record request paths or email content.

## Residual risks

A loopback service is not an authentication boundary against other local programs. MIME parsers consume CPU and memory; upload limits do not eliminate all hostile-input risks. Use synthetic or authorized samples, preferably in an isolated lab. Do not expose the service to the internet or use it as a malware sandbox.

Exports may include personal data and original header values; JSON is an evidence format, not a fully sanitized sharing format. Review and redact reports before sharing. Saved cases persist in `data/cases.sqlite3`. The database includes header values, body previews, extracted indicators, analyst notes and activity history; it is not encrypted. The original email bytes and attachment payloads are not stored. The directory is created with mode 0700 and the database with mode 0600 where the OS supports these permissions. Case files are excluded from Git. Protect local backups and exports. Stop the server before removing the database to reset all saved cases. Browser and operating-system storage may retain copies.

The assigned analyst name is a label, not an authenticated identity. Activity history is not tamper-proof. Revision checks prevent accidental stale overwrites through the API but do not protect against a local user modifying SQLite directly. Completed cases are read-only through the application.

## Reporting

Do not post private emails, credentials, personal information or live malicious samples in public issues. Reproduce bugs with sanitized synthetic fixtures. For sensitive vulnerabilities, use GitHub private vulnerability reporting if enabled; otherwise contact the repository owner through an appropriate private channel.
