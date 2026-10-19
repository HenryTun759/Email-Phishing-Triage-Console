# Security model

This application is intended for local, single-user education and portfolio demonstrations.

## Controls

- Loopback-only binding; Host allowlist reduces DNS-rebinding exposure.
- Origin validation and a required non-simple upload content type reject ordinary cross-origin browser submissions. No CORS permissions are granted.
- Fixed static route allowlist; no user-controlled filesystem paths.
- 2 MiB upload limit and socket timeouts.
- No network enrichment, URL retrieval, remote images, raw HTML rendering, attachment execution or automatic persistence.
- Security headers include CSP, frame denial, no-sniff and no-store.
- Logs do not record request paths or email content.

## Residual risks

A loopback service is not an authentication boundary against other local programs. MIME parsers consume CPU and memory; upload limits do not eliminate all hostile-input risks. Use synthetic or authorized samples, preferably in an isolated lab. Do not expose the service to the internet or use it as a malware sandbox.

Exports may include personal data and original header values; JSON is an evidence format, not a fully sanitized sharing format. Review and redact reports before sharing. The application stores no history, but browsers and operating systems may retain data in memory or download storage.

## Reporting

Do not post private emails, credentials, personal information or live malicious samples in public issues. Reproduce bugs with sanitized synthetic fixtures. For sensitive vulnerabilities, use GitHub private vulnerability reporting if enabled; otherwise contact the repository owner through an appropriate private channel.
