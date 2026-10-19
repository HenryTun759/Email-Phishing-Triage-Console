# Detection methodology

The engine calculates `min(100, sum(points for unique matched rules))`. Each rule contributes at most once, even when several URLs or attachments match. A finding includes one illustrative piece of evidence, not an exhaustive per-rule list; the inventory lists extracted URLs and attachments.

| Rule | Points | Interpretation |
| --- | ---: | --- |
| LINK_MISMATCH | 25 | An anchor displays an HTTP(S) URL with a different destination hostname |
| ATTACHMENT_RISK | 25 | Filename ends with a configured active/executable extension |
| AUTH_DMARC | 20 | Header reports DMARC fail, softfail or permerror |
| REPLY_TO | 15 | Exact sender and Reply-To domains differ |
| DOUBLE_EXTENSION | 15 | Filename uses a document/image extension followed by another extension |
| IP_URL | 15 | URL host is an IPv4 or IPv6 literal |
| URL_USERINFO | 15 | URL contains a username section before the host |
| CREDENTIALS | 15 | Credential-related text appears with a URL |
| AUTH_SPF / AUTH_DKIM | 10 each | Header reports fail, softfail or permerror |
| URGENCY | 10 | Configured urgency/account-pressure terms appear |
| PUNYCODE | 10 | Host contains an `xn--` label |
| MALFORMED_URL | 5 | URL parsing rejects a candidate |
| PARSER_DEFECT | 0 | MIME parser reports a recoverable anomaly |

Low: **0–19**. Medium: **20–49**. High: **50–100**.

A score is a deterministic prioritization aid, not a probability. Passing authentication does not lower the score or prove legitimacy. Missing authentication headers are shown as “not reported” and add no points. English keywords are deliberately simple; obfuscated text and other languages can evade them. Authentication failures may also arise from benign forwarding or configuration issues.

## Evidence integrity

The email SHA-256 is calculated on the exact uploaded bytes. The case ID uses its first ten hexadecimal characters for convenient display, not as a globally unique key. Compare the full hash for evidence correlation. Pasting or editing the email changes the bytes and therefore the hash. The browser retains uploaded bytes until the text is edited.

Attachment hashes cover transfer-decoded attachment bytes. Containers without a decoded byte payload do not receive a misleading empty-file hash. The tool neither saves nor opens attachments.

## Analyst validation

1. Establish a trusted source for gateway authentication results and delivery events.
2. Confirm the sender and business context using a separate known-good channel.
3. Review indicators using approved tooling and data-sharing rules.
4. Determine who received, opened, clicked, or submitted credentials, where logs allow.
5. Record evidence, uncertainty, disposition and recommended escalation.

No isolation, blocking, account reset, message deletion or other containment action is automated by this project.
