# Email Phishing Triage Console

**An offline analyst workbench for investigating suspicious email and documenting a defensible triage decision.**

![Python tests](https://github.com/HenryTun759/Email-Phishing-Triage-Console/actions/workflows/tests.yml/badge.svg)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB)
![External dependencies](https://img.shields.io/badge/runtime_dependencies-zero-66e3c4)

![Email Phishing Triage Console — inspect, investigate, document](docs/banner.svg)

## Console preview

![Credential-phishing investigation in the working console](docs/console.png)

Screenshot captured from the working app by the passing Chromium workflow. Desktop and mobile captures are also available in the `console-screenshots` CI artifact.

Built as a cybersecurity portfolio lab by **Zayar Lin Tun (Henry)**. The project demonstrates MIME parsing, indicator extraction, evidence hashing, explainable detection logic, safe handling of untrusted content, and SOC investigation documentation.

> **Scope:** a working educational triage tool, not a production email gateway or a trained AI classifier. Scores prioritize manual review; they do not prove maliciousness. No email content is sent to external APIs.

## Run locally

Requires **Python 3.10 or newer** and a modern browser. No pip installation, API key, account, or paid service is required.

```bash
git clone https://github.com/HenryTun759/Email-Phishing-Triage-Console.git
cd Email-Phishing-Triage-Console
python3 app.py
```

Open **http://127.0.0.1:8765**. On Windows, use `py app.py` if `python3` is unavailable. Stop the server with `Ctrl+C`.

The server binds to loopback only. Keep it local: it is not designed for public hosting or multi-user deployments.

## Quick analysis in two minutes

1. Select **Credential lure** to load and analyze a synthetic email.
2. Inspect the **High / 100** review priority and the evidence behind each rule.
3. Open **Indicators** for defanged URLs and attachment hashes; open **Headers** for reported authentication and the Received chain.
4. Record your disposition and investigation notes.
5. Export a Markdown case report or structured JSON evidence record.
6. Compare **Suspicious invoice** (55 / High) and **Routine update** (0 / Low).

All samples use reserved example domains and documentation IP addresses. The invoice attachment contains inert training text. No real phishing campaign or malware is included.

## Five-stage case workflow

The application follows the supplied SOC workflow diagram:

| Stage | Working feature | Required before continuing |
| --- | --- | --- |
| 1. Assign alert | Save an analyzed email with an alert reference and assigned analyst | Reference and analyst |
| 2. Alert triaging process | Record analyst priority, category and initial impact assessment | Category and notes |
| 3. Analyze email artifacts | **3.1** Record sender-reputation evidence; **3.2** review attachment inventory | Sender assessment, source and notes; attachment review and notes |
| 4. Investigate related alerts | Match saved local cases by sender address, URL host or attachment hash; record external references | Review confirmation and scope/findings |
| 5. Case reporting | Save final disposition, actions and handoff; export all five stages | Final disposition and report |

Choose a sample, enter an alert reference and analyst in the workflow panel, and click **Save assigned case**. Use **Save & continue** through each stage. In stage 5, enter the final report in the panel below the evidence and click **Complete case**.

- **Save stage** persists partial work; use **Saved cases** to resume after a browser or server restart.
- Completed cases are read-only. Create a new alert for follow-up work.
- The server enforces stage requirements and rejects stale updates from another browser tab.
- Exports include the saved workflow, evidence-source references, related-case snapshot and activity history. Save edits before exporting; unfinished cases are labeled as drafts in Markdown.
- **Sender reputation is an analyst review**, not an automatic external lookup. Record the trusted source or choose **Inconclusive** when verification is unavailable.
- **Related alerts are local matches**, not a SIEM search or proof of a coordinated campaign.

See [workflow and API documentation](docs/WORKFLOW.md).

## What works

| Capability | Implementation |
| --- | --- |
| Email intake | Upload original `.eml` bytes or paste complete email source; 2 MiB limit |
| MIME parsing | Plain text, HTML text extraction, multipart messages, base64 and quoted-printable decoding |
| Header inspection | From, To, Reply-To, Date, Message-ID, Received, and reported SPF/DKIM/DMARC results |
| URL analysis | HTTP(S) extraction, defanging, visible-link mismatch, IP destinations, user-info and punycode signals |
| Attachment evidence | Name, MIME type, decoded byte count and SHA-256; risky/double extensions |
| Explainable scoring | Named rules, visible points, evidence, capped score and recommended next steps |
| Analyst workflow | Five enforced stages, assigned owner, local saved cases, disposition, notes, Markdown and JSON reports |
| Safe display | Text-only DOM rendering, no remote images, no link retrieval, no attachment execution |
| Verification | Python unit/integration tests, browser smoke test, GitHub Actions |

## Architecture

```text
Browser (vanilla HTML/CSS/JS)
  → loopback HTTP service (Python standard library)
  → MIME parser and deterministic rules
  → structured findings and evidence
  → analyst review and local report download
```

- `triage/cases.py` — SQLite case storage, stage validation, related-case matching and revision checks.
- `web/workflow.js` — five-stage form and saved-case workflow.
- `triage/analyzer.py` — parsing, evidence extraction and scoring; no networking code.
- `app.py` — fixed-route local HTTP service with request limits and security headers.
- `web/` — responsive dashboard; untrusted fields are inserted with `textContent`.
- `samples/` — three synthetic investigations.
- `tests/` — parser, evidence, server boundary and browser workflow checks.
- `docs/` — methodology, worked case, security model and interview walkthrough.

See [detection methodology](docs/METHODOLOGY.md), [worked investigation](docs/CASE_STUDY.md), and [demo walkthrough](docs/DEMO.md).

## Test

```bash
python3 -m unittest discover -s tests -v
```

Optional browser verification (Node.js plus Playwright):

```bash
npm install --no-save --package-lock=false playwright
npx playwright install chromium
# Start python3 app.py in another terminal, then:
node tests/browser-smoke.cjs
node tests/workflow-browser.cjs
```

The browser test covers sample analysis, tabs, notes, report downloads, file upload, script-injection handling, validation errors, reset and mobile overflow. Python CI runs on 3.10, 3.12 and 3.13.

## Limitations that matter

- **No live SPF/DKIM/DMARC validation.** Uploaded `Authentication-Results` headers can be forged. Confirm the receiving gateway and trust boundary independently.
- **No reputation lookup, DNS resolution, redirect following, antivirus or sandbox detonation.** A hash is an identifier, not a malware verdict.
- **No calibrated accuracy claim.** Rule weights and thresholds are illustrative, not trained or validated against a representative labeled dataset.
- Exact hostname/domain comparisons can flag legitimate third-party services and subdomains. Brand ownership and public-suffix relationships are not resolved.
- Only HTTP(S) text and HTML anchor URLs are extracted. QR codes, images, obfuscation, archives and attachment contents are not analyzed. Encrypted emails are not decrypted.
- Attached multipart/email containers are listed but not recursively investigated or hashed as decoded files. Analyze those separately in approved tooling.
- Quick-analysis notes are temporary. Explicitly saved cases persist in `data/cases.sqlite3`, including extracted metadata, body preview and notes. Original email bytes and attachment payloads are not stored. Treat the database and exported reports as sensitive.
- This is a local single-user tool with a small HTTP server, not a hardened hosted service. Read [SECURITY.md](SECURITY.md).

## Portfolio discussion

Be ready to explain why a low score does not mean safe, why authentication headers require a trusted source, how SHA-256 supports evidence integrity, and how you would validate detections using labeled examples. See [the interview walkthrough](docs/DEMO.md) for a practical demonstration plan.

## Possible next steps

- Evaluate false positives and false negatives against an authorized, labeled corpus.
- Add configurable organization domains and a public-suffix-aware comparison.
- Add opt-in hash-only reputation enrichment with explicit data-sharing controls.
- Add authenticated access control, protected audit storage and retention management before considering multi-user use.
