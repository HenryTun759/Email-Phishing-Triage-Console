# Five-stage investigation workflow

This implementation follows the supplied diagram in sequence. The automated analysis can be previewed before saving; the formal investigation begins when an alert is assigned. The case record wraps the extracted evidence and keeps the automated score separate from analyst priority and disposition.

## States and gates

A new record starts at stage 1 with status `Open`. `save` persists current-stage work without advancing. `advance` validates the current stage before moving one stage forward. `complete` is accepted only at stage 5 with a final disposition and report. Completed cases are read-only through the API.

1. **Assign alert:** an alert reference and analyst name are mandatory. These are labels for a local lab; no identity authentication or ticket-system integration is implied.
2. **Alert triaging process:** set priority, choose a non-default category and describe the initial assessment and potential user impact.
3. **Analyze email artifacts:** both subtasks must be documented. Sender review needs a status, evidence source and reasoning. Use `Inconclusive` and explain missing verification if no reputation service is available. Attachment review must be `Reviewed` when an inventory exists, or `No attachments` when empty, with notes either way. A review can document unresolved risk; it does not mean an attachment is safe.
4. **Investigate related alerts:** confirm review and record scope/findings, including limits of any external searches. Matches compare exact parsed sender addresses, defanged URL hostnames and non-empty attachment SHA-256 values across saved local cases. Matching values are shown as evidence. A common hostname can be benign shared infrastructure. The matching snapshot is recomputed and stored when this stage is saved or advanced.
5. **Case reporting:** record a disposition other than `Needs investigation`, summarize evidence, actions actually performed and recommended handoff. A completed triage case may still be escalated for further incident investigation.

## Persistence

The local database is `data/cases.sqlite3`, created when the server starts. There are no extra packages. Each case has a generated record ID, full extracted analysis, stage records, timestamps, revision number and append-only-by-API activity entries. This is not a tamper-resistant audit log.

The original email file and decoded attachment payloads are not persisted. Headers, body preview, hashes, indicators and analyst notes are persisted and may be sensitive. Existing quick-analysis behavior remains available without saving.

Each update includes its last known `revision`. A stale revision produces HTTP 409; reload the saved case before editing again. Updates use a database compare-and-set so two concurrent writers cannot silently replace one another. Completed stages cannot be rewritten through the current-stage forms. Capture corrections in subsequent notes or create a follow-up case.

The selector lists the 200 most recently updated cases; correlation examines all saved records. This is intended for small local lab datasets, not a high-volume SOC queue. Unsaved form changes are not retained when loading another case or starting another email. Exports contain saved workflow data; save before exporting.

To erase all local cases, stop the app and remove the `data` directory. This is permanent unless you have a backup. Do not commit the database or real evidence to the repository.

## Local API

All endpoints retain loopback Host checks, request limits and browser-origin restrictions. POST case routes require `Content-Type: application/json`.

| Method | Route | Behavior |
| --- | --- | --- |
| POST | `/api/analyze` | Existing raw-email analysis; `application/octet-stream` |
| GET | `/api/cases` | Latest 200 case summaries |
| POST | `/api/cases` | Analyze original bytes and create assigned case |
| GET | `/api/cases/{id}` | Load saved evidence and workflow |
| POST | `/api/cases/{id}` | Save, advance or complete with revision check |
| GET | `/api/cases/{id}/related` | View current local correlation matches |

Create request: `email_base64` (base64 original bytes), `alert_id`, `assignee`. Email limit is 2 MiB; the JSON transport limit is 3 MiB. Analysis is computed on the server, not accepted from client-supplied findings.

Update example for stage 2:

```json
{
  "revision": 2,
  "action": "advance",
  "fields": {
    "priority": "High",
    "category": "Credential phishing",
    "notes": "User reported a sign-in lure. Recipient exposure is not yet verified."
  }
}
```

Validation failures return 400, unknown cases 404, stale revisions 409, oversize requests 413, unsupported media types 415 and case-write storage errors 503. Client-supplied stage/status values cannot skip server transitions.

## Verification

`tests/test_cases.py` exercises progression, stage gates, stale-write rejection, restart persistence, correlation evidence and completed-case immutability. HTTP tests cover case creation, reads, updates and validation. `tests/workflow-browser.cjs` covers the full UI path, reloading saved work, related matches, final exports and mobile overflow.
