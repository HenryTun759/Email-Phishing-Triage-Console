# Five-minute portfolio demonstration

1. **Problem (30 seconds):** “Suspicious-email triage needs reproducible evidence and documented reasoning. This local tool organizes that first review.”
2. **Working workflow (90 seconds):** launch the app, load Credential lure, explain link mismatch and the capped score, inspect headers and defanged URLs.
3. **Evidence (60 seconds):** load Suspicious invoice; show the filename, decoded byte count and SHA-256. Explain why the attachment is never executed and why its extension alone cannot prove malware.
4. **Decision (60 seconds):** enter investigation notes, choose a disposition and export Markdown/JSON. Distinguish observed evidence from follow-up actions you have not performed.
5. **Engineering and limits (60 seconds):** show automated tests and discuss untrusted authentication headers, false positives, missing reputation checks and the next validation experiment.

## Questions to prepare for

- Why use a deterministic engine? Each finding is reproducible and explainable, with no API cost or external email disclosure.
- Why not call it AI-powered? This version uses explicit rules. An AI claim would misrepresent its implementation.
- Can the email execute JavaScript? Its HTML is parsed into text on the server; browser output uses text nodes rather than raw HTML, with a restrictive CSP as defense in depth.
- What does an authentication pass prove? Only a reported result is shown here. Even a verified pass does not establish benign intent.
- How would you improve accuracy? Use a representative, authorized labeled corpus, measure precision/recall by scenario, examine false positives and adjust rules transparently.
- What would production require? Stronger parsing isolation/resource bounds, authentication, authorization, audit trails, retention controls, monitoring, secure deployment and operational validation.

Describe the project honestly, including assistance used in its implementation. Practice explaining and modifying a rule yourself before listing it as a skill demonstration.
