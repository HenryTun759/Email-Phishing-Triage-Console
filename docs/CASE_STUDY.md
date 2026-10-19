# Worked case: synthetic credential lure

**Source:** `samples/credential-phishing.eml`  
**Purpose:** illustrate a Tier 1 triage record, not claim a real incident investigation.

## Observation

An email claims an account will be suspended unless the recipient signs in immediately. The visible link references `portal[.]example[.]org`, while the actual destination is `account-review[.]example`. The sender and Reply-To domains differ. The supplied authentication header reports failures for SPF, DKIM and DMARC.

## Tool output

| Evidence | Points |
| --- | ---: |
| Visible link/destination mismatch | 25 |
| Reply-To domain mismatch | 15 |
| Reported SPF failure | 10 |
| Reported DKIM failure | 10 |
| Reported DMARC failure | 20 |
| Urgency wording | 10 |
| Credential request with link | 15 |
| **Total, capped** | **100 / High** |

## Analyst assessment

**Disposition:** Escalate — suspected phishing.

The combination of a deceptive destination and account-pressure language supports escalation. The reported authentication failures are additional leads, not verified facts: the gateway identity and header trust boundary have not been established by this offline tool.

## Recommended follow-up

- Validate the original message and gateway logs.
- Search for related messages and determine recipient exposure.
- If a user interacted, escalate for endpoint and identity investigation according to the response procedure.
- Preserve the original email, full hash, timestamps and exported report.

**Not performed in this lab:** URL browsing, credential submission, reputation lookup, mailbox search, containment or incident confirmation.

## Comparison cases

The synthetic invoice scores 55 because of the Reply-To mismatch (15), active extension (25) and double extension (15). Its attachment is harmless text, demonstrating that detection heuristics are not equivalent to malware analysis.

The routine update scores 0. That means only that no configured rules matched; it does not authorize a “safe” verdict without independent checks.
