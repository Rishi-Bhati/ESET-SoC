# ESET PROTECT Cloud — Webhook Field Confirmation Request

**Purpose of this document:** this is meant to be shown to Mac Systems / reviewed against the actual ESET PROTECT Cloud console, to confirm which of the fields below the tenant's webhook notifications can actually populate. It is a client-facing confirmation artifact — distinct from the internal API contract documented in `README.md`, which describes what *our* receiving endpoint accepts, not what ESET actually sends.

This corresponds to Task 2 of `docs/SOC_LITE_AUDIT.md`'s recommended implementation order, and directly informs the open items in that audit's §8 (ESET Integration Audit).

---

## Why we're asking

Our AI-notification pipeline can normalize and process whatever fields ESET PROTECT Cloud's webhook actually sends — but as of this writing, **our engineering team has never received a real webhook from this tenant**, so every field below is our best understanding of what is *generally* available in ESET PROTECT Cloud, not a confirmed fact about your specific environment. We need your team (or direct console access) to confirm which of these a configured webhook notification can actually populate.

## What we're asking for

1. In the ESET PROTECT Cloud console, open the notification/webhook configuration screen for a Threat Detection (or similar) notification type.
2. Either:
   - Use the **"Send test webhook"** function (if available) pointed at our receiving endpoint, so we can see the real payload directly, **or**
   - Share a screenshot/export of the available webhook variables/template fields for that notification type.
3. Confirm, using the checklist below, which fields are actually populated.

## Field checklist

| Field we'd like | Generally described in ESET documentation as available? | Confirmed available in this tenant? | Notes |
|---|:---:|:---:|---|
| Event / detection type | Likely | ☐ | |
| Alert / detection identifier | Likely | ☐ | |
| Detection UUID | Uncertain | ☐ | Needed if we later evaluate ESET Connect API enrichment |
| Target (endpoint) UUID | Uncertain | ☐ | Same as above |
| Occurred/detected time | Likely | ☐ | |
| Severity | Likely | ☐ | |
| Detection/threat name | Likely | ☐ | |
| Endpoint (computer) name | Likely | ☐ | |
| Endpoint type (workstation/server) | Uncertain | ☐ | |
| Logged-in user | Uncertain | ☐ | |
| Operating system | Uncertain | ☐ | |
| Action taken by ESET | Likely | ☐ | |
| Threat handled (yes/no) | Likely | ☐ | |
| Isolation status | Uncertain | ☐ | |
| Affected object type (file/process/etc.) | Uncertain | ☐ | |
| Affected object path/URI | Uncertain | ☐ | |
| File hash | Uncertain | ☐ | |
| URL (if applicable) | Uncertain | ☐ | |
| IP address (if applicable) | Uncertain | ☐ | |
| Domain (if applicable) | Uncertain | ☐ | |
| Notification subject line | Likely | ☐ | |
| Notification body/content | Likely | ☐ | |
| Incident link (to ESET console) | Uncertain | ☐ | Listed as optional in the PoC requirements document |
| Incident computer link | Uncertain | ☐ | Same as above |

"Generally described in ESET documentation as available" reflects the requirements document's own summary (Section 4) and has **not** been independently verified against current official ESET documentation as part of this checklist — treat those column values as a starting assumption to confirm, not a guarantee.

## What happens after confirmation

Once we know which fields are real, we will:
1. Update `src/ingestion/webhook_handler.py` and `src/models/raw_payload.py` if any real field name differs from what we've assumed.
2. Mark PoC Test #10 ("Actual ESET webhook") in `docs/SOC_LITE_AUDIT.md` §13 as validated.
3. If the confirmed fields are insufficient for reliable triage (e.g. no file hash, no IP/URL), we will revisit whether ESET Connect API enrichment (Option B in the requirements document) is worth pursuing — pending confirmation that the ESET PROTECT Complete subscription includes that access.

## Reference: what our receiving endpoint already accepts

For technical reference, our webhook receiver (`POST /webhook/eset`, documented in `README.md`) already accepts every field in the table above, plus any additional fields (they are preserved, just unused). Nothing needs to change on our side to receive a real payload — we only need to know what ESET actually sends so the mapping is accurate rather than assumed.
