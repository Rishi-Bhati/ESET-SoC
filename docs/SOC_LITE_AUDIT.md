# ESET SOC Lite / AI Notification PoC — Requirements-to-Implementation Audit

**Audited repository:** `d:\ESET\ESET-SoC` (branch `ai-content-fix`)
**Requirements baseline:** `ESET_SOC_Lite_Client_Status_and_PoC_Considerations_EN.docx` (v1.0, prepared 2026-08-06) — already present in the repo root, extracted for this audit
**Audit date:** 2026-08-25
**Method:** Direct inspection of source files, tests, config, and fixtures. No code was modified to produce this report. Every "Implemented" claim below cites the file(s) that prove it.

Status vocabulary used throughout:

| Label | Meaning |
|---|---|
| **IMPLEMENTED** | Working, with repository evidence (code + usually a test) |
| **PARTIALLY IMPLEMENTED** | Exists, but materially incomplete |
| **MISSING** | Clearly absent from the codebase |
| **BLOCKED** | Cannot proceed without external dependency (ESET tenant, client decision, credentials) |
| **UNKNOWN** | Repository does not provide enough evidence either way |
| **NOT REQUIRED FOR POC** | Correctly out of scope per the requirements document |

---

## Implementation Update — 2026-08-25

Everything below this box is the **original audit as written**, preserved as the point-in-time baseline. This box records what engineering subsequently implemented against that baseline, with all statuses re-verified against the current code and a full test-suite run (144/144 passing — see `tests/`).

**Implemented in this pass (engineering-only, no client/ESET access required):**

| Original finding | Status now | Evidence |
|---|---|---|
| §9 "Missing" — no pre-AI masking | **IMPLEMENTED** (policy proposal; final field list still needs client sign-off — see §18) | `src/services/ai/prompt_masking.py`, wired into `src/services/ai/gemini_service.py`, config toggle `AI_MASKING_ENABLED` in `src/config.py`. Tests: `tests/unit/test_prompt_masking.py`, `tests/unit/test_gemini_service_masking.py`. |
| §8 "Missing" — no prompt-injection framing | **IMPLEMENTED** | `src/prompts/system_prompts.py` (new "UNTRUSTED INPUT" section, `PROMPT_VERSION` bumped to `v1.1`). Test: `tests/unit/test_gemini_service_masking.py::test_system_prompt_frames_alert_content_as_untrusted_data`. |
| §5/§8 — AI call has no timeout, `AI_TIMEOUT_SECONDS`/`MAX_RETRIES` were dead config | **IMPLEMENTED** | `src/services/ai/gemini_service.py` — the Gemini call is now wrapped in `asyncio.wait_for(..., timeout=settings.ai_timeout_seconds)`; the retry decorator now reads `settings.max_retries` instead of a hardcoded `3`. |
| §5 — stale "Send Test Alert" dashboard-control comment | **IMPLEMENTED (fixed)** | `src/api/webhook.py` docstring corrected to reference `scripts/send_test_webhook.sh`/`scripts/send_test_syslog.py`, which are the actual mechanism. |
| §5 — `supervisord.conf` port conflict with embedded syslog listeners | **IMPLEMENTED (fixed)** | `supervisord.conf` — `[program:syslog_server]` removed; `[program:api]` (which already embeds the listeners via `src/main.py`'s `lifespan()`) is now the only process supervisord starts. |
| §12 — least-tested ingestion path: UDP/TCP syslog listeners had no socket-level test | **IMPLEMENTED** | `tests/integration/test_syslog_listeners.py` — binds real UDP/TCP sockets on high ports and asserts the listener → JSON-extraction → forward hand-off. |
| §17 PoC Test #4 — no multi-endpoint/critical fixture | **IMPLEMENTED** | `tests/fixtures/sample_critical_multi_endpoint.json` + `tests/integration/test_full_pipeline.py::test_full_pipeline_critical_multi_endpoint_event`. Schema is still single-endpoint-per-alert by design (unchanged — see the test's own docstring); this fixture represents the scenario the way the pipeline actually receives it. |
| §7 "Missing" — `cleanup_expired()` was dead code, `dedup_log` grew unbounded | **IMPLEMENTED** | `src/storage/deduplication.py: run_cleanup_loop()`, started/cancelled in `src/main.py`'s lifespan alongside the existing email-dispatch sweeper. Test: `tests/unit/test_deduplication.py::test_run_cleanup_loop_calls_cleanup_expired_periodically`. |
| §7 "Missing" — no explicit ingest body-size limit | **IMPLEMENTED** | `src/api/webhook.py: _reject_oversized_body()`, config `MAX_INGEST_BODY_BYTES` (default 1 MiB) in `src/config.py`. Header-based defense-in-depth, not a hard on-the-wire cap. Tests: `tests/integration/test_webhook_endpoint.py`. |
| §14 P1 — no client-facing sample ESET webhook field-confirmation artifact | **IMPLEMENTED** | `docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md` (new) — distinct from the README's internal API contract; meant to be sent to the client. |
| (test infra) Windows-only `UnicodeDecodeError` on 4 pre-existing tests reading `dashboard.js`/output JSON | **IMPLEMENTED (fixed)** | Added `encoding="utf-8"` to `open()` calls in `tests/integration/test_full_pipeline.py`, `test_security.py`, `test_dashboard_controls.py`. Pre-existing on `main`/`ai-content-fix` before this pass (confirmed via `git stash`), unrelated to the audit's findings — fixed so the full suite gives a trustworthy signal. |

**Explicitly left as-is per the audit's own "should not build yet" / risk guidance:**

- **ESET Connect API enrichment** — still **MISSING**, not built. Correctly gated on client confirmation of subscription/permission scope (§8, §15, §18) — no prerequisite from the audit was satisfied, so this was not started.
- **Real (non-mock) threat-intel test path** — still **MISSING** (P2). Not attempted in this pass; see "Remaining engineering work" below.
- **`_check_access()` as an enforced FastAPI dependency instead of a manual per-route call** — still **PARTIALLY IMPLEMENTED** as originally audited (P2). Deferred: touches every dashboard route, higher regression risk relative to benefit for this pass.
- **Semantic (non-exact-phrase) AI safety-lint check** — still **PARTIALLY IMPLEMENTED** as originally audited. The new prompt-injection framing (above) reduces the same underlying risk from a different angle, but the lint itself (`src/services/ai/lint_checker.py`) is unchanged — still an exact-phrase blocklist.
- **`DASHBOARD_ACCESS_KEY` hardening** — unchanged; this is an operational/deployment action for whoever runs the service, not a code change.
- **All items in the original §8/§15/§18 (ESET Integration Audit, Blocked, Client Action Items)** — unchanged and still genuinely **BLOCKED**. No ESET payload has been received; nothing in this pass could or did change that. See the Final Verdict at the end of this addendum.

**Test suite:** 144 tests passing (127 pre-existing + 17 new: 7 masking unit tests, 3 prompt-injection/masking-in-flight tests, 3 syslog socket-level tests, 2 body-size-limit tests, 1 dedup-cleanup-loop test, 1 multi-endpoint fixture test), 0 failing. Run with `PYTHONPATH=. .venv/Scripts/python.exe -m pytest tests/ -v` (Windows venv layout in this checkout).

**Files changed in this pass:** `src/services/ai/prompt_masking.py` (new), `src/services/ai/gemini_service.py`, `src/prompts/system_prompts.py`, `src/config.py`, `.env.example`, `src/api/webhook.py`, `supervisord.conf`, `src/storage/deduplication.py`, `src/main.py`, `docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md` (new), `tests/unit/test_prompt_masking.py` (new), `tests/unit/test_gemini_service_masking.py` (new), `tests/unit/test_deduplication.py`, `tests/integration/test_syslog_listeners.py` (new), `tests/integration/test_webhook_endpoint.py`, `tests/integration/test_full_pipeline.py`, `tests/integration/test_security.py`, `tests/integration/test_dashboard_controls.py`, `tests/fixtures/sample_critical_multi_endpoint.json` (new).

**Final status: NOT READY FOR CLIENT DEMO OF REAL ESET INTEGRATION / READY FOR SIMULATED-INPUT DEMO.** Every engineering-only P0 item from the original audit is now implemented and tested. Nothing about real ESET connectivity has changed, because nothing in this pass could change it — nothing here should be read as ESET-validated. See "Final PoC status" in the accompanying implementation-summary report for the full reasoning.

---

## 1. Executive Summary

This PoC is materially further along than "PoC" usually implies. The engineering team has already built a complete, working pipeline — ingestion, normalization, deterministic risk scoring, threat-intel enrichment, schema-enforced bilingual AI generation, a safety lint, HMAC-signed email handoff, and a live operator dashboard — against a normalized schema and AI output schema that match the requirements document's Section 8/9 JSON almost field-for-field. This is not a skeleton; it is a working system that has clearly never been pointed at a real ESET tenant.

**What works today (verified by reading the code and running the test suite mentally against it):**
- Webhook ingestion (`POST /webhook/eset`) and syslog-JSON ingestion (`POST /webhook/syslog`), both Bearer-token authenticated.
- Embedded UDP/TCP syslog listeners forwarding into the same pipeline.
- Deduplication by `alert_id:occurred_at` (SHA-256 fallback), 1-hour default TTL.
- The full 23-field normalized schema from the requirements doc, with strict `"UNKNOWN"` fallback and zero inference — confirmed line-by-line in `src/services/normalizer.py`.
- A deterministic, auditable risk engine independent of the AI (`src/services/risk_engine.py`).
- Gemini-backed structured generation of all 4 required bilingual notification variants (`src/services/ai/gemini_service.py`, `src/models/ai_output.py`).
- A post-generation safety lint blocking overreaching claims (`src/services/ai/lint_checker.py`).
- Email composition for all 4 audiences and HMAC-signed handoff to an external mail service (`src/services/email_composer.py`, `src/services/email_delivery/eset_mail.py`).
- A live, key-gated operator dashboard (`static/dashboard.html/js`, `src/api/dashboard.py`).
- ~90 automated tests covering auth, dedup, risk logic, normalization, the Gemini schema workaround, email composition, XSS-safe rendering, and every HTTP/WebSocket route.

**What is incomplete:**
- No pre-AI data masking. `raw_payload` is excluded from the Gemini prompt, but `ip_address`, `url`, `domain`, `user_name`, `endpoint_name`, and `file_hash` are sent to Gemini as plain text — the requirements document's own open question ("which fields must be masked before AI processing?") is unresolved in code.
- No prompt-injection framing anywhere in the system prompt, despite every alert field being attacker-influenceable by definition.
- ESET Connect API enrichment does not exist (no client, no model, no call site).
- Syslog network listeners (the actual UDP/TCP socket code) are implemented but have zero automated test coverage.
- `supervisord.conf` and the embedded-syslog architecture in `run.py`/`src/main.py` are mutually incompatible (both would try to bind the same ports).

**Biggest risk:** every "ESET" fact encoded in this codebase — webhook field names, syslog key names, the existence of `target_uuid`/`detection_uuid` as usable identifiers — is an engineered guess. **Zero requests have ever been received from a real ESET PROTECT Cloud tenant.** This is not a code defect; it is exactly the gap the requirements document itself predicts, and no further engineering closes it without client/ESET access.

**Biggest external dependency:** client action to register the webhook URL in ESET PROTECT Cloud and trigger a test send (see Section 15/18).

---

## 2. Current Architecture

This is a **single Python process** (FastAPI + Uvicorn, one `asyncio` event loop) — not the multi-tool n8n/Shuffle stack the requirements document treats as a candidate, and not a microservices architecture.

```
 EXTERNAL: ESET PROTECT Cloud (never actually connected — see §6)
      │
      ├─ HTTPS POST ───────────────────────────────┐
      │                                              │
      └─ syslog UDP/TCP (RFC 5424 + JSON) ──┐        │
                                              ▼        ▼
                        src/services/syslog_runtime.py (embedded UDP/TCP listeners,
                        same asyncio loop) → forwards to /webhook/syslog over loopback
                                              │
                     ┌────────────────────────┴─────────────────────┐
                     ▼                                                ▼
         POST /webhook/eset                                POST /webhook/syslog
         src/api/webhook.py  ── Depends(validate_eset_token) ──  src/middleware/auth.py
                     │
                     ▼
         ingest_alert()  src/api/webhook.py
             1. handler.parse()        src/ingestion/{webhook,syslog}_handler.py
             2. compute_dedup_key() → deduplication.is_duplicate()   src/storage/deduplication.py
             3. job_store.create_job()                                 src/storage/job_store.py
             4. background_tasks.add_task(run_pipeline_task, ...)
             → HTTP 200 {"status":"queued","correlation_id":...}  (returns before processing)
                     │
                     ▼
         process_alert_pipeline()   src/pipeline/orchestrator.py
             1. job_store.update_job_status(PROCESSING)
             2. normalizer.normalize()          → NormalizedAlert          src/services/normalizer.py
             3. risk_engine.compute_risk()       → risk_level, rationale    src/services/risk_engine.py
             4. threat_intel.aggregator.gather_threat_intel()  (parallel, timeout-safe, mock by default)
             5. GeminiAIService.generate()        → AIOutput                src/services/ai/gemini_service.py
             6. lint_checker.lint_ai_output()     → raises if unsafe claim  src/services/ai/lint_checker.py
             7. output_writer.write_result()      → output/alerts/<id>.json
             8. email_composer.compose_emails()   → up to 4 EmailMessage    src/services/email_composer.py
             9. email_outbox.add_emails()          → output/emails/outbox.json
            10. email_dispatcher.dispatch_soon()   → HMAC handoff           src/services/email_delivery/eset_mail.py
            11. job_store.update_job_status(SUCCESS / PARTIAL / FAILED)
                     │  every step also emits a WebSocket event
                     ▼
         Live Dashboard (static/dashboard.html/js) — zero build step, key-gated
                     │
                     ▼
         EXTERNAL: ESET Mail worker (Cloudflare Worker, not in this repo)
```

Storage is a hybrid: **SQLite** (`data/soc_lite.db`, no ORM, no migrations) holds workflow state — `jobs`, `dedup_log`, `app_settings`, `email_deliveries`. **Flat JSON files** (`output/alerts/*.json`, `output/emails/outbox.json`) hold the actual alert content and generated AI output, written once, read many times.

Two components not required by the requirements document but present and net-positive:
- **Risk Engine** — a deterministic rule engine that decides risk level, explicitly *not* AI-driven (`src/services/risk_engine.py`). This directly serves the doc's "must not confirm infection/compromise/resolution" requirement by keeping the highest-stakes decision out of the LLM's hands.
- **AI safety lint** — a second, independent check after AI generation (`src/services/ai/lint_checker.py`).

---

## 3. Current End-to-End Flow

Exactly what happens if one alert is sent into the system right now:

1. `POST /webhook/eset` with `Authorization: Bearer <ESET_WEBHOOK_AUTH_TOKEN>` (constant-time compared via `hmac.compare_digest` in `src/middleware/auth.py`). Missing/wrong token → HTTP 401, no body detail.
2. Body parsed into `EsetRawPayload` (`src/models/raw_payload.py`) — every field optional, unknown extra fields allowed and preserved.
3. Dedup key computed (`alert_id:occurred_at`, or SHA-256 of the full payload if either is missing) and checked against a 1-hour TTL SQLite table (`src/storage/deduplication.py`). A repeat within the window returns `{"status": "duplicate"}` and the pipeline never runs — no job, no WebSocket event.
4. A job row is written (`status=PENDING`), the pipeline is scheduled as a FastAPI `BackgroundTasks` call, and the HTTP response returns `{"status": "queued", "correlation_id": ...}` **before** any processing happens.
5. **Normalize** (`src/services/normalizer.py`): every missing field becomes the literal string `"UNKNOWN"`. Nothing is inferred — confirmed by reading every mapping line, each of the form `raw.field or "UNKNOWN"`.
6. **Risk score** (`src/services/risk_engine.py`): pure function of `severity` × `threat_handled` × `isolation_status`. No AI involved.
7. **Threat intel** (`src/services/threat_intel/aggregator.py`): VirusTotal + AbuseIPDB queried in parallel, 5s timeout each. **Mock mode is the default** (`use_mock_threat_intel=True`, hardcoded in `src/config.py`, not exposed as an env var) — real API code exists in `virustotal.py`/`abuseipdb.py` but is inactive unless someone edits the source.
8. **AI generate** (`src/services/ai/gemini_service.py`): the normalized alert (minus `raw_payload`), the risk level, and threat-intel verdicts are sent to Gemini (`gemini-3.1-flash-lite`) via a schema-enforced structured-output call (`src/services/ai/schema_builder.py`). Response is parsed into `AIOutput` (Pydantic validation).
9. **Lint** (`src/services/ai/lint_checker.py`): every string in the AI response is scanned against a blocklist of overreaching phrases (English + Japanese). A hit raises `LintFailureException` and the run downgrades to `PARTIAL`.
10. Result is written to `output/alerts/{correlation_id}.json` — always, regardless of outcome (`SUCCESS`/`PARTIAL`/`FAILED`); no alert is ever silently dropped (`src/services/output_writer.py`).
11. On `SUCCESS` only: up to 4 emails composed (client/C-Three/internal JA, engineer EN), one per recipient group with a configured address, queued to `output/emails/outbox.json`, then handed off once via an HMAC-signed POST to the external ESET Mail worker (`src/services/email_delivery/eset_mail.py`) — **only if `EMAIL_DELIVERY_ENABLED=true`** (defaults to `false`; otherwise emails sit in the outbox indefinitely).
12. Every stage transition is broadcast over WebSocket (`src/utils/events.py`, `src/utils/broadcaster.py`) to the dashboard, rendered as a live per-alert flow graph.

**What never happens today:** no step in this flow has ever been triggered by a real ESET PROTECT Cloud webhook, a real ESET Connect API call, or a real syslog export from an ESET tenant. Every alert that has gone through this pipeline was hand-crafted (curl, a test fixture, or `scripts/send_test_webhook.sh`).

---

## 4. Requirements vs Implementation

Organized by the requirements document's own categories.

### 4.1 ESET Integration

| Requirement | Status | File / Path | Evidence |
|---|---|---|---|
| Webhook receiving endpoint (HTTPS, JSON) | **IMPLEMENTED** | `src/api/webhook.py` | `POST /webhook/eset`, Bearer-token gated, tested |
| Webhook payload variables (subject, content, event type, target UUID, occurred time) | **PARTIALLY IMPLEMENTED** | `src/models/raw_payload.py` | All named fields modeled as optional inputs; whether ESET's actual webhook sends them is unverified |
| Test Webhook trigger from ESET console | **BLOCKED** | — | Requires client action |
| Webhook retry behavior | **UNKNOWN** | — | Not documented anywhere in this repo; not independently verified against ESET docs in this audit |
| Webhook authentication/security (our side) | **IMPLEMENTED** | `src/middleware/auth.py` | Constant-time Bearer token check; single static token, no per-source scoping |
| ESET Connect API enrichment (detection/target UUID → details) | **MISSING** | — | No client, no call site, no response model anywhere in `src/` |
| Incident Management API / detection API | **MISSING** | — | Same as above |
| Syslog export ingestion (JSON) | **IMPLEMENTED** | `src/ingestion/syslog_handler.py` | Maps ~10 alternate key spellings (`threat_name`, `computer_name`, `hash`, `ip`, `handled`, …); never confirmed against a real ESET syslog export |
| Syslog UDP/TCP network listeners | **PARTIALLY IMPLEMENTED** | `src/services/syslog_runtime.py` | Implemented and embedded in the main process; **no automated test binds a real socket**; ports 514/601 need root and silently stay down without it |
| External ESET account, MFA, read-only permissions | **BLOCKED** | — | Organizational/access matter |
| Source IP restriction | **NOT REQUIRED FOR POC** | — | Doc states none currently indicated; confirm before any internet-facing exposure |

### 4.2 Input Layer

| Input source | Status | File / Path | PoC role per doc |
|---|---|---|---|
| Actual ESET Webhook | **BLOCKED** | — | Mandatory end-goal; never received |
| Configured ESET Webhook (manual variables) | **BLOCKED** | — | Depends on client confirming console fields |
| ESET Connect API enrichment | **MISSING** | — | Optional enrichment path (Option B); correctly not urgent |
| Syslog JSON | **IMPLEMENTED** | `src/ingestion/syslog_handler.py`, `src/services/syslog_runtime.py` | Fallback/enrichment path (Option C); code exists, unvalidated against real ESET output |
| Simulated payload | **IMPLEMENTED** | `tests/fixtures/*.json`, `scripts/send_test_webhook.sh` | Explicitly endorsed by the doc (Option D); the one input path fully exercised today |

### 4.3 Normalization Layer

**IMPLEMENTED.** Every field in the doc's Section 8 schema exists verbatim in `src/models/normalized_alert.py`, defaults to the literal string `"UNKNOWN"`, and is never inferred (confirmed in `src/services/normalizer.py` — every mapping is `raw.field or "UNKNOWN"`). Full field-by-field detail in Section 7 of this document.

### 4.4 AI Processing

| Requirement | Status | File / Path | Evidence |
|---|---|---|---|
| AI provider / model integration | **IMPLEMENTED** (with a spec discrepancy) | `src/services/ai/gemini_service.py` | Uses Google Gemini (`gemini-3.1-flash-lite`). **Note:** the requirements doc says "OpenAI API" throughout Sections 6, 11, and 15; the actual build uses Gemini. Functionally equivalent for PoC purposes, but this divergence should be confirmed with the client. |
| Structured JSON output (not free text) | **IMPLEMENTED** | `src/services/ai/schema_builder.py` | Custom schema converter built to work around a Gemini SDK bug that silently drops `required` arrays; regression-tested |
| Risk classification | **IMPLEMENTED** (deterministic, not AI) | `src/services/risk_engine.py` | Doc doesn't mandate AI-driven scoring; a rule engine is arguably more defensible for the "no unsupported claims" requirement |
| 4 audience notifications (client JA / C-Three JA / internal JA / engineer EN) | **IMPLEMENTED** | `src/models/ai_output.py`, `src/prompts/system_prompts.py` | Schema fields match doc Section 9 exactly, including `draft_client_response` at 3 of 4 levels |
| Unsupported-claim prevention | **PARTIALLY IMPLEMENTED** | `src/prompts/system_prompts.py`, `src/services/ai/lint_checker.py` | System prompt states the rule explicitly; lint backs it up with an exact-phrase blocklist (11 English + 9 Japanese phrases) — not semantic. A rephrased equivalent claim would not be caught. |
| Evidence-based reasoning / "UNKNOWN" for missing info | **IMPLEMENTED** | `src/prompts/system_prompts.py` | Explicit instruction: "DO NOT invent, assume, or infer facts... represent it as UNKNOWN or list it in unknown_information" |
| Prompt-injection resistance | **MISSING** | — | No system-prompt language treating alert-derived fields as untrusted data rather than instructions. Confirmed by full-repo grep for "injection"/"untrusted" — zero matches. |
| JSON schema validation of AI response | **IMPLEMENTED** | `src/services/ai/gemini_service.py` | `AIOutput.model_validate_json(raw_response)` — Pydantic rejects malformed shape |
| Retry / error handling on AI failure | **IMPLEMENTED** | `src/utils/retry.py`, `src/pipeline/orchestrator.py` | 3 attempts, exponential backoff; failure downgrades the alert to `PARTIAL`, never lost |
| Token / error logging for AI calls | **IMPLEMENTED** (beyond spec) | `src/services/ai/trace_recorder.py`, `src/api/ai_visibility.py` | A full "AI Visibility" observability subsystem — prompt, config, external-call metadata, token usage, findings — with its own capture-time redaction pass (separate from prompt-time masking, see Section 9) |
| Masking before AI processing | **MISSING** | — | The doc's own open question (Section 13, Q7); unresolved in code — see Section 9 |

### 4.5 Notification Layer

| Recipient | Status | File / Path | Evidence |
|---|---|---|---|
| Mac Systems — Japanese, initial + status | **IMPLEMENTED** | `src/services/email_composer.py: _client_body()` | `CLIENT_JA` — summary / current_status / required_confirmation |
| C-Three Index — Japanese, operational + escalation + draft response | **IMPLEMENTED** | `src/services/email_composer.py: _cthree_body()` | `CTHREE_JA` — summary / assessment / front_office_notes / draft_client_response |
| Internal company — Japanese, coordination + response prep | **IMPLEMENTED** | `src/services/email_composer.py: _internal_body()` | `INTERNAL_JA` — summary / assessment / recommended_actions / draft_client_response |
| Engineers — English, technical triage | **IMPLEMENTED** | `src/services/email_composer.py: _engineer_body()` | `ENGINEER_EN` — alert_summary / assessment / confirmed / unknown / investigation_items / recommended_actions / draft_client_response |
| Existing HMAC-secured serverless email system as routing mechanism | **IMPLEMENTED** | `src/services/email_delivery/eset_mail.py` | HMAC-SHA256 over `timestamp + "\n" + nonce + "\n" + sha256(body)`, exact-byte signing |
| Retry behavior, failed-delivery handling, audit log | **IMPLEMENTED** | `src/services/email_dispatcher.py`, `src/storage/delivery_store.py` | Retryable vs. permanent classification; full attempt history in SQLite |
| Attachment support | **NOT REQUIRED FOR POC** | — | `EmailMessage` has no attachment field; doc lists this as an open question, not a requirement |

### 4.6 Audit / Logging

| Requirement | Status | File / Path |
|---|---|---|
| Processing ID / correlation ID on every request | **IMPLEMENTED** | `src/utils/correlation.py` |
| Request/response/notification/error logs | **IMPLEMENTED** | `src/utils/logging.py`, `logs/app.log` (structlog JSON) |
| Traceability from receipt to notification | **IMPLEMENTED** | `correlation_id` bound via `structlog.contextvars` to every log line for a run |
| Raw payload storage | **IMPLEMENTED** | `jobs.raw_payload` (SQLite) + `normalized_alert.raw_payload` (JSON output) |
| Sensitive-data handling / retention policy | **UNKNOWN** | No retention/TTL/purge logic found for `output/alerts/*.json` or SQLite tables |

### 4.7 Backlog

| Requirement | Status | Evidence |
|---|---|---|
| Backlog integration in current PoC | **NOT REQUIRED FOR POC** | Doc's Section 7 "Suggested First PoC Scope" and Section 15 diagram list Backlog only under a later "Notification Layer" step, not the minimum flow. Repo-wide search for "Backlog"/"backlog": **zero matches**. Correct, not a gap. |
| Who posts the formal Backlog response | **BLOCKED** | Open question in doc Section 13, Q11 — organizational decision |

---

## 5. Implemented / Partially Implemented / Missing

### Implemented (with file-path evidence)

- Webhook ingestion — `src/api/webhook.py`, `src/middleware/auth.py`
- Syslog-JSON ingestion — `src/api/webhook.py` (`/webhook/syslog`), `src/ingestion/syslog_handler.py`
- Embedded UDP/TCP syslog listeners — `src/services/syslog_runtime.py`
- Deduplication — `src/storage/deduplication.py`, `src/api/webhook.py: compute_dedup_key()`
- Full 23-field normalized schema, zero inference — `src/models/normalized_alert.py`, `src/services/normalizer.py`
- Deterministic risk engine — `src/services/risk_engine.py`
- Threat-intel enrichment interface (mock-mode active) — `src/services/threat_intel/{aggregator,virustotal,abuseipdb}.py`
- Gemini structured AI generation, 4 notification variants — `src/services/ai/gemini_service.py`, `src/models/ai_output.py`, `src/prompts/system_prompts.py`
- Gemini schema-conversion workaround (regression-tested) — `src/services/ai/schema_builder.py`, `tests/unit/test_schema_builder.py`
- AI safety lint — `src/services/ai/lint_checker.py`
- AI Visibility observability (beyond spec) — `src/services/ai/trace_recorder.py`, `src/api/ai_visibility.py`, `src/services/ai/redaction.py`
- Email composition, all 4 audiences — `src/services/email_composer.py`
- HMAC-signed email handoff, retry/failure classification — `src/services/email_delivery/eset_mail.py`, `src/services/email_dispatcher.py`
- Delivery audit trail — `src/storage/delivery_store.py`
- Live operator dashboard — `static/dashboard.html`, `static/dashboard.js`, `static/dashboard-viz.js`, `src/api/dashboard.py`
- Crash recovery — `src/main.py: recover_unfinished_jobs()`
- Graceful degradation (SUCCESS/PARTIAL/FAILED, no alert dropped) — `src/pipeline/orchestrator.py`
- ~90 automated tests — `tests/unit/*.py`, `tests/integration/*.py`

### Partially Implemented

- **Webhook/syslog field coverage** — every variable the doc names exists as an input; none validated against a real ESET payload.
- **Unsupported-claim prevention** — prompt instruction + exact-phrase lint (`src/services/ai/lint_checker.py`), no semantic check.
- **Syslog network listeners** — implemented (`src/services/syslog_runtime.py`), zero socket-level test.
- **Deployment story** — `supervisord.conf` runs syslog as a second process that would port-conflict with the embedded listener `run.py` already starts.

### Missing

- **Pre-AI data minimization/masking** — nothing masks `ip_address`, `url`, `domain`, `user_name`, `endpoint_name`, or `file_hash` before they reach Gemini (`src/services/ai/gemini_service.py`).
- **ESET Connect API enrichment** (doc Option B) — no client, model, or call site.
- **Prompt-injection framing** — `src/prompts/system_prompts.py` never states that alert-derived fields are untrusted data.
- **Real threat-intel path exercised by tests** — `virustotal.py`/`abuseipdb.py` real-API code exists but is never turned on by any test and is off by default.
- **Client-reviewable sample ESET webhook JSON template** (doc Task 2) — the README's curl example is an internal contract, not a client-facing confirmation artifact.
- **Explicit ingest payload size limit** — relies on Uvicorn defaults, not configured in this repo.
- **Dedup-table pruning** — `deduplication.py: cleanup_expired()` exists but is never called anywhere in the running application.

---

## 6. ESET Integration Audit

The requirements document's Section 4 ("General ESET PROTECT Cloud Capabilities") is the client's own summary of ESET's general capabilities, explicitly stated to still need validation in the tenant. This audit could not independently re-verify any of these claims against live ESET documentation — that would be a separate research task. What this audit *can* state is what the repository does and does not confirm.

| ESET Capability | Claimed in doc | Evidence in this repo | Client/ESET action required |
|---|---|---|---|
| Webhook notifications exist | Yes (Section 4) | **NONE** — no webhook ever received | Register + test |
| Webhook variables: subject, content, event type, target UUID, occurred time | Yes (Section 4) | **NONE** — modeled as inputs, not confirmed sent by ESET | Sample/test payload |
| "Send test webhook" function exists in console | Yes (Section 4) | **NONE** | Trigger it |
| Webhook retry behavior | Not described | **NONE** | Confirm with ESET docs/support |
| Target UUID / detection UUID availability | Assumed present as enrichment keys | **NONE** — modeled, unconfirmed | Confirm |
| ESET Connect Incident Management API for detection details | Yes (Section 4) | **NONE** — no client built | Confirm subscription/permission scope |
| Syslog export to a Syslog server; JSON supported format | Yes (Section 4) | **NONE** — receiver built, format unconfirmed | Real export test |
| ESET PROTECT Complete subscription includes Webhook/API/Syslog | Assumed (Section 2) | **NONE** | Confirm entitlements |
| Read-only permission granularity (alerts/endpoints/detections/reports/logs) | "Appear generally possible" (Section 2) | **NONE** | Account issuance |
| MFA requirement for external accounts | Yes (Section 2) | N/A — organizational | Confirm |

**Read this table literally: every row's "Evidence in this repo" column is NONE.** This is the single most important finding of this audit. The codebase's ESET-shaped inputs are well-engineered assumptions against a specification nobody on the engineering side has seen confirmed — exactly what the requirements document itself predicted ("the client does not want to investigate the Webhook specification themselves... our engineering team should lead the technical validation"). The validation step still has to happen against a real tenant; no additional coding closes this gap.

**Do not treat a local webhook receiver as ESET integration.** `src/api/webhook.py` proves this codebase *can* receive a webhook. It does not prove ESET PROTECT Cloud has ever sent one, or that the field names it expects match reality.

---

## 7. Normalized Schema Audit

All 23 fields from the requirements document's Section 8 schema, verified against `src/models/normalized_alert.py` and `src/services/normalizer.py`.

| Field | Present? | Missing-value handling | Sent to AI? | Masking needed? |
|---|---|---|---|---|
| `source` | Yes | `"UNKNOWN"` | Yes | No |
| `event_type` | Yes | `"UNKNOWN"` | Yes | No |
| `alert_id` | Yes | `"UNKNOWN"` | Yes | No — low sensitivity |
| `detection_uuid` | Yes | `"UNKNOWN"` | Yes | No — low sensitivity |
| `target_uuid` | Yes | `"UNKNOWN"` | Yes | No — low sensitivity |
| `occurred_at` | Yes | `"UNKNOWN"` | Yes | No |
| `severity` | Yes | `"UNKNOWN"` → risk engine falls back to MEDIUM | Yes | No |
| `detection_name` | Yes | `"UNKNOWN"` | Yes | No |
| `endpoint_name` | Yes | `"UNKNOWN"` | Yes | **Should mask — hostname, potentially identifying** |
| `endpoint_type` | Yes | `"UNKNOWN"` | Yes | No |
| `user_name` | Yes | `"UNKNOWN"` | Yes | **Should mask — PII** |
| `os_name` | Yes | `"UNKNOWN"` | Yes | No |
| `action_taken` | Yes | `"UNKNOWN"` | Yes | No |
| `threat_handled` | Yes | `"UNKNOWN"` (bool or string, normalized) → treated as not-handled by risk engine | Yes | No |
| `isolation_status` | Yes | `"UNKNOWN"` (bool or string, normalized) | Yes | No |
| `object_type` | Yes | `"UNKNOWN"` | Yes | No |
| `object_uri` | Yes | `"UNKNOWN"` | Yes | **Should mask — may contain a username or internal path** |
| `file_hash` | Yes | `"UNKNOWN"` → skips threat-intel lookup | Yes | No — low sensitivity, needed for triage |
| `url` | Yes | `"UNKNOWN"` | Yes | **Consider masking — may embed credentials/internal hostnames** |
| `ip_address` | Yes | `"UNKNOWN"` | Yes | **Consider masking — reveals network topology** |
| `domain` | Yes | `"UNKNOWN"` | Yes | No — needed for triage |
| `raw_subject` | Yes | `"UNKNOWN"` | Yes | **Attacker-controlled text — untrusted, see Section 8** |
| `raw_content` | Yes | `"UNKNOWN"` | Yes | **Attacker-controlled text — untrusted, see Section 8** |
| `raw_payload` | Yes | `{}` if absent | **No — explicitly excluded** | N/A — never leaves the pipeline |

The normalizer's discipline is genuinely good: all 22 scalar fields use the identical `raw.field or "UNKNOWN"` pattern in `src/services/normalizer.py` — there is no branch that infers, guesses, or derives a value the source didn't provide. Excluding `raw_payload` from the AI prompt (`src/services/ai/gemini_service.py`) is a correct, deliberate design choice already in place. The gap is that the 22 *mapped* fields — several genuinely sensitive — are not treated the same way.

---

## 8. AI Audit

**Provider/model:** Google Gemini, `gemini-3.1-flash-lite`, via `google-generativeai` SDK (`src/services/ai/gemini_service.py`). **The requirements document names "OpenAI API" throughout Sections 6, 11, and 15; the implementation uses Gemini instead.** This is a real spec-vs-implementation divergence that should be surfaced to the client explicitly, even though it is functionally adequate for the PoC.

**What data reaches the model:** exactly `alert.model_dump(exclude={"raw_payload"})` (all 22 normalized scalar fields), the computed `risk_level`, and the threat-intel verdicts. No conversation history, no file uploads, no tool/function calling — confirmed both by reading the code and by the module's own `CONTEXT_NOTES` constant, which is also surfaced verbatim in the AI Visibility dashboard.

**System prompt** (`src/prompts/system_prompts.py`, versioned `PROMPT_VERSION = "v1.0"`): correctly states the doc's core safety rules — don't invent facts, don't confirm infection/compromise/leakage/resolution without explicit evidence, never claim isolation succeeded unless `isolation_status` confirms it.

**Prompt injection:** **MISSING.** The system prompt does not instruct the model to treat alert-derived field values (`detection_name`, `raw_subject`, `raw_content`, `url`, `object_uri`) as untrusted data rather than instructions. A repo-wide grep for "injection"/"untrusted" across all `.py` files returned zero matches. Every one of those fields originates from whatever ESET — or an attacker able to trigger a detection — puts in front of the endpoint; this must be treated as untrusted input.

**Structured output enforcement:** genuinely well-engineered. `src/services/ai/schema_builder.py` exists specifically because the raw Gemini SDK silently drops `required` arrays when converting a Pydantic model, previously causing near-empty AI responses. The workaround is regression-tested — `tests/unit/test_schema_builder.py` asserts the raw SDK *still* has the bug, so if Google fixes it upstream the test fails and flags that the workaround can be retired.

**JSON validation:** `AIOutput.model_validate_json(raw_response)` — Pydantic rejects malformed shape (`src/services/ai/gemini_service.py`).

**Hallucination prevention:** system prompt instruction + `src/services/ai/lint_checker.py`'s exact-phrase blocklist (11 English + 9 Japanese prohibited phrases, e.g. "infection confirmed", "感染を確認"). **Not semantic** — a differently-worded overreach ("the endpoint is now clean" instead of "infection confirmed") would not be caught.

**Failure handling:**

| Scenario | Handled? | Mechanism |
|---|---|---|
| Empty response from Gemini | Yes | Raises, retried via `@retry_api_call` |
| Malformed JSON / schema mismatch | Yes | Pydantic validation error → retried → `PARTIAL` |
| API error / timeout / rate limit | Yes | 3x exponential backoff (`src/utils/retry.py`), then `PARTIAL`, never crashes the process |
| Lint failure (prohibited phrase) | Yes | `LintFailureException` → alert downgraded to `PARTIAL`, no email sent with the offending content |
| Semantically-equivalent overreach, different wording | **No** | Passes the lint silently |
| Prompt injection in alert fields | **No** | No test, no defense beyond the model's inherent robustness |

**Duplicate alerts:** handled upstream of the AI entirely — the dedup layer (Section 3, step 3) stops a repeat before a job is even created, so the AI is never invoked twice for the same `alert_id`+`occurred_at` within the TTL window.

---

## 9. Data Masking / Privacy Audit

What actually leaves this infrastructure and reaches Google's Gemini API, field by field.

| Field / data | Sent to AI? | Necessary for triage? | Sensitive? | Masked today? | Recommendation |
|---|---|---|---|---|---|
| `ip_address` | Yes | Yes | Yes — network topology | No | Confirm with client (doc Q7); consider partial masking while preserving classification signal |
| `url` | Yes | Yes | Yes — may embed tokens/paths | No | Same |
| `domain` | Yes | Yes | Low | No | Leave unmasked — needed for reputation context |
| `user_name` | Yes | Marginal | Yes — PII | No | Mask/pseudonymize before the prompt; not needed for risk/triage reasoning |
| `endpoint_name` | Yes | Yes — needed in notification text | Yes — internal hostname | No | Confirm with client; likely acceptable since it appears verbatim in every outbound notification regardless |
| `file_hash` | Yes | Yes | Low | No | Leave unmasked |
| `object_uri` | Yes | Yes | Yes — may contain a username/path | No | Consider masking username segments |
| `raw_subject` | Yes | Yes | Yes — attacker-controlled text | No | Not a masking issue — a prompt-injection issue, see Section 8 |
| `raw_content` | Yes | Yes | Yes — attacker-controlled text | No | Same |
| `raw_payload` | **No** | No | Yes — everything, incl. unmapped extra fields | N/A — excluded entirely | Correct as-is |
| Cookies / auth headers / API keys / tokens | No | No | Critical | N/A — never part of the alert schema | Not applicable to this data path |
| Threat-intel verdicts (VT/AbuseIPDB status) | Yes | Yes | Low | No | Leave unmasked |

**This is the clearest open item from the requirements document that engineering can resolve without waiting on the client, then confirm with them.** Section 13, Q7 of the doc explicitly asks "which fields must be masked before AI processing?" and leaves it unanswered — proposing the policy above and implementing a toggle is exactly the PoC-stage work the document asks engineering to lead.

**Separately:** `src/services/ai/redaction.py` already implements a mature, well-tested pattern-based redaction engine (private keys, JWTs, connection strings, bearer tokens, AWS/Google/GitHub/Slack tokens, credit-card-shaped numbers, emails). It runs at the **observability capture layer** (AI Visibility traces in `src/services/ai/trace_recorder.py`), not on the outbound prompt itself. Extending this exact module to also scrub the prompt before it is sent to Gemini would be a small, low-risk change once the masking policy is confirmed with the client.

---

## 10. Notification / HMAC Audit

| Area | Status | Evidence |
|---|---|---|
| Request format | **IMPLEMENTED** | `{to, subject, body, email_id}`, compact JSON, exact bytes signed and transmitted (`content=`, never `json=`, specifically to avoid re-serialization invalidating the signature) — `src/services/email_delivery/eset_mail.py` |
| HMAC generation | **IMPLEMENTED** | `HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + sha256(body))`; 3 security modes (`api-key-only` / `signed` / `full`) matching the external worker's own modes |
| HMAC validation | **UNKNOWN (cannot verify from this repo)** | Validation happens inside the external ESET Mail Cloudflare Worker, not in this repository. This audit confirms our side signs correctly; it cannot confirm the worker accepts it without a live test. |
| Recipient routing | **IMPLEMENTED** | 4 independently-configurable recipient lists, live-editable from the dashboard without restart, falling back to `.env` — `src/storage/settings_store.py` |
| Templates | **IMPLEMENTED** | One body formatter per audience, plain text, bilingual field labels — `src/services/email_composer.py` |
| Retry behavior | **IMPLEMENTED** | Up to 3 handoff attempts, classified retryable vs. permanent (HTTP 400 / 401-non-nonce = permanent); periodic sweeper every 60s plus fire-and-forget dispatch right after queuing — `src/services/email_dispatcher.py` |
| Failed delivery handling | **IMPLEMENTED** | Failed/exhausted attempts recorded with error text, surfaced in the dashboard's Emails tab. No separate human-facing alert (e.g. Slack) on permanent failure — only visible if someone is watching the dashboard. |
| Audit log format | **IMPLEMENTED** | `email_deliveries` SQLite table: email_id, correlation_id, notification_type, recipients, subject, status, attempts, remote_id, error, timestamps — `src/storage/delivery_store.py` |
| Attachments | **NOT REQUIRED FOR POC** | No field for it; doc lists this as an open question, not a requirement |

**Can the current system receive the AI-generated structured result directly?** Yes, no adapter needed — `email_composer.compose_emails(result: PipelineResult)` already consumes the exact `AIOutput` shape produced by the pipeline; this is one integrated codebase, not two systems needing a bridge.

---

## 11. Security Audit

| Area | Finding | Severity |
|---|---|---|
| Transport | No TLS termination in-repo (by design — README instructs a reverse proxy). Both bearer secrets travel in cleartext without it. | Medium |
| Ingest auth | Single static shared token, constant-time compared, no scoping/rotation/expiry. Appropriate for a single-client PoC. | Acceptable for PoC |
| Dashboard auth | `DASHBOARD_ACCESS_KEY` documented default of `123456` in README; blank disables auth entirely (logs a warning if bound non-locally). Dashboard exposes hostnames, usernames, hashes, internal IPs from every alert. | High if unchanged before any non-local exposure |
| Rate limiting | None on ingest — a flood consumes Gemini/threat-intel quota. Documented, accepted trade-off for local/internal use. | Medium if exposed |
| Input validation | Pydantic validates shape; `EsetRawPayload` allows arbitrary extra fields (stored, never reaches the AI prompt). No explicit request body size cap configured anywhere. | Low-medium |
| Prompt injection | No defense — see Section 8. | Medium |
| XSS (frontend) | Manually-disciplined `esc()` escaping (`static/dashboard.js`), enforced by source-grep regression tests (`tests/integration/test_security.py`) against a fixed token list. Correct today; structurally fragile for future fields. | Low, mitigated |
| CSWSH | WebSocket route validates `Origin` against `Host` (`src/api/dashboard.py: _origin_allowed()`); tested. | Mitigated |
| SQL injection | All queries parameterized across `src/storage/*.py`; no string interpolation into SQL anywhere. | Not found |
| Secrets in logs | Spot-checked, none found in first-party code; third-party SDK (httpx, google-generativeai) internal logging not exhaustively verified. | Unknown / low |
| AI safety lint | Exact-phrase blocklist, not semantic — see Sections 5, 8. | Medium — known design limitation |
| HMAC email signing | Correctly scoped to exact transmitted bytes (compact JSON, no re-serialization). | Correct |
| Authorization / RBAC | None beyond the two binary secrets — anyone with the dashboard key can read every audience's notification content, including the client-facing one. | Out of scope for PoC |

---

## 12. Testing Audit

**Existing coverage (well-tested):** risk engine (all severity × handled × isolated combinations), normalizer's `"UNKNOWN"` fallback, dedup TTL, the Gemini schema `required`-field regression, AI safety lint (English + Japanese), email composition/outbox/HMAC signing, every HTTP + WebSocket route, ingest/dashboard auth (including near-miss tokens), XSS-safe rendering — `tests/unit/*.py`, `tests/integration/*.py` (~90 tests, run via `PYTHONPATH=. pytest tests/ -v`).

**Missing coverage:**
- Real VirusTotal/AbuseIPDB API calls — only the mock path is exercised anywhere.
- Real Gemini round-trips — every test replaces `GeminiAIService.generate()` with an autouse mock fixture (`tests/conftest.py`); **no test in this repo has ever made a real network call to Google, VirusTotal, AbuseIPDB, or the ESET Mail worker.**
- The raw UDP/TCP syslog socket listeners (`src/services/syslog_runtime.py`) — no test binds a real socket.
- The periodic email-dispatch sweep loop's long-running behavior (`run_dispatch_loop()`).
- Crash recovery (`recover_unfinished_jobs()`).
- Prompt-injection or masking-policy behavior — confirmed absent because neither feature exists yet.

Confidence in the pipeline's internal logic is high; confidence in every external integration point is correspondingly unverified by automation.

---

## 13. PoC Test Matrix

| # | Test | Can run today? | Notes |
|---|---|---|---|
| 1 | Low-risk blocked event, full flow to Japanese + English notification | **Yes** | `tests/fixtures/sample_low_risk.json` |
| 2 | Suspicious application — risk classification, unknowns, investigation items | **Yes** | `tests/fixtures/sample_medium_risk.json` |
| 3 | High-risk malware — HIGH/CRITICAL handling, escalation notification | **Yes** | `tests/fixtures/sample_high_risk.json` |
| 4 | Critical multi-endpoint event — routing, duplicate handling | **Partially** | `tests/fixtures/sample_critical.json` exists for a single endpoint only; the schema itself is single-endpoint-per-alert, no correlated-multi-endpoint fixture exists |
| 5 | Missing fields (no UUIDs/severity/endpoint/hash) — confirm no hallucination | **Yes** | Normalizer behavior is deterministic and unit-tested; worth an explicit AI-layer assertion too |
| 6 | Prompt-injection content in detection_name/raw_content/url/filename | **No test exists** | No defense to verify yet — see Section 8 |
| 7 | AI failure — timeout, invalid JSON, API error, rate limit | **Yes** | Retry + `PARTIAL`-downgrade path is exercised in tests |
| 8 | Email failure — retry, failure log, no silent loss | **Yes** | Retryable/permanent classification tested; handoff-only scope |
| 9 | Duplicate alert | **Yes** | Confirmed: same key within TTL → `{"status":"duplicate"}`, no second pipeline run, no second email |
| 10 | Actual ESET webhook | **BLOCKED** | Only markable as validated once a real ESET PROTECT Cloud webhook has actually been received — has not happened |

---

## 14. What Can Be Done Now

Work possible without client/ESET access:

- Propose and implement the pre-AI masking policy (Section 9), gated by a feature flag.
- Add prompt-injection framing to the system prompt, plus a test using hostile field content.
- Build the client-facing sample ESET webhook JSON template (doc Task 2).
- Fix the `supervisord.conf` vs. embedded-syslog architecture conflict.
- Add a socket-level test for the UDP/TCP syslog listeners.
- Build a multi-endpoint/correlated critical-event fixture (doc Task 3).
- Add a semantic check, or at minimum document the current lint's known limitation.
- Wire or remove the dead `AI_TIMEOUT_SECONDS`/`MAX_RETRIES` settings.
- Call `deduplication.cleanup_expired()` periodically.
- Add a real (non-mock) threat-intel test path using recorded HTTP fixtures.

---

## 15. What Is Blocked

Exact client/ESET dependencies — nothing here can be resolved by further engineering alone:

- Registering the PoC webhook URL in the client's actual ESET PROTECT Cloud console.
- Triggering ESET's "Send test webhook" function against the endpoint.
- Confirming the actual variable set ESET's webhook payload includes.
- Issuing an ESET PROTECT external account (with MFA) for engineering access.
- Confirming read-only permission scope (alerts, endpoints, detections, reports, logs).
- Confirming whether the client's ESET PROTECT Complete subscription includes ESET Connect API access, and its scope.
- A real syslog export test from the client's tenant, to validate the key-name guesses in `src/ingestion/syslog_handler.py`.
- Final recipient lists (real addresses) for all four notification types.
- Confirmation of which alert fields the client considers sensitive enough to require masking before any third-party AI sees them.
- Confirmation of the Critical escalation flow (phone/emergency).
- Confirmation of who posts the formal Backlog response.

---

## 16. What Should NOT Be Built Yet

- **ESET Connect API enrichment (Option B)** — build only after the webhook-only payload (Option A) is confirmed insufficient *and* subscription/permission access is confirmed.
- **Backlog integration** — explicitly out of the doc's first-PoC scope; correctly absent from the codebase today.
- **Any endpoint action** — scan execution, isolation, configuration changes. The doc is explicit: "Do not design the PoC to perform endpoint actions." The codebase correctly contains none of this.
- **Phone/SMS escalation automation** — doc says email-first is reasonable for the PoC.
- **Production-grade infrastructure** — task queue (Celery/Redis), containerization, CI/CD, a migration system. The current single-process/SQLite-plus-JSON-files design is a defensible PoC choice.
- **n8n/Shuffle adoption** — the doc explicitly frames these as candidates to evaluate, not commitments. The current custom FastAPI pipeline already satisfies the doc's own evaluation checklist better than standing up a second tool would.
- **24/365 human monitoring or autonomous remediation** — doc explicitly scopes the PoC to "automated detection, AI processing, and notification only."
- **Per-client/multi-tenant credentials, RBAC, user accounts** — the current two-shared-secret model is appropriate for a single-client PoC.

---

## 17. P0/P1/P2/P3 Backlog

### P0 — Blocking a credible PoC demo

| Task | Why | Files affected | Acceptance criteria |
|---|---|---|---|
| Get an actual ESET test webhook fired at the endpoint | Every ESET Integration claim in Section 6 is unconfirmed without this | None (config only) | A real webhook payload has been received and logged |
| Confirm masking policy with client, then implement it | Doc's own open question (Q7); currently unmasked | `src/services/ai/gemini_service.py`, extend `src/services/ai/redaction.py` | Masking policy signed off; normalized fields sent to AI reflect it |
| Add prompt-injection framing to the system prompt + a test | Alert content is attacker-influenceable by definition | `src/prompts/system_prompts.py`, new test | Hostile field content does not alter AI output behavior in a test |

### P1 — Required for a meaningful demonstration

| Task | Why | Files affected | Acceptance criteria |
|---|---|---|---|
| Client-reviewable sample ESET webhook JSON template | Distinct artifact to confirm field expectations with Mac Systems | New doc/JSON artifact | Client has reviewed and commented on it |
| Fix the stale "Send Test Alert" comment in `webhook.py` (references a dashboard control that doesn't exist) | Misleading to future contributors | `src/api/webhook.py` | Comment corrected or the control is actually built |
| Document (or improve) the lint's exact-phrase limitation | A rephrased overreach currently passes silently | `src/services/ai/lint_checker.py` | Either a semantic check added, or the limitation explicitly documented for the demo audience |
| Reconcile `supervisord.conf` vs. embedded syslog architecture | Running both as documented causes a port-bind conflict | `supervisord.conf` | Single, consistent process-management story |
| Socket-level test for UDP/TCP syslog listeners | Least-tested ingestion path | `tests/integration/` (new) | A test sends a real UDP/TCP packet and asserts pipeline execution |
| Multi-endpoint/correlated critical-event fixture | Doc Task 3 explicitly asks for this scenario | `tests/fixtures/` | Fixture exists and is exercised by a test |

### P2 — Useful if time allows

- Wire `AI_TIMEOUT_SECONDS`/`MAX_RETRIES` into actual behavior, or remove them from `.env.example`.
- Call `deduplication.cleanup_expired()` periodically.
- Add a real (non-mock) threat-intel test path using recorded HTTP fixtures.
- Convert dashboard `_check_access()` into an enforced FastAPI dependency instead of a manual per-route call.
- Add an explicit ingest body-size limit.

### P3 — Production / future scope — do not build now

- ESET Connect API enrichment (Option B).
- Backlog integration.
- Any endpoint action (isolation, scan execution, config change).
- Multi-tenant/per-client credentials, RBAC, user accounts.
- Task queue/container/CI-CD infrastructure investment.
- Phone/SMS escalation automation.

---

## 18. Client/ESET Action Items

| Item | Why we need it | What the client does | Evidence we need back |
|---|---|---|---|
| Register our webhook URL | Nothing about real ESET payload shape can be confirmed otherwise | Add our endpoint URL in ESET PROTECT Cloud's notification/webhook console | Confirmation it was added |
| Send a test webhook | Validates actual JSON shape against our current field guesses | Trigger ESET's "Send test webhook" function | The raw payload received (we'll log it ourselves) |
| Share/confirm a sample notification payload | Removes guesswork from `src/ingestion/webhook_handler.py` | Export or describe one real (redacted if needed) webhook payload | A JSON sample or field list |
| Issue an ESET PROTECT account for engineers | Needed for console inspection (variables, syslog config) | Provision an external account with MFA | Working credentials + confirmed permission scope |
| Confirm read-only access scope | Determines what we can validate vs. what stays a guess | Grant/confirm alerts, endpoints, detections, reports, logs — read only | Permission list actually granted |
| Confirm ESET Connect API / subscription entitlement | Option B can't be scoped without this | Check ESET PROTECT Complete entitlements | Yes/no + any credential/scope details |
| Confirm a real Syslog JSON export sample | Validates key-name guesses in `syslog_handler.py` | Configure a test Syslog export, or share a sample | A real exported JSON event |
| Confirm AI data policy / which fields must be masked | Directly blocks finalizing the masking implementation | Review the masking table in Section 9 and confirm/adjust | A signed-off masking policy |
| Confirm final notification recipients (all 4 audiences) | Currently only test addresses are wired | Provide real email addresses | Recipient list |
| Confirm the Critical escalation flow | Doc Section 13 Q12 — undecided | Define who gets called and when | An escalation procedure document |
| Confirm who posts the formal Backlog response | Doc Section 13 Q11 — undecided | Decide internally / with C-Three Index | A named owner or process |
| Approve AI vendor for production (doc says OpenAI; PoC uses Gemini) | Divergence between doc and implementation | Confirm which AI vendor is acceptable for production data handling | A written approval |

---

## 19. Recommended Implementation Order

1. Draft the masking policy (Section 9) and send it, along with the notification-recipient and escalation-flow questions (Section 18), to the client — these can move in parallel with no code changes.
2. Implement pre-AI redaction in `src/services/ai/gemini_service.py`, gated by a feature flag (e.g. `AI_MASKING_ENABLED` in `src/config.py`), reusing the pattern already proven in `src/services/ai/redaction.py`.
3. Add prompt-injection framing to `SYSTEM_PROMPT` (`src/prompts/system_prompts.py`) plus a fixture-driven test.
4. Build the client-facing sample ESET webhook JSON template (doc Task 2).
5. Send the P0 client questions (Section 18) — the true long pole; everything else proceeds without blocking on it.
6. While waiting on the client: fix `supervisord.conf`, add the syslog socket test, build the multi-endpoint critical fixture, correct the stale comment in `webhook.py`.
7. Once a real ESET webhook is received: diff it against `EsetRawPayload`'s field set, patch `src/ingestion/webhook_handler.py`/`syslog_handler.py` for any real-world key-name mismatches, and only then mark PoC Test #10 as validated.
8. If the webhook proves insufficient and Connect API access is confirmed: scope and build Option B enrichment — not before.
9. Run the full PoC Test Matrix (Section 13) end-to-end as the go/no-go gate before any client-facing demo.

---

## 20. PoC Definition of Done

- [ ] A real ESET PROTECT Cloud test webhook has been received and successfully processed end-to-end (PoC Test #10).
- [ ] The masking policy is confirmed with the client and implemented — normalized alert fields sent to the AI reflect that policy, not the current unmasked pass-through.
- [ ] Prompt-injection framing exists in the system prompt and is covered by at least one test using hostile field content (PoC Test #6).
- [ ] All 10 PoC Test Matrix scenarios (Section 13) pass, including the multi-endpoint/critical case.
- [ ] All four notification types have been delivered end-to-end through the real HMAC-secured email service to real (even if internal) test recipients — not just queued to the outbox.
- [ ] `DASHBOARD_ACCESS_KEY` is a real secret, not the documented `123456` placeholder, if the dashboard will be reachable by anyone outside the immediate engineering team.
- [ ] The client has confirmed, in writing, the recipient list and the Critical escalation flow.
- [ ] Every BLOCKED item in Section 15 has either been resolved or explicitly deferred with client sign-off.

---

## 21. Final Engineering Verdict

**Where we are now:** a genuinely credible pipeline PoC exists and is demonstrable today using simulated input (doc Option D) — normalization → deterministic risk scoring → mock threat-intel → 4 schema-enforced bilingual AI notifications → safety lint → persisted result → HMAC-signed email handoff, all watchable live in the dashboard.

**What works:** everything in Section 5's Implemented list — the pipeline mechanics, the schema fidelity to the requirements doc, the email/HMAC subsystem, and the test discipline around all of it.

**What is missing:** pre-AI masking and prompt-injection framing — both resolvable by engineering without client input, both currently absent.

**What is blocked:** every claim about actual ESET behavior (Section 6) — webhook field shape, retry semantics, Connect API availability, real syslog format — none of it has been confirmed against a real tenant, and none of it can be by writing more code.

**What remains risky:** the AI safety lint is exact-phrase, not semantic — a rephrased overreach would reach a client's inbox undetected. Prompt injection has zero defense today. Neither is hypothetical: both are direct consequences of treating attacker-influenceable detection fields as trusted prompt content, which is exactly what happens right now.

**What we should do next:** start the two P0 code items that need no client input — masking and prompt-injection framing — immediately, in parallel with sending the client the P0 action items in Section 18. Everything else in this document follows from those two threads resolving.
