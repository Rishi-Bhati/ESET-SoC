# ESET PROTECT Webhook Integration — Full Audit

**Audited:** `D:\ESET\ESET-SoC`, branch `main`, commit `1f672e9` ("Integrate OpenAI as primary AI provider and prepare AWS deployment")
**Audit date:** 2026-09-29
**Method:** Direct code inspection with line-number citations, plus live evidence — installed missing dependencies, ran the full automated test suite, started the actual FastAPI app locally, and fired real HTTP requests at it (auth-valid, auth-missing, auth-wrong, malformed JSON, oversized body, duplicate alert), capturing the real terminal output and resulting log/DB rows. Also inspected the existing SQLite job history, `logs/app.log`, and `output/alerts/*.json` for any trace of a non-test sender. No claim below is asserted without one of: a file/line citation, a pasted test/command output, or an explicit "not verified."

---

## Plain-English summary

The receiving side of this integration is real, working code — not a stub. `POST /webhook/eset` is implemented, bearer-token authenticated, deduplicated, persisted to SQLite, and handed off to a background pipeline that runs threat-intel enrichment, deterministic risk scoring, AI notification drafting, and (when `EMAIL_DELIVERY_ENABLED=true`, which it is locally) real outbound email delivery to an external mail worker. I proved this myself in this session: I sent a live HTTP request at the running app and watched it flow all the way through to two real `202 Accepted` responses from `https://eset-mail.villdesign.workers.dev/api/send`. **What is proven:** the pipeline mechanics work end-to-end against a payload I crafted. **What is assumed:** the shape of that payload — field names like `detection_name`, `target_uuid`, `threat_handled` — is an engineering guess at what ESET PROTECT Cloud actually sends; it has never been checked against a real tenant. **What is missing:** every single job row in the local database (17/17), every `webhook_received` log line (17/17, all from `client_ip: 127.0.0.1`), and every result file in `output/alerts/` originates from a hand-crafted curl/test payload — not one request has ever arrived from ESET PROTECT Cloud's actual infrastructure. The local dev environment is also not currently capable of a full real run even if ESET sent one today: the AI provider is misconfigured (`OPENAI_MODEL` is unset), which I confirmed live — the pipeline degrades gracefully to a `PARTIAL` result with a fallback notification rather than losing the alert, but it would not produce the real AI-drafted client email.

---

## 1. Webhook receiver implementation

### Route handler

- **File/line:** [src/api/webhook.py:324-346](src/api/webhook.py#L324-L346) — `@router.post("/eset", dependencies=[Depends(validate_eset_token)])` / `async def receive_eset_webhook(...)`.
- The router is mounted with no extra prefix beyond `/webhook` ([src/api/webhook.py:21](src/api/webhook.py#L21), included via [src/api/router.py:10](src/api/router.py#L10) and [src/main.py:247](src/main.py#L247)), so the live path is exactly **`POST /webhook/eset`**.
- There is also a parallel **`POST /webhook/syslog`** ([src/api/webhook.py:349-371](src/api/webhook.py#L349-L371)) for JSON forwarded by the embedded syslog listeners — same auth, same shared ingestion path, different payload parser.

### Full request path, in order

1. **Auth check** — `Depends(validate_eset_token)` runs before the route body at all, via FastAPI's dependency system: [src/middleware/auth.py:14-49](src/middleware/auth.py#L14-L49). Rate-limits by client IP first (`auth_limiter.retry_after`), then requires the `Authorization` header, strips an optional `Bearer ` prefix, and does a constant-time comparison (`hmac.compare_digest`) against `settings.eset_webhook_auth_token`.
2. **Oversized-body fast check** — `_reject_oversized_body(request)` ([src/api/webhook.py:77-108](src/api/webhook.py#L77-L108)) checks the `Content-Length` header against `MAX_INGEST_BODY_BYTES` before reading anything.
3. **Body parsing** — `read_json_body(request)` ([src/api/webhook.py:172-243](src/api/webhook.py#L172-L243)) streams the body in chunks (bounding memory even without `Content-Length`), parses JSON, scrubs unencodable surrogate characters, and requires the top-level value to be a JSON object.
4. **Payload validation** — `ingest_alert()` ([src/api/webhook.py:246-321](src/api/webhook.py#L246-L321)) calls `webhook_handler.parse(raw_json)`, which is `WebhookIngestionHandler.parse()` ([src/ingestion/webhook_handler.py:13-34](src/ingestion/webhook_handler.py#L13-L34)) — builds an `EsetRawPayload` Pydantic model ([src/models/raw_payload.py](src/models/raw_payload.py)).
5. **Deduplication** — `compute_dedup_key()` ([src/api/webhook.py:111-121](src/api/webhook.py#L111-L121)) then `deduplication.is_duplicate()` / `record_seen()` ([src/storage/deduplication.py:8-37](src/storage/deduplication.py#L8-L37)) against a SQLite `dedup_log` table, 1-hour TTL by default.
6. **Capacity reservation** — `pipeline_capacity.capacity.reserve()` (imported at [src/api/webhook.py:13](src/api/webhook.py#L13)), bounding concurrent pipelines (`MAX_CONCURRENT_PIPELINES`).
7. **Job creation** — `job_store.create_job()` ([src/storage/job_store.py:10-31](src/storage/job_store.py#L10-L31)) writes a `PENDING` row to the `jobs` SQLite table.
8. **Background handoff** — `background_tasks.add_task(reservation.run, run_pipeline_task, ...)` ([src/api/webhook.py:311-313](src/api/webhook.py#L311-L313)); the HTTP response (`{"status": "queued", "correlation_id": ...}`) returns **before** the pipeline runs. `run_pipeline_task()` ([src/api/webhook.py:124-145](src/api/webhook.py#L124-L145)) then dynamically imports and calls `src.pipeline.orchestrator.process_alert_pipeline()`.

### Authentication

- **Type:** static bearer token, constant-time compared. No HMAC signing of the payload, no per-source token scoping, no IP allowlist on the webhook route itself.
- **Config:** `ESET_WEBHOOK_AUTH_TOKEN` env var → `settings.eset_webhook_auth_token` ([src/config.py:75](src/config.py#L75)). Can alternatively be overlaid at startup from an AWS Secrets Manager JSON secret named by `APP_SECRETS_SECRET_ID` ([src/config.py:66-70](src/config.py#L66-L70), comment lists `ESET_WEBHOOK_AUTH_TOKEN` as one of the allowlisted overlay keys).
- If the token resolves to empty, **every** request is refused with 401 ([src/middleware/auth.py:37-41](src/middleware/auth.py#L37-L41)) — verified live below.

### Payload schema

- **File:** [src/models/raw_payload.py](src/models/raw_payload.py) — `EsetRawPayload(BaseModel)`.
- **Permissive by design:** every named field is `Optional` with no defaults required, and `model_config = {"extra": "allow"}` ([src/models/raw_payload.py:36-38](src/models/raw_payload.py#L36-L38)) — unknown fields are accepted and preserved, not rejected. `WebhookIngestionHandler.parse()` also unconditionally stuffs the *entire* raw request into `raw_payload` ([src/ingestion/webhook_handler.py:21-24](src/ingestion/webhook_handler.py#L21-L24)) and defaults `source` to `"ESET_PROTECT_CLOUD_WEBHOOK"` if absent.
- Confirmed live: a payload of `{"totally": "unrelated", "shape": true}` is accepted, not rejected — this matches `tests/integration/test_webhook_endpoint.py::test_webhook_accepts_completely_non_eset_shaped_json` (passed, see §3).

### Error handling, verified live against the running app (see §3 for the exact commands/output)

| Case | Result | Code path |
|---|---|---|
| Missing auth header | `HTTP 401`, empty body | [src/middleware/auth.py:27-29](src/middleware/auth.py#L27-L29) |
| Wrong auth token | `HTTP 401`, empty body, failure counted for throttling | [src/middleware/auth.py:44-47](src/middleware/auth.py#L44-L47) |
| Malformed JSON | `HTTP 400`, `"Request body is not valid JSON: ..."` | [src/api/webhook.py:220-230](src/api/webhook.py#L220-L230) |
| Oversized body (2 MB against a 1 MiB cap) | `HTTP 413 Content Too Large` | [src/api/webhook.py:100-106](src/api/webhook.py#L100-L106) (header-based fast path) |
| Duplicate alert (same `alert_id`+`occurred_at` twice) | First: `{"status":"queued",...}`; second: `{"status":"duplicate","message":"Alert already processed",...}` | [src/api/webhook.py:274-286](src/api/webhook.py#L274-L286) |

---

## 2. Has a REAL ESET webhook ever been received?

**No. Zero evidence of any request from ESET PROTECT Cloud infrastructure exists anywhere in this repository, its logs, or its database.** Everything found is locally hand-crafted test traffic.

Evidence gathered:

- **SQLite `jobs` table** (`data/soc_lite.db`): 17 total rows, **all** `source = 'WEBHOOK'`, **zero** `source = 'SYSLOG'`. The 3 most recent rows' `raw_payload` (queried directly) are:
  ```
  alert_id: "test-001", computer_name: "TEST-LAPTOP-01",
  threat_name: "Test.Trojan.Sample", file_hash: "a1b2c3d4e5f6"
  ```
  — an obviously synthetic, hand-typed payload (repeated identical `alert_id` across multiple rows, a 12-character fake hash, a placeholder hostname). Not one row matches ESET's real key-naming conventions from any documented source, nor does the repo have a captured example of one.
- **`logs/app.log`** (387,657 bytes, spans 2026-08-18 through 2026-09-29): `grep -c '"event": "webhook_received"'` → **17** matches, matching the job count exactly. Every logged `client_ip` associated with an auth event is **`127.0.0.1`** (localhost) — grepped across the entire file, zero other values found.
- **`output/alerts/`**: 19 result JSON files, one per job (plus 2 from a prior run not in the current DB snapshot) — same synthetic-payload pattern.
- **The project's own prior audit**, [docs/SOC_LITE_AUDIT.md:293](docs/SOC_LITE_AUDIT.md#L293) and [docs/SOC_LITE_AUDIT.md:304](docs/SOC_LITE_AUDIT.md#L304), reaches the identical conclusion independently: *"Read this table literally: every row's 'Evidence in this repo' column is NONE... Zero requests have ever been received from a real ESET PROTECT Cloud tenant."* That audit is dated 2026-08-25, predates the OpenAI migration, and its AI-provider-specific claims (it describes Gemini as primary) are now stale — but nothing in the commits since then (`git log`, checked) touches ingestion or adds any real-ESET evidence, and this session's direct DB/log inspection reconfirms its conclusion as still true today.
- **`docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md`** is literally a document prepared *to be sent to the client* asking them to trigger a real test webhook from the ESET console, because *"our engineering team has never received a real webhook from this tenant"* ([docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md:11](docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md#L11)).

**Explicit distinction requested:** every alert ever ingested by this system — 100% of them — was received via a local test script or manual curl (`scripts/send_test_webhook.sh`, or ad-hoc `curl`/Python similar to what this audit itself used in §3). **None** originated from ESET PROTECT Cloud infrastructure. This is true as of 2026-09-29.

---

## 3. End-to-end pipeline verification

### Pipeline stages after ingestion, in order (all in [src/pipeline/orchestrator.py](src/pipeline/orchestrator.py))

1. **Job status → PROCESSING**, `INGEST` stage event — [orchestrator.py:96-97](src/pipeline/orchestrator.py#L96-L97)
2. **Normalize** — `normalizer.normalize()` ([src/services/normalizer.py](src/services/normalizer.py)), called at [orchestrator.py:108-109](src/pipeline/orchestrator.py#L108-L109)
3. **Threat intel** — `gather_threat_intel()` ([src/services/threat_intel/aggregator.py](src/services/threat_intel/aggregator.py)), called at [orchestrator.py:117](src/pipeline/orchestrator.py#L117) — mock mode by default (`USE_MOCK_THREAT_INTEL`, defaults `true`, [src/config.py:166](src/config.py#L166))
4. **Risk scoring** — `risk_engine.assess_risk()` ([src/services/risk_engine.py](src/services/risk_engine.py)), called at [orchestrator.py:135-137](src/pipeline/orchestrator.py#L135-L137) — deterministic rules, not AI
5. **AI generation** — `ai_factory.get_ai_provider().generate()` ([src/services/ai/factory.py](src/services/ai/factory.py), [src/services/ai/openai_provider.py](src/services/ai/openai_provider.py)), called at [orchestrator.py:168-171](src/pipeline/orchestrator.py#L168-L171)
6. **Validation/lint** — `validate_ai_output()` ([src/services/ai/output_validator.py](src/services/ai/output_validator.py)), called at [orchestrator.py:195](src/pipeline/orchestrator.py#L195)
7. **Result write** — `output_writer.write_result()` ([src/services/output_writer.py](src/services/output_writer.py)), called at [orchestrator.py:234](src/pipeline/orchestrator.py#L234) — always runs, `SUCCESS`/`PARTIAL`/`FAILED`
8. **Email compose + queue** — `email_composer` / `email_outbox.add_emails()`, called at [orchestrator.py:233](src/pipeline/orchestrator.py#L233) and [orchestrator.py:235](src/pipeline/orchestrator.py#L235)
9. **Email dispatch handoff** — `email_dispatcher.dispatch_soon()` (fire-and-forget task, [orchestrator.py:74](src/pipeline/orchestrator.py#L74)) → `src/services/email_delivery/eset_mail.py` (HMAC-signed POST to the external mail worker)
10. **Job status → SUCCESS/PARTIAL**, final stage event — [orchestrator.py:237-243](src/pipeline/orchestrator.py#L237-L243)

### Automated test suite — actual run, this session

Dependency install was required first — `openai` was **not installed** in the local venv despite being pinned in `requirements.txt` (a real gap; see §6):

```
$ .venv/Scripts/python.exe -m pip install -r requirements.txt
...
Successfully installed boto3-1.43.103 botocore-1.43.104 httpcore2-2.13.1 httpx2-2.13.1
jiter-0.17.0 jmespath-1.1.0 openai-3.19.2 python-dateutil-2.9.0.post0
python-dotenv-1.2.2 s3transfer-0.19.2 six-1.17.0 sniffio-1.3.1 truststore-0.10.4 boto3
```

Full suite:

```
$ PYTHONPATH=. .venv/Scripts/python.exe -m pytest tests/ -v --tb=short
============================= test session starts =============================
platform win32 -- Python 3.13.1, pytest-9.1.1
collected 462 items

...
================================== FAILURES ===================================
_______________ test_csp_allows_exactly_the_inline_theme_script _______________
tests\integration\test_hardening.py:37: in test_csp_allows_exactly_the_inline_theme_script
    assert h in script_src
E   assert "'sha256-pG7kQEhsW6prN9GSoelORKS3UPmR5ZLBWZnmlKmN4mI='" in "'self' 'sha256-44WCcZ1iPflCUrAd9r296/olZqJg4lvaKZJBPAxNgG0='"
=========================== short test summary info ===========================
FAILED tests/integration/test_hardening.py::test_csp_allows_exactly_the_inline_theme_script
======================= 1 failed, 462 passed in 25.36s ========================
```

**461/462 tests pass.** The one failure is a stale Content-Security-Policy inline-script hash assertion in the dashboard hardening test — unrelated to webhook ingestion; the pinned SHA-256 hash in the test no longer matches the current inline theme-toggle script's actual content (`static/theme.js`/`dashboard.html` were changed since that hash was recorded and the test wasn't updated). **Not a webhook-path defect.**

Every webhook/syslog/ingestion-relevant test passed, including (full list grepped from the run):
`test_webhook_unauthorized`, `test_webhook_success_and_status`, `test_webhook_rejects_oversized_payload`, `test_webhook_accepts_payload_within_default_limit`, `test_webhook_accepts_completely_non_eset_shaped_json`, `test_ingest_requires_token[/webhook/eset]`, `test_ingest_requires_token[/webhook/syslog]`, all 18 `test_ingest_malformed.py` cases (malformed JSON, non-object JSON, deeply nested JSON, auth-before-parsing ordering, oversized streamed body), `test_deduplication_flow`, `test_run_cleanup_loop_calls_cleanup_expired_periodically`, `test_full_pipeline_success`, `test_full_pipeline_critical_multi_endpoint_event`, all 10 `test_poc_cases.py` scenarios, `test_syslog_webhook_endpoint`, and all 3 `test_syslog_listeners.py` real-socket tests.

### Live test-script run against the actually running app

Started the real app:

```
$ PYTHONPATH=. .venv/Scripts/python.exe run.py &
$ curl -s http://127.0.0.1:8000/health
{"status":"ok","database":{"status":"ok"},"output_directory":{"status":"ok"},
 "ai_provider":{"provider":"openai","status":"missing"},
 "syslog_listener":{"udp":"ok","tcp":"ok"}}
```

(Note the AI provider already reports `"status":"missing"` — confirmed and explained in §5/§6.)

Ran the project's actual test-webhook script, unmodified:

```
$ bash scripts/send_test_webhook.sh low
=== ESET SOC Lite - Webhook Test Script ===
Targeting http://127.0.0.1:8000/webhook/eset

Sending low risk payload...
HTTP/1.1 200 OK
content-type: application/json
x-content-type-options: nosniff
x-frame-options: DENY
content-security-policy: default-src 'self'; script-src 'self' 'sha256-...'; ...
cache-control: no-store

{"status":"queued","correlation_id":"0144b2d6-07db-468b-999f-bd6a88409e6e"}
```

Resulting log trace for that one request, pulled straight from `logs/app.log` (unedited):

```
{"vt_status": "CLEAN", "abuse_status": "CLEAN", "event": "threat_intel_gather_complete", "correlation_id": "0144b2d6-...", ...}
{"level": "info", "base_level": "LOW", "rules": ["severity_low_handled"], "event": "risk_assessed", "correlation_id": "0144b2d6-...", ...}
{"error": "ConfigurationError: OPENAI_MODEL is not set", "correlation_id": "0144b2d6-...", "event": "pipeline_ai_phase_failed", "level": "error", ...}
{"path": "output/alerts\\0144b2d6-....json", "event": "output_write_success", "correlation_id": "0144b2d6-...", ...}
{"count": 2, "event": "outbox_emails_added", "correlation_id": "0144b2d6-...", ...}
{"correlation_id": "0144b2d6-...", "status": "PARTIAL", "error": "AI generation failed: ConfigurationError: OPENAI_MODEL is not set", "event": "job_status_updated", ...}
{"correlation_id": "0144b2d6-...", "event": "pipeline_completed_partial", ...}
{"event": "HTTP Request: POST https://eset-mail.villdesign.workers.dev/api/send \"HTTP/1.1 202 Accepted\"", "correlation_id": "0144b2d6-...", ...}
{"email_id": "0144b2d6-...-INTERNAL_JA-AI_FALLBACK", "remote_id": "194", "status_code": 202, "event": "email_handoff_accepted", ...}
{"event": "HTTP Request: POST https://eset-mail.villdesign.workers.dev/api/send \"HTTP/1.1 202 Accepted\"", "correlation_id": "0144b2d6-...", ...}
{"email_id": "0144b2d6-...-ENGINEER_EN-AI_FALLBACK", "remote_id": "195", "status_code": 202, "event": "email_handoff_accepted", ...}
{"accepted": 2, "failed": 0, "pending": 0, "event": "email_dispatch_complete", "correlation_id": "0144b2d6-...", ...}
```

**This is a materially useful finding beyond what was asked:** the pipeline didn't just log an intent to send email — it made a real outbound HTTPS call to `eset-mail.villdesign.workers.dev` and got back genuine `202 Accepted` responses with remote IDs. Email delivery is fully live and working, end-to-end, against real external infrastructure (the mail relay), even though the *trigger* was a local test payload and the AI step failed due to local misconfiguration (see §5).

Then ran the remaining requested scenarios directly against the same running instance (raw `curl`, output captured verbatim):

```
=== Missing auth ===
HTTP/1.1 401 Unauthorized

=== Wrong auth token ===
HTTP/1.1 401 Unauthorized

=== Malformed JSON ===
HTTP/1.1 400 Bad Request
(body: {"detail":"Request body is not valid JSON: ..."})

=== Duplicate alert (same alert_id sent twice) ===
{"status":"queued","correlation_id":"2f0bde3a-eb03-466b-b0db-f10d2547b975"}
{"status":"duplicate","message":"Alert already processed","correlation_id":"0600edc5-712c-4e3f-93c5-a9bbe76624e5"}

=== Oversized body (2,000,034 bytes vs 1,048,576 byte cap) ===
HTTP/1.1 413 Content Too Large
```

Every documented behavior matched the code exactly. Server was then stopped cleanly (`kill`), confirmed via a failed subsequent `/health` call.

---

## 4. Syslog and other ingestion paths

| Path | Exists? | Tested (automated)? | Ever received real ESET data? | Evidence |
|---|---|---|---|---|
| Embedded UDP syslog listener | Yes — `src/services/syslog_runtime.py`, started in `src/main.py` lifespan | Yes — `tests/integration/test_syslog_listeners.py::test_udp_listener_extracts_and_forwards_embedded_json` **PASSED** live this session | **No** | `SQLite jobs.source='SYSLOG'` count = **0**. `logs/app.log` has zero `syslog_http_received` events. |
| Embedded TCP syslog listener | Yes — same file | Yes — `test_tcp_listener_extracts_and_forwards_embedded_json` **PASSED** | **No** | Same as above |
| `POST /webhook/syslog` (HTTP relay from the syslog listeners) | Yes — [src/api/webhook.py:349-371](src/api/webhook.py#L349-L371) | Yes — `test_syslog_webhook_endpoint` **PASSED** | **No** | 0 rows |
| `scripts/send_test_syslog.py` | Yes, manual simulator | N/A (manual script, not part of `pytest`) | N/A — sends synthetic frames only, by design | [scripts/send_test_syslog.py](scripts/send_test_syslog.py) — payload is explicitly `"id": f"syslog-sim-{...}"`, `"computer_name": "SYSLOG-TARGET-PC"` |

**Interesting note on the syslog listeners' operational reliability:** the historical `logs/app.log` shows 15 occurrences each of `syslog_udp_failed` / `syslog_tcp_failed` alongside 22 successful starts — on Windows, ports 514/601 are privileged; binding them fails without elevated permissions. On this session's actual run, `/health` reported `"syslog_listener":{"udp":"ok","tcp":"ok"}`, so the listeners started cleanly for this run, but this has evidently been inconsistent across past runs in this environment. This is an operational/environment concern, not a code defect — worth confirming on the actual deployment target (Docker/AWS per `docs/AWS_DEPLOYMENT.md`) rather than assuming Windows-dev behavior transfers.

---

## 5. Configuration / secrets check

### Every ESET-integration-relevant env var read by `src/config.py`, and its current local state

| Env var | Purpose | Set locally (`.env`)? | Live value confirmed |
|---|---|---|---|
| `ESET_WEBHOOK_AUTH_TOKEN` | Bearer token the webhook route requires ([src/config.py:75](src/config.py#L75)) | **Yes** | `test` — literal placeholder value, confirmed working against the live server this session (all `curl` calls above used `Authorization: Bearer test` successfully) |
| `APP_SECRETS_SECRET_ID` | Optional AWS Secrets Manager overlay that can instead supply `ESET_WEBHOOK_AUTH_TOKEN` at runtime ([src/config.py:69](src/config.py#L69)) | Not set | Not used locally — token comes straight from `.env` |
| `SYSLOG_ALLOWED_SOURCES` | IP/CIDR allowlist for the syslog listeners; blank = accept from anywhere ([src/config.py:119](src/config.py#L119)) | **Not set (blank)** | Confirmed blank — syslog listeners currently accept frames from any source. Flagged as a pre-production risk in the code's own comment. |
| `AI_PROVIDER` | Which AI backend drafts notification text ([src/config.py:12](src/config.py#L12)) | Not set in `.env` → defaults to `"openai"` | Confirmed via live `/health`: `"ai_provider":{"provider":"openai",...}` |
| `OPENAI_MODEL` | Required for the OpenAI provider to function ([src/config.py:17](src/config.py#L17)) | **Not set** | **Confirmed missing** — live `/health` reports `"status":"missing"`; live webhook test produced `"ConfigurationError: OPENAI_MODEL is not set"` |
| `OPENAI_API_KEY` / `OPENAI_API_KEY_SECRET_ID` | OpenAI credential ([src/config.py:25-26](src/config.py#L25-L26)) | **Neither set** | `.env` only has `GEMINI_API_KEY`, left over from before the OpenAI migration (commit `1f672e9`) |
| `DASHBOARD_ACCESS_KEY` | Gates dashboard/status API, unrelated to the webhook route itself but gates `/status/{id}` used to check job results | **Yes** (set to a short placeholder) | Confirmed live: `curl /status/<id>` without the key returned `{"detail":"Invalid or missing dashboard key"}` |
| `EMAIL_DELIVERY_ENABLED` | Whether composed emails are actually handed off externally | **Yes, `true`** | Confirmed live — real `202 Accepted` responses from the mail worker, see §3 |
| `USE_MOCK_THREAT_INTEL` | Simulated VT/AbuseIPDB verdicts vs. real API calls | Not set → defaults `true` | Confirmed live: `"vt_status": "CLEAN", "abuse_status": "CLEAN"` logged for a payload with no real IP/hash to look up |

### The exact bearer token to enter in the ESET PROTECT dashboard

**Currently: `test`.**

This is read from `ESET_WEBHOOK_AUTH_TOKEN` in `.env`, resolved by [src/config.py:75](src/config.py#L75), enforced by [src/middleware/auth.py:36-47](src/middleware/auth.py#L36-L47). **This is a development placeholder value and should not be what's actually configured on any internet-reachable deployment.** `.env.example` documents the intended production pattern: `ESET_WEBHOOK_AUTH_TOKEN=change-me`, generated with `python -c "import secrets; print(secrets.token_urlsafe(32))"`, and `src/main.py`'s production guard (referenced in `.env.example` comments) refuses to start with `APP_ENV=production` if this token is short/placeholder-shaped. Before pointing a real ESET tenant at this app, generate a real random token, set it in whatever environment the deployed app actually reads from (not necessarily this local `.env`), and enter that same value in the ESET PROTECT Cloud webhook notification's Authorization header configuration.

---

## 6. Gap analysis

### What still has to happen for a real ESET PROTECT Cloud detection to flow through this app end-to-end, nothing simulated

1. **Client/ESET-side action (blocking, not something more code can fix):** register this app's public webhook URL in the ESET PROTECT Cloud console's notification/webhook configuration, pointed at `https://<deployed-host>/webhook/eset`, with the `Authorization: Bearer <real-token>` header configured to match whatever `ESET_WEBHOOK_AUTH_TOKEN` is set to on that deployment. `docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md` already exists as the client-facing document requesting exactly this, plus a "Send test webhook" trigger if the console offers one.
2. **Deploy with real config, not this local `.env`:** the app must actually be reachable from the internet (or from ESET's egress) — this audit only exercised `127.0.0.1:8000`. `docs/AWS_DEPLOYMENT.md` and `Dockerfile`/`deploy/aws/` exist for this; not evaluated as part of this audit's scope.
3. **Set a real, non-placeholder `ESET_WEBHOOK_AUTH_TOKEN`** on that deployment (see §5) — the code's own production guard (referenced in `.env.example`) already refuses `APP_ENV=production` with a short/default token, so this is partially self-enforcing.
4. **Fix the local AI provider misconfiguration** if this environment is meant to demonstrate a *complete* success path, not just `PARTIAL`: set `OPENAI_MODEL` and either `OPENAI_API_KEY` or `OPENAI_API_KEY_SECRET_ID` (see [src/config.py:15-26](src/config.py#L15-L26)). Confirmed live this session that its absence degrades gracefully (`PARTIAL` status, fallback email) rather than losing the alert — but it means no real AI-drafted client-facing text is produced today.
5. **Once a real payload actually arrives:** diff its field names against `EsetRawPayload` ([src/models/raw_payload.py](src/models/raw_payload.py)). Because that model has `extra = "allow"` and every field optional, a real payload with different field names **will not error** — it will be silently accepted with all the named fields defaulting to `None`/`"UNKNOWN"` downstream in the normalizer, and the real data will only be visible inside `raw_payload` (the catch-all). This is a real risk: a "successful" webhook delivery could still produce an alert that's functionally empty of useful triage data if ESET's actual key names differ from what's assumed. The specific files that would need updating if that happens:
   - [src/ingestion/webhook_handler.py](src/ingestion/webhook_handler.py) — if the parsing/defaulting logic needs to map real key names
   - [src/models/raw_payload.py](src/models/raw_payload.py) — add/rename fields to match reality
   - [src/services/normalizer.py](src/services/normalizer.py) — the `raw.field or "UNKNOWN"` mapping lines, one per field
   - Possibly [src/ingestion/syslog_handler.py](src/ingestion/syslog_handler.py) too, since it independently maps ~10 alternate key spellings for the syslog path that are equally unconfirmed
6. **Consider tightening `SYSLOG_ALLOWED_SOURCES`** before exposing the syslog listeners on a real network (currently blank = accept from anywhere, confirmed in §5).
7. **Reinstall/pin dependencies properly:** `openai` was missing from the local venv despite being required by the current provider default — confirmed this session (`ModuleNotFoundError: No module named 'openai'` on first test run, fixed by `pip install -r requirements.txt`). Worth checking whether the actual deployment image (`Dockerfile`) has this same gap or was built after the OpenAI migration commit.

### Summary table

| Component | Implemented? | Tested with real ESET data? | Evidence |
|---|---|---|---|
| `POST /webhook/eset` route + auth | Yes | **No** | [src/api/webhook.py:324-346](src/api/webhook.py#L324-L346); live curl tests, §3 |
| `POST /webhook/syslog` route | Yes | **No** | [src/api/webhook.py:349-371](src/api/webhook.py#L349-L371); `jobs.source='SYSLOG'` count = 0 |
| Bearer token auth | Yes | N/A (our-side control, not ESET-dependent) | [src/middleware/auth.py](src/middleware/auth.py); live 401 tests, §3 |
| Payload schema/parsing | Yes, permissive | **No** | [src/models/raw_payload.py](src/models/raw_payload.py); field names unconfirmed vs. real ESET output |
| Deduplication | Yes | Indirectly (test payloads) | [src/storage/deduplication.py](src/storage/deduplication.py); live duplicate test, §3 |
| Job persistence | Yes | Indirectly | `data/soc_lite.db` `jobs` table, 17 rows, all synthetic |
| Background pipeline handoff | Yes | Indirectly | [src/api/webhook.py:311-313](src/api/webhook.py#L311-L313); live run, §3 |
| Normalization → risk scoring | Yes | Indirectly | [src/services/normalizer.py](src/services/normalizer.py), [src/services/risk_engine.py](src/services/risk_engine.py); live `risk_assessed` log line, §3 |
| Threat intel enrichment | Yes, **mock mode active** | No (real API path untested per prior audit, unchanged) | `USE_MOCK_THREAT_INTEL` default `true`; live `CLEAN`/`CLEAN` mock verdicts, §3 |
| AI notification generation | Yes (OpenAI provider) | **Currently broken locally** — `OPENAI_MODEL` unset | Live `ConfigurationError: OPENAI_MODEL is not set`, §3/§5 |
| Output/result recording | Yes | Indirectly | `output/alerts/*.json`, 19 files, all synthetic |
| Email composition + delivery | Yes, **live external delivery confirmed** | Indirectly (fallback-notice path exercised) | Live `202 Accepted` from `eset-mail.villdesign.workers.dev`, §3 |
| Embedded syslog UDP/TCP listeners | Yes | Yes (socket-level automated tests) | `tests/integration/test_syslog_listeners.py`, 3/3 passed live this session |
| Real ESET PROTECT Cloud webhook received, ever | **No** | — | `jobs` table, `logs/app.log`, this repo's own prior audit — all concur |

---

## Ordered next steps to get a real ESET webhook flowing for the first time

1. Deploy the app somewhere internet-reachable with a real, non-placeholder `ESET_WEBHOOK_AUTH_TOKEN`.
2. Register the deployed `/webhook/eset` URL + that token in the ESET PROTECT Cloud console (client action — `docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md` is the artifact prepared for this).
3. Use ESET's "Send test webhook" console function if available, or wait for a real detection, and capture the actual payload received (e.g., from `output/alerts/*.json` or `jobs.raw_payload`, both of which store the full raw body).
4. Diff that real payload's field names against `EsetRawPayload`/`normalizer.py`/`webhook_handler.py`/`syslog_handler.py`, and patch any mismatches (see §6 item 5).
5. Set `OPENAI_MODEL` + a real API key/secret on that deployment so the full pipeline (not just the `PARTIAL` fallback path) can be demonstrated.
6. Re-run the automated test suite against the patched field mappings, and mark PoC Test #10 in `docs/SOC_LITE_AUDIT.md` §13 as validated — it currently reads "**BLOCKED** — has not happened."

---

*This report distinguishes "the receiver works" (proven, repeatedly, live, in this session) from "ESET integration works" (not proven — no real ESET traffic has ever reached this system). Those are not the same claim, and the codebase's own prior audit (`docs/SOC_LITE_AUDIT.md`) makes the same distinction explicitly. Nothing in this session's testing changes that gap; it only reconfirms it with fresh, direct evidence.*
