# ESET → Notification Email: Evidence-Based Flow Audit

**Repository:** `D:\ESET\ESET-SoC`, branch `main`, commit `1f672e9`
**Audit date:** 2026-10-02
**Method:** I read every module on the alert path end to end and quote line numbers from the file as it is at `1f672e9`. I ran the full test suite (`463 tests: 462 passed, 1 failed`; the failure is `test_hardening.py::test_csp_allows_exactly_the_inline_theme_script`, a dashboard CSP hash check that is unrelated to the alert flow). I inspected the local evidence on disk (`data/soc_lite.db`, `logs/app.log`, `output/alerts/*.json`). I also wrote three throw-away probe tests that ran inside the repo's own test harness, to confirm three behaviours by execution rather than by reading (§14.0). The probe file was deleted afterwards and the working tree is unchanged.

### Status legend (used throughout)

| Label | Meaning |
|---|---|
| **PROVEN BY CODE** | The executable path exists and I traced it call by call. |
| **PROVEN BY EXECUTION** | I ran it in this session and observed the result. |
| **PROVEN ONLY BY TEST/MOCK** | Exercised only with a fake or mock in place of the external party. |
| **CONFIGURED BUT NOT VERIFIED** | A setting exists; nothing shows it is set that way in a real deployment. |
| **CONFIG-DEPENDENT** | Behaviour flips on a setting whose default differs from what the claim implies. |
| **DOCUMENTED BUT NOT IMPLEMENTED** | Described in prose; no executable code does it. |
| **PARTIALLY IMPLEMENTED** | Code does part of what the claim says. |
| **NOT FOUND** | No code exists for it. |
| **ASSUMED / INFERRED** | Rests on an assumption about an external system. |
| **REQUIRES LIVE EXTERNAL VALIDATION** | Can only be proven against the real third party. |
| **NOT PROVEN FROM REPOSITORY** | Nothing in the repository proves it either way. |

---

## Headline findings (read these first)

1. **No real ESET PROTECT payload has ever been processed.** All 19 jobs in `data/soc_lite.db` are hand-crafted, with alert IDs `test-001`, `live-repro-*`, `ai-content-repro-*`, `test-alert-*` and `dup-test-001`. The ESET field names are engineering guesses, and `docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md` says so itself. **Real ESET production payload processing is NOT PROVEN.**
2. **Threat intelligence is simulated by default and does not affect risk while simulated.** `USE_MOCK_THREAT_INTEL` defaults to `True` ([src/config.py:166](src/config.py#L166)). The local `.env` does not override it, and neither does the AWS template ([deploy/aws/cloudformation.yaml:217-233](deploy/aws/cloudformation.yaml#L217-L233)). In mock mode the verdicts are dropped from the risk engine ([src/pipeline/orchestrator.py:136](src/pipeline/orchestrator.py#L136)) and from the AI prompt ([src/services/ai/base.py:242-247](src/services/ai/base.py#L242-L247)). The log contains **0** real VirusTotal calls and **0** real AbuseIPDB calls.
3. **Domains are never checked by any threat-intelligence integration.** VirusTotal checks *one* indicator per alert (hash, else URL, else IP); AbuseIPDB checks IPs only.
4. **Email delivery is OFF by default** (`EMAIL_DELIVERY_ENABLED=False`, [src/config.py:197](src/config.py#L197)). **The AWS deployment template does not turn it on**, so that deployment would queue emails and never send them.
5. **The client email and the C-Three "review" email are composed in the same loop, queued in the same write and handed off in the same sweep.** No approval gate exists anywhere in `src/`. I confirmed this by execution.
6. **"Delivered" is not proven.** The code proves only that the mail service answered HTTP 200/202 with `success: true` (the handoff). Inbox delivery is outside the repository.
7. **There are alert-loss paths the client draft denies.** Three were confirmed by execution:
   - If the job row fails to save after the dedup key is recorded, the sender's retry within the hour is answered `"duplicate"` and the alert is never processed.
   - If normalization, threat intel or risk scoring throws, the job ends `FAILED` and **nobody is emailed**.
   - Client and C-Three emails are queued together, with no hold between them (finding 5).

   More loss paths are listed in §14.
8. **No successful OpenAI generation exists anywhere in the repository's artifacts.** The 2 OpenAI-era results on disk both failed with `model=unset`. The 16 `SUCCESS` results predate the OpenAI integration: they carry no `ai_run` metadata, so their provider is not recorded. The local `.env` has `OPENAI_MODEL` unset (verified), so every local alert currently ends `PARTIAL`.
9. **The email retry and dead-letter logic has no tests.** No test calls `email_dispatcher._hand_off`, `dispatch_pending`, `run_dispatch_loop` or `record_dead_letter`.
10. **Timing is NOT MEASURED / NOT PROVEN.** There is no benchmark, latency test or monitoring. The only timestamps are from 19 local synthetic runs (§17).

---

## Addendum (2026-10-02): evidence from the deployed dashboard

Source: the dashboard screen of the deployed instance, pasted by the user. This is not stored in this repository, so I could not check it here.

| Observation | What it proves | Effect on findings above |
|---|---|---|
| ~21 `webhook` jobs over the past ~15 h, all `SUCCESS`, all `MEDIUM`, all fields `UNKNOWN`. The user reports these are ESET PROTECT test webhooks | ESET → `/webhook/eset` connection and token check work on that deployment. **PROVEN BY DEPLOYMENT EVIDENCE** | Headline 1 / Part 16 rows 1, 3, 5: now **yes** for test webhooks |
| Job `e938f26a…`: AI summary describes an ESET **audit-log event** with subject "TEST" and fields domain / action / result / user / details | ESET's real webhook format differs from the `EsetRawPayload` / alias mapping: **nothing** was extracted | Part 6: the field mapping is **confirmed wrong** for ESET's test-webhook format. Part 16 row 4: **no** |
| Risk = MEDIUM via `severity_unknown` on every ESET webhook | The risk rules never received real input | Part 8: until the mapping is fixed, every real ESET alert gets the MEDIUM fallback |
| `SUCCESS` status with a coherent, non-inventing AI summary | Live AI generation, schema, validation and composition work on that deployment | Headline 8 / Part 9: live AI now **PROVEN BY DEPLOYMENT EVIDENCE** (provider and model not visible in the paste) |
| VirusTotal / AbuseIPDB "not clear", 0/0 | No indicators were extracted, so nothing was looked up | Part 7 unchanged |

Still not proven: a real **detection** event from ESET (as opposed to an audit-log test event), and whether emails were handed off for these jobs. If client recipients are configured on that deployment, the client may have been sent a MEDIUM notification for each test webhook.

---

## PART 1 — Repository map and real runtime call chain

### 1.1 Components on the alert path

| Role | File |
|---|---|
| Process entry | [run.py](run.py) → `uvicorn.run("src.main:app")`, a **single process**; no `workers=` |
| App + startup | [src/main.py](src/main.py) `lifespan()` 163-223 |
| Routes | [src/api/router.py](src/api/router.py) 10-14; webhook routes in [src/api/webhook.py](src/api/webhook.py) |
| Webhook auth | [src/middleware/auth.py](src/middleware/auth.py) `validate_eset_token` 14-49 |
| Syslog listeners | [src/services/syslog_runtime.py](src/services/syslog_runtime.py), started at [src/main.py:197](src/main.py#L197) |
| Parsing | [src/ingestion/webhook_handler.py](src/ingestion/webhook_handler.py), [src/ingestion/syslog_handler.py](src/ingestion/syslog_handler.py), [src/models/raw_payload.py](src/models/raw_payload.py) |
| Dedup | [src/storage/deduplication.py](src/storage/deduplication.py) |
| Admission/capacity | [src/services/pipeline_capacity.py](src/services/pipeline_capacity.py) |
| Job persistence | [src/storage/job_store.py](src/storage/job_store.py), schema in [src/storage/database.py](src/storage/database.py) |
| Orchestrator | [src/pipeline/orchestrator.py](src/pipeline/orchestrator.py) `process_alert_pipeline` 79-243 |
| Normalization | [src/services/normalizer.py](src/services/normalizer.py) |
| Threat intel | [src/services/threat_intel/aggregator.py](src/services/threat_intel/aggregator.py), [virustotal.py](src/services/threat_intel/virustotal.py), [abuseipdb.py](src/services/threat_intel/abuseipdb.py) |
| Risk | [src/services/risk_engine.py](src/services/risk_engine.py), [src/storage/observation_store.py](src/storage/observation_store.py) |
| AI | [src/services/ai/factory.py](src/services/ai/factory.py), [base.py](src/services/ai/base.py), [openai_provider.py](src/services/ai/openai_provider.py), [gemini_service.py](src/services/ai/gemini_service.py) |
| Masking | [src/services/ai/prompt_masking.py](src/services/ai/prompt_masking.py) |
| Prompt | [src/prompts/system_prompts.py](src/prompts/system_prompts.py) (a static string with no interpolation) |
| Output schema | [src/models/ai_output.py](src/models/ai_output.py), [src/services/ai/schema_builder.py](src/services/ai/schema_builder.py) |
| Validation | [src/services/ai/output_validator.py](src/services/ai/output_validator.py), [lint_checker.py](src/services/ai/lint_checker.py) |
| Result file | [src/services/output_writer.py](src/services/output_writer.py) |
| Email composition | [src/services/email_composer.py](src/services/email_composer.py) |
| Outbox / dead letter | [src/services/email_outbox.py](src/services/email_outbox.py) (JSON files) |
| Handoff + retry | [src/services/email_dispatcher.py](src/services/email_dispatcher.py) |
| Mail provider | [src/services/email_delivery/eset_mail.py](src/services/email_delivery/eset_mail.py) (Cloudflare Worker `POST /api/send`) |
| Handoff history | [src/storage/delivery_store.py](src/storage/delivery_store.py) |
| Crash recovery | [src/main.py:116-160](src/main.py#L116-L160) `recover_unfinished_jobs` |

### 1.2 The executable call chain (webhook path)

```
HTTP POST /webhook/eset
 └─ src/api/webhook.py:324  receive_eset_webhook()            [FastAPI resolves dependency first]
     ├─ src/middleware/auth.py:14  validate_eset_token()        → 429 / 401 or continue
     ├─ webhook.py:333  _reject_oversized_body()  (77-108)      → 413 or continue
     ├─ webhook.py:334  read_json_body()          (172-243)     → 413 / 400 or dict
     └─ webhook.py:341  ingest_alert()            (246-321)
         ├─ :258  generate_correlation_id()  → src/utils/correlation.py:8  uuid4
         ├─ :262  WebhookIngestionHandler.parse() → webhook_handler.py:13 → EsetRawPayload(**data)
         ├─ :272  compute_dedup_key()        (111-121)
         ├─ :274  deduplication.is_duplicate() → deduplication.py:8   → return "duplicate"
         ├─ :289  pipeline_capacity.capacity.reserve() → pipeline_capacity.py:87 → 503 or Reservation
         ├─ :308  deduplication.record_seen() → deduplication.py:23  (INSERT OR REPLACE dedup_log)
         ├─ :310  job_store.create_job()      → job_store.py:10      (INSERT jobs … 'PENDING')
         ├─ :311  background_tasks.add_task(reservation.run, run_pipeline_task, …)
         └─ :318  return {"status":"queued","correlation_id":…}   ← HTTP response sent here
                  ── Starlette then runs the background task ──
 run_pipeline_task()  webhook.py:124
  └─ :139  orchestrator.process_alert_pipeline()   orchestrator.py:79
      ├─ :96   job_store.update_job_status("PROCESSING")
      ├─ :108  EsetRawPayload(**raw_payload)
      ├─ :109  normalizer.normalize()                 → normalizer.py:92
      ├─ :117  gather_threat_intel(alert)             → aggregator.py:11 → VirusTotalProvider.query / AbuseIPDBProvider.query
      ├─ :126  observation_store.record_and_count()   → observation_store.py:12
      ├─ :135  risk_engine.assess_risk(alert, None if mock else intel, observed)  → risk_engine.py:194
      │   (any exception in 106-143 → :145-160 FAILED result written, job FAILED, RETURN — no email)
      ├─ :168  ai_factory.get_ai_provider()           → factory.py:53
      ├─ :169  provider.generate()                    → base.py:293
      │         ├─ base.py:320  _build_prompt() → prompt_masking.mask_alert_for_prompt / mask_raw_payload_for_prompt
      │         ├─ base.py:347  build_strict_json_schema(AIOutput, pin={"risk_level":[level]})
      │         ├─ base.py:393  AsyncRetrying(...)(attempt) → openai_provider._invoke() :156 → client.chat.completions.create
      │         └─ base.py:410  AIOutput.model_validate_json()
      ├─ :195  validate_ai_output(ai_output, risk_level) → output_validator.py:32 → lint_checker.find_prohibited_phrases
      ├─ :233  _compose_notifications()  → email_composer.compose_emails() :205  or compose_fallback_emails() :215
      ├─ :234  output_writer.write_result()           → output_writer.py:26
      ├─ :235  _queue_notifications()                 → email_outbox.add_emails() :52 → delivery_store.record_pending()
      │         └─ :74  asyncio.create_task(email_dispatcher.dispatch_soon())
      └─ :238/242  job_store.update_job_status("SUCCESS" | "PARTIAL")
 email_dispatcher.dispatch_soon() :188 → dispatch_pending() :58
  ├─ :63  if not EMAIL_DELIVERY_ENABLED → return (email stays in outbox)
  └─ :90  _hand_off() :122 → EsetMailProvider.send() eset_mail.py:294 → httpx POST EMAIL_API_URL
          → _interpret() :404 → ACCEPTED (outbox removed) | retry | FAILED (dead letter)
 email_dispatcher.run_dispatch_loop() :198 (started main.py:204) — re-sweeps the outbox every max(10, EMAIL_DISPATCH_INTERVAL_SECONDS)
```

**Verdict for Part 1:** the complete chain from the webhook to the mail-provider handoff and its retry/failure handling **exists in executable code** (PROVEN BY CODE). Every link to an external party is unproven against the real party: ESET, VirusTotal, AbuseIPDB, OpenAI, and inbox delivery.

---

## PART 2 — ESET alert ingestion

| # | Question | Answer | Evidence | Status |
|---|---|---|---|---|
| 1 | Endpoint | `POST /webhook/eset` | router prefix `/webhook` [webhook.py:21](src/api/webhook.py#L21); route [webhook.py:324](src/api/webhook.py#L324); mounted via [router.py:10](src/api/router.py#L10), [main.py:247](src/main.py#L247) | PROVEN BY CODE |
| 2 | Method | POST only | `@router.post` at :324 | PROVEN BY CODE |
| 3 | Auth required | Static shared token in the `Authorization` header (`Bearer <t>` or bare `<t>`) | [auth.py:12](src/middleware/auth.py#L12), [31-34](src/middleware/auth.py#L31-L34) | PROVEN BY CODE |
| 4 | Where checked | `validate_eset_token`, attached as a route dependency | [webhook.py:324](src/api/webhook.py#L324) `dependencies=[Depends(validate_eset_token)]` | PROVEN BY CODE |
| 5 | On failure | 401 with an empty body; 429 after `AUTH_MAX_FAILURES` (default 20) wrong tokens per IP per 600 s | [auth.py:22-29, 36-47](src/middleware/auth.py#L22-L47) | PROVEN BY CODE + tests `test_security.py::test_ingest_requires_token`, `test_near_miss_tokens_rejected`, `test_hardening.py::test_wrong_webhook_tokens_are_throttled` |
| 6 | Raw body | Streamed with a byte cap (default 1 MiB), JSON-parsed, unencodable code points scrubbed, must be a JSON object | [webhook.py:172-243](src/api/webhook.py#L172-L243) | PROVEN BY CODE + `test_ingest_malformed.py` |
| 7 | Payload persisted? | Yes, **if the request passes auth, size, JSON, dedup and capacity**. `jobs.raw_payload` holds `EsetRawPayload.model_dump()`, which contains `raw_payload` = the full original JSON | [webhook_handler.py:23-24](src/ingestion/webhook_handler.py#L23-L24), [webhook.py:309-310](src/api/webhook.py#L309-L310), [job_store.py:10-24](src/storage/job_store.py#L10-L24). Rejected requests get only a ≤4000-char log preview ([webhook.py:26-56](src/api/webhook.py#L26-L56)) | PROVEN BY CODE |
| 8 | Tracking ID | `correlation_id = uuid4()` | [webhook.py:258](src/api/webhook.py#L258) → [correlation.py:8](src/utils/correlation.py#L8) | PROVEN BY CODE |
| 9 | Before/after processing | Generated **before** parsing; the job row is written **before** the background pipeline is scheduled | webhook.py:258 → 310 → 311 | PROVEN BY CODE |
| 10 | ESET fields read | 23 named fields on `EsetRawPayload` ([raw_payload.py:10-33](src/models/raw_payload.py#L10-L33)) plus alias keys in [normalizer.py:27-50](src/services/normalizer.py#L27-L50); the risk engine also reads payload keys `affected_endpoints`, `endpoint_count`, etc. ([risk_engine.py:63-66](src/services/risk_engine.py#L63-L66)) | — | PROVEN BY CODE |
| 11 | Match real ESET payload? | **Unknown.** No real payload exists in the repository | DB: 19/19 jobs synthetic (alert IDs listed in Headline 1) | **NOT PROVEN FROM REPOSITORY** |
| 12 | Documented? | Only as a *request for confirmation* to the client | [docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md](docs/ESET_WEBHOOK_SAMPLE_TEMPLATE.md): "our engineering team has never received a real webhook from this tenant" | DOCUMENTED AS UNVERIFIED |
| 13 | Basis | Assumptions and hand-written fixtures (`tests/fixtures/*.json`, `scripts/send_test_webhook.sh`) | `docs/SOC_LITE_AUDIT.md:81` "every 'ESET' fact … is an engineered guess" | ASSUMED / INFERRED |
| 14 | Syslog path | Yes. UDP 514 / TCP 601 by default (5514/5601 in Docker), embedded in the same process; each frame's embedded JSON is forwarded over loopback HTTP to `POST /webhook/syslog` with the real token attached | [syslog_runtime.py:128-169](src/services/syslog_runtime.py#L128-L169); route [webhook.py:349-371](src/api/webhook.py#L349-L371) | PROVEN BY CODE + `test_syslog_listeners.py` (loopback HTTP mocked) |
| 15 | Same pipeline? | Yes. Both routes call `ingest_alert()` and the same orchestrator; only the parser differs (`SyslogIngestionHandler` re-maps ~10 alternate key spellings, [syslog_handler.py:31-56](src/ingestion/syslog_handler.py#L31-L56)) | [webhook.py:341-346, 366-371](src/api/webhook.py#L341-L371) | PROVEN BY CODE |

**Payload acceptance is unconditional on shape:** `EsetRawPayload` has every field optional and `extra="allow"` ([raw_payload.py:36-38](src/models/raw_payload.py#L36-L38)). `{"totally":"unrelated"}` is accepted (`test_webhook_endpoint.py::test_webhook_accepts_completely_non_eset_shaped_json`).

**Real-ESET evidence check:** `logs/app.log` has 20 `webhook_received` and 0 `syslog_forwarding_success` events. Every stored payload's `alert_id` is a hand-made test value. **Real ESET production payload processing is NOT PROVEN.**

---

## PART 3 — Authentication / ingestion security

Claim: *"The sender must present a secret access token. Anything without it is rejected."*

| Aspect | Evidence | Status |
|---|---|---|
| Header checked | `Authorization`, via `APIKeyHeader(name="Authorization")` [auth.py:12](src/middleware/auth.py#L12) | PROVEN BY CODE |
| Comparison | `hmac.compare_digest` (constant-time) [auth.py:44](src/middleware/auth.py#L44) | PROVEN BY CODE |
| Missing header | 401 [auth.py:27-29](src/middleware/auth.py#L27-L29) | PROVEN BY CODE + test |
| Token unset on server | Every request refused with 401 [auth.py:36-41](src/middleware/auth.py#L36-L41) | PROVEN BY CODE + `test_hardening.py::test_unconfigured_webhook_token_refuses_everything` |
| Applied to `/webhook/eset` and `/webhook/syslog` | `dependencies=[Depends(validate_eset_token)]` at [webhook.py:324](src/api/webhook.py#L324) and [:349](src/api/webhook.py#L349) | PROVEN BY CODE |
| Token source | `ESET_WEBHOOK_AUTH_TOKEN` env/.env ([config.py:75](src/config.py#L75)) or the AWS Secrets Manager overlay ([secrets.py:182-190, 216-221](src/services/secrets.py#L182-L221)). `APP_ENV=production` refuses to start if it is <16 chars or a placeholder ([main.py:81-83](src/main.py#L81-L83)) | PROVEN BY CODE; the production value is CONFIGURED BUT NOT VERIFIED |
| **Bypass: syslog listeners** | The UDP/TCP listeners take **no token**. They accept any source when `SYSLOG_ALLOWED_SOURCES` is blank (the default, [config.py:119](src/config.py#L119); [syslog_runtime.py:52-54](src/services/syslog_runtime.py#L52-L54)) and then attach the real token themselves ([syslog_runtime.py:133-134](src/services/syslog_runtime.py#L133-L134)). The local `.env` leaves the allowlist blank (verified). The AWS template sets it from a parameter ([cloudformation.yaml:232](deploy/aws/cloudformation.yaml#L232)) | **The claim is false for the syslog path unless the allowlist is set.** UDP sources are spoofable (the code comment says so, [syslog_runtime.py:178-181](src/services/syslog_runtime.py#L178-L181)) |
| Other bypass | Dashboard API is open when `DASHBOARD_ACCESS_KEY` is blank ([dashboard.py:42-43](src/api/dashboard.py#L42-L43)). It cannot inject alerts, but it can re-run FAILED/PARTIAL jobs ([dashboard.py:578-605](src/api/dashboard.py#L578-L605)), dispatch the outbox, and delete queued emails ([:566](src/api/dashboard.py#L566)) | PROVEN BY CODE |
| Payload integrity | No HMAC signature on the webhook body, no IP allowlist on `/webhook/*`. The Caddy comment states ESET has no fixed source IP ([cloudformation.yaml](deploy/aws/cloudformation.yaml), Caddyfile block) | NOT FOUND (by design) |
| Transport encryption | The app serves plain HTTP ([run.py](run.py)). TLS exists only if the AWS/Caddy deployment is used | CONFIG-DEPENDENT |

---

## PART 4 — Duplicate handling

Claim: *"Duplicate alerts are identified and prevented from generating duplicate notifications."*

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Where | `compute_dedup_key` [webhook.py:111-121](src/api/webhook.py#L111-L121); `is_duplicate`/`record_seen` [deduplication.py:8-37](src/storage/deduplication.py#L8-L37); SQLite table `dedup_log` [database.py:51-57](src/storage/database.py#L51-L57) |
| 2 | What makes a duplicate | Same `alert_id + ":" + occurred_at` when **both** are present; otherwise the SHA-256 of the **entire** original JSON (sorted keys). In the fallback case a resend that differs in any byte-level field (a send timestamp, for instance) is **not** a duplicate |
| 3 | Fields compared | `alert_id`, `occurred_at`, or the whole payload |
| 4/5 | Time window / one hour | `DEDUP_TTL_SECONDS` default **3600** ([config.py:139](src/config.py#L139)); `expires_at > now` check ([deduplication.py:13](src/storage/deduplication.py#L13)). The local `.env` evaluates to 3600 (verified). **The one-hour window is implemented as a configurable default.** |
| 6 | Before/after persistence | Checked **before** the job row (:274). The key is **recorded before** the job row too (:308 then :310), which creates a loss path (row 8) |
| 7 | Dropped or just not emailed | **Dropped completely**: no job, no pipeline, no result file. Response is HTTP 200 `{"status":"duplicate"}` plus one log line ([webhook.py:274-286](src/api/webhook.py#L274-L286)) |
| 8 | Tested | `test_deduplication.py::test_deduplication_flow` (1 s TTL), `test_webhook_endpoint.py::test_webhook_success_and_status` (duplicate → `"duplicate"`), `test_ingest_malformed.py::test_duplicate_drop_body_preview_is_logged`. The one-hour value itself is not tested |
| 9 | Concurrency | Within one process, a second concurrent request with the same key hits `PipelineAlreadyActive` ([pipeline_capacity.py:91-92](src/services/pipeline_capacity.py#L91-L92)). It is answered `"duplicate"` if the first request has already committed `record_seen`, **otherwise HTTP 503** ([webhook.py:290-305](src/api/webhook.py#L290-L305)). Across processes there is no atomic guard (`is_duplicate` then `INSERT OR REPLACE` is check-then-act), but the shipped `run.py` runs one process. Multi-process dedup is NOT PROVEN |

**What the claim gets wrong:**
- Dedup acts at ingestion only. The same alert re-sent **after** the TTL is processed again and generates a second set of emails.
- Duplicate *emails* can still happen by design. A mail-service timeout is treated as retryable and the worker does not deduplicate on `email_id` ([eset_mail.py:325-336](src/services/email_delivery/eset_mail.py#L325-L336)).

**Corrected wording:** "Repeat submissions of the same alert (same alert ID and occurrence time) within one hour are discarded at receipt. In rare mail-service timeouts a notification may be sent twice."

---

## PART 5 — Persistence / tracking

Claim: *"Every alert is saved with a tracking ID before processing starts."*

Actual sequence ([webhook.py:258-321](src/api/webhook.py#L258-L321)):

1. `correlation_id = uuid4()` (:258)
2. Parse (:262). Failure → 400, **nothing saved**
3. Dedup check (:274). Duplicate → **nothing saved**
4. Capacity reserve (:289). Full → 503, **nothing saved**
5. `record_seen(dedup_key)` (:308), written to the `dedup_log` table
6. `create_job(correlation_id, source, payload)` (:310), `INSERT INTO jobs … 'PENDING'` ([job_store.py:16-22](src/storage/job_store.py#L16-L22))
7. Background pipeline scheduled (:311). This is the first processing step.

| Question | Answer |
|---|---|
| Mechanism | SQLite `jobs` table ([database.py:38-48](src/storage/database.py#L38-L48)) plus a per-alert JSON result file `output/alerts/<correlation_id>.json` ([output_writer.py:26-61](src/services/output_writer.py#L26-L61)) |
| Before processing? | Yes, for every request that reaches step 6 |
| Failed alerts retained? | Yes. The job row is updated to FAILED/PARTIAL ([orchestrator.py:158, 242](src/pipeline/orchestrator.py#L158)) and a result file is written ([:157, :234](src/pipeline/orchestrator.py#L157)) |
| Persistence failure stops processing? | Yes. The exception propagates → HTTP 500, the reservation is released (:314-316), and no pipeline runs. **But the dedup key from step 5 stays recorded**, so ESET's retry within the TTL is answered `"duplicate"` and **the alert is never processed.** PROVEN BY EXECUTION (§14.0, probe 1) |
| Crash mid-pipeline | Jobs left PENDING/PROCESSING are re-run at the next startup ([main.py:116-160, 200](src/main.py#L116-L160)). PROVEN BY CODE + `test_pipeline_capacity.py::test_recovery_shares_capacity_and_never_starts_backlog_concurrently` |
| All ingestion paths? | Webhook and syslog-HTTP: yes (shared `ingest_alert`). **Syslog frames before forwarding live only in an in-memory queue** ([syslog_runtime.py:19, 76-93](src/services/syslog_runtime.py#L19-L93)). They are dropped when the queue is full, and a non-2xx forward (e.g. 503) is logged and **not retried** ([syslog_runtime.py:151-164](src/services/syslog_runtime.py#L151-L164)) |

**Corrected wording:** "Each accepted alert is given a tracking ID and saved before analysis begins. Rejected, duplicate, or over-capacity requests are not saved (they are logged)."

---

## PART 6 — Normalization

| Item | Evidence |
|---|---|
| Function | `normalize(raw: EsetRawPayload, source) -> NormalizedAlert` [normalizer.py:92-122](src/services/normalizer.py#L92-L122) |
| Input schema | `EsetRawPayload` [raw_payload.py](src/models/raw_payload.py) (all optional, extra allowed) |
| Output schema | `NormalizedAlert` [normalized_alert.py:4-32](src/models/normalized_alert.py#L4-L32): 23 string fields plus `raw_payload` |
| Missing fields | `"UNKNOWN"` ([normalizer.py:68-75](src/services/normalizer.py#L68-L75)) |
| Lookup order | Exact `EsetRawPayload` field → case-insensitive top-level alias from `_ALIASES` ([normalizer.py:27-65](src/services/normalizer.py#L27-L65)) → `"UNKNOWN"` |
| Handling/isolation | `bool` → `"true"`/`"false"`; any other string is lower-cased **as is** ([normalizer.py:78-89](src/services/normalizer.py#L78-L89)). The risk engine recognises only `"true"`/`"false"` ([risk_engine.py:97-100](src/services/risk_engine.py#L97-L100)). **A value like `"Yes"`, `"Cleaned"` or `"Handled"` is treated as "unknown".** |
| Severity | Copied verbatim, then mapped in the risk engine to LOW/MEDIUM/HIGH/CRITICAL plus INFO/INFORMATION/INFORMATIONAL→LOW and WARN/WARNING→MEDIUM ([risk_engine.py:47-50](src/services/risk_engine.py#L47-L50)). Anything else → MEDIUM "unknown severity" ([:143-145](src/services/risk_engine.py#L143-L145)) |
| Device / threat / time / event type / ESET IDs | `endpoint_name`, `detection_name`, `occurred_at`, `event_type`, `alert_id`/`detection_uuid`/`target_uuid`: string copies, no parsing or validation. `occurred_at` is never parsed as a date. **No ESET console URL field exists** in either model |

**Field lineage examples:**

| Raw input | Normalized | Next consumer |
|---|---|---|
| `"severity": "HIGH"` | `severity="HIGH"` | `risk_engine._base_level` [:103-145](src/services/risk_engine.py#L103-L145) |
| `"threat_handled": false` | `threat_handled="false"` | `_handled` → base level, intel rule, important-endpoint rule, ransomware rule |
| `"computer_name": "PC-01"` (not an `EsetRawPayload` field) | `endpoint_name="PC-01"` via alias | `observation_store.record_and_count`, `is_important_endpoint`, email subjects |
| `"file_hash": "<sha256>"` | `file_hash` | VirusTotal `/files/{hash}` (only when mock is off) |
| `"ip_address": "203.0.113.5"` | `ip_address` | AbuseIPDB; also VirusTotal when there is no hash and no URL |
| `"domain": "x.example"` | `domain` | **No threat-intel lookup.** Goes only to the AI prompt and the fallback email fact list |
| `"affected_endpoints": [...]` | (stays in `raw_payload`) | `reported_endpoint_count` → CRITICAL rule |

**Fields the code depends on that are not proven to exist in real ESET payloads:** all of them. In particular, `threat_handled` (and its value vocabulary), `isolation_status`, `endpoint_type`, `severity` (and its vocabulary), `file_hash`, `ip_address`, `url`, the `affected_*` count/list keys, and the `outbreak` wording in text fields. Only the client's ESET tenant can settle these: REQUIRES LIVE EXTERNAL VALIDATION.

Tests: `test_normalizer.py` (5 tests, synthetic inputs).

---

## PART 7 — Threat intelligence

Claim: *"File hashes, IP addresses or domains are checked against VirusTotal and AbuseIPDB."*

| # | VirusTotal | AbuseIPDB |
|---|---|---|
| 1 Client | `VirusTotalProvider` [virustotal.py:43-182](src/services/threat_intel/virustotal.py#L43-L182) | `AbuseIPDBProvider` [abuseipdb.py:12-141](src/services/threat_intel/abuseipdb.py#L12-L141) |
| 2 Invoked by | `gather_threat_intel` [aggregator.py:11-56](src/services/threat_intel/aggregator.py#L11-L56) ← [orchestrator.py:117](src/pipeline/orchestrator.py#L117) | same |
| 3 Input | **One** indicator: `file_hash`, else `url`, else `ip_address` ([virustotal.py:55-63](src/services/threat_intel/virustotal.py#L55-L63)). **Domain never.** | `ip_address` only ([abuseipdb.py:19-23](src/services/threat_intel/abuseipdb.py#L19-L23)) |
| 4 API call | `GET https://www.virustotal.com/api/v3/{files|ip_addresses|urls}/…` with header `x-apikey` ([:125-147](src/services/threat_intel/virustotal.py#L125-L147)) | `GET https://api.abuseipdb.com/api/v2/check` with header `Key` ([:92-111](src/services/threat_intel/abuseipdb.py#L92-L111)) |
| 5 Response read | `last_analysis_stats`: malicious >5 → MALICIOUS; any malicious/suspicious → SUSPICIOUS; else CLEAN; 404 → UNKNOWN ([:149-172](src/services/threat_intel/virustotal.py#L149-L172)) | `abuseConfidenceScore` ≥50 → MALICIOUS; >10 or reports >5 → SUSPICIOUS ([:113-123](src/services/threat_intel/abuseipdb.py#L113-L123)) |
| 6 Effect on alert | Stored in `PipelineResult.threat_intel`. **Used by risk only when `USE_MOCK_THREAT_INTEL=false`** ([orchestrator.py:136](src/pipeline/orchestrator.py#L136)); sent to the AI only when not mock ([base.py:242-251](src/services/ai/base.py#L242-L251)) | same |
| 7 Real or mock | Both are coded. **Mock is the default** ([config.py:166](src/config.py#L166) `True`). Mock heuristics: indicator contains "malicious"/"ransom"/"virus" → MALICIOUS ([:74-107](src/services/threat_intel/virustotal.py#L74-L107)) | Mock: `"100" in ip` → MALICIOUS, `"50" in ip` → SUSPICIOUS ([:30-69](src/services/threat_intel/abuseipdb.py#L30-L69)) |
| 8 API failure | Timeout (default 5 s) or exception → `UNKNOWN` with the error recorded; the pipeline continues ([aggregator.py:24-42](src/services/threat_intel/aggregator.py#L24-L42)). UNKNOWN never raises risk | same |
| 9 Key required | Yes. Read from **`os.environ` only** ([virustotal.py:113](src/services/threat_intel/virustotal.py#L113), [abuseipdb.py:75](src/services/threat_intel/abuseipdb.py#L75)). **A key placed in `.env` is not seen** (pydantic-settings does not export to `os.environ`; PROVEN BY EXECUTION). It must be a real environment variable or come via the `APP_SECRETS_SECRET_ID` overlay ([secrets.py:193-195, 222-225](src/services/secrets.py#L193-L225)). Missing key → UNKNOWN | same |
| 10 Enabled by default | **No** (mock on). The local `.env` doesn't override it (verified); the AWS template doesn't set it ([cloudformation.yaml:217-233](deploy/aws/cloudformation.yaml#L217-L233)) | same |
| 11 Called in main pipeline | Yes, always called (orchestrator.py:117). With mock on, the call never leaves the process | same |

**Evidence of a real call:** `logs/app.log` has `vt_query_real_start` = **0**, `abuseipdb_query_real_start` = **0**, `vt_query_mock` = 18, `abuseipdb_query_mock` = 3.

**Tests:**
- `test_poc_cases.py::test_real_threat_intel_raises_the_risk_level` replaces `gather_threat_intel` with a function that returns a canned MALICIOUS result. It proves the **risk wiring**, not the integration.
- `test_indicator_validation.py` calls `_query_real` only with inputs rejected before any network call.
- **No test makes or simulates a VirusTotal/AbuseIPDB HTTP exchange.**

**Status:** the integration code exists (PROVEN BY CODE). Live operation is NOT PROVEN FROM REPOSITORY / REQUIRES LIVE EXTERNAL VALIDATION. In the default configuration the **real lookup does not run and has no effect on risk**. The domain checking in the claim is NOT FOUND.

**Corrected wording:** "When enabled, file hashes, URLs or IP addresses (one per alert for VirusTotal; IPs only for AbuseIPDB) are checked, and a malicious or suspicious verdict can raise the risk level. In the current configuration these lookups are simulated and do not affect the risk level."

---

## PART 8 — Risk engine

Trace: `NormalizedAlert` → `observation_store.record_and_count` ([orchestrator.py:126](src/pipeline/orchestrator.py#L126)) → `risk_engine.assess_risk(alert, intel-or-None, observed_endpoint_count)` ([:135-137](src/pipeline/orchestrator.py#L135-L137); [risk_engine.py:194-270](src/services/risk_engine.py#L194-L270)) → `assessment.level` → `PipelineResult.risk_level`. The level is persisted in the result file ([output_writer.py:40-48](src/services/output_writer.py#L40-L48)) and `index.json` ([:82](src/services/output_writer.py#L82)), logged as `risk_assessed` ([risk_engine.py:268](src/services/risk_engine.py#L268)), and stored with its factors and rationale.

| Rule / claim | Exact code | Implemented? | Notes |
|---|---|---|---|
| Base level from ESET severity + handled + isolated | [risk_engine.py:103-145](src/services/risk_engine.py#L103-L145) | Yes | CRITICAL→CRITICAL; HIGH: handled+isolated→**LOW**, handled→MEDIUM, else HIGH; MEDIUM: handled→LOW else MEDIUM; LOW: handled→LOW else **MEDIUM**; unknown→MEDIUM. **The base can be lower than ESET's own severity** |
| Threat intel raises | [:220-234](src/services/risk_engine.py#L220-L234) | Yes, **only when not mock** | MALICIOUS → floor HIGH (MEDIUM if handled); SUSPICIOUS + not handled → floor MEDIUM |
| Endpoint importance | [:236-241](src/services/risk_engine.py#L236-L241), [:179-191](src/services/risk_engine.py#L179-L191) | Yes | Unhandled + type contains "server"/"domain controller" or name matches `IMPORTANT_ENDPOINT_PATTERNS` (blank by default) → +1 level, capped at HIGH |
| Ransomware pattern | regex [:55-60](src/services/risk_engine.py#L55-L60); rule [:245-252](src/services/risk_engine.py#L245-L252) | Yes | Unhandled → CRITICAL; handled → floor HIGH. Matches against detection_name/event_type/raw_subject/raw_content |
| ESET outbreak | [:61](src/services/risk_engine.py#L61), [:254-255](src/services/risk_engine.py#L254-L255) | Yes | The word "outbreak" (or アウトブレイク) in text fields → CRITICAL. Whether ESET uses that wording: ASSUMED |
| **3+ machines within one hour = CRITICAL** | [:257-266](src/services/risk_engine.py#L257-L266); counting in [observation_store.py:12-45](src/storage/observation_store.py#L12-L45) | **Yes, as configurable defaults** (`OUTBREAK_ENDPOINT_THRESHOLD=3`, `OUTBREAK_WINDOW_SECONDS=3600`, [config.py:158-159](src/config.py#L158-L159)) | Two routes: (a) the payload reports ≥3 endpoints via guessed keys ([:63-66](src/services/risk_engine.py#L63-L66)); (b) this platform has seen the same `detection_name` on ≥3 distinct `endpoint_name`s in the window. Route (b) needs both names known ([observation_store.py:19-20](src/storage/observation_store.py#L19-L20)) and counts only alerts that passed dedup |
| Rules only raise | `_raise_to` [:93-94](src/services/risk_engine.py#L93-L94), used by `apply` [:212-218](src/services/risk_engine.py#L212-L218) | Yes, **relative to the base level** | Not relative to ESET's reported severity (see first row). Test: `test_rules_never_lower_the_base_level` |
| AI cannot change it | Schema pin [base.py:347](src/services/ai/base.py#L347) + [schema_builder.py:65-94](src/services/ai/schema_builder.py#L65-L94); hard check [output_validator.py:36-40](src/services/ai/output_validator.py#L36-L40) | Yes | The validator check is provider-independent and blocks any mismatch. Tests: `test_output_validator.py::test_a_different_risk_level_is_rejected`, `test_poc_cases.py::test_output_with_a_changed_risk_level_is_blocked` |
| "Same alert always same level" | Pure function of (alert, intel, observed count, config) | **Partially** | Same *inputs* → same level. But the observed count depends on prior traffic, live intel (when enabled) can change, and thresholds are env-tunable. The same payload can get a different level at a different time |

**Approval status (separate from implementation):** the module docstring says *"The rule table is an engineering proposal pending client sign-off"* ([risk_engine.py:25-26](src/services/risk_engine.py#L25-L26)). The rules are **technically implemented but not approved**. There is no evidence of sign-off in the repository.

Tests: `test_risk_engine.py` (24 tests), `test_poc_cases.py` (5 parametrised fixtures). All inputs are synthetic.

---

## PART 9 — AI / OpenAI flow

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Provider actually used | Selected at runtime by `AI_PROVIDER` (default `"openai"`); `azure_openai` and `gemini` are also wired | [config.py:12](src/config.py#L12), [factory.py:29-33, 53-62](src/services/ai/factory.py#L29-L62) |
| 2 | Model | `OPENAI_MODEL`, **no default** ([config.py:17](src/config.py#L17)). Unset → `AIConfigurationError` ([openai_provider.py:76-77](src/services/ai/openai_provider.py#L76-L77)) → PARTIAL. **Unset locally (verified).** The AWS template sets it from a stack parameter | CONFIGURED BUT NOT VERIFIED |
| 3 | Client init | `openai.AsyncOpenAI(..., max_retries=0, timeout=AI_TIMEOUT_SECONDS)`; key via Secrets Manager or env | [openai_provider.py:104-128](src/services/ai/openai_provider.py#L104-L128) |
| 4 | Request | `client.chat.completions.create(model, messages=[system,user], response_format=json_schema strict, max_completion_tokens, store=False)` | [openai_provider.py:132-154](src/services/ai/openai_provider.py#L132-L154) |
| 5 | Data sent | `predefined_risk` (level, rationale, base/raised factors); `normalized_alert` (masked, capped, without `raw_payload`); `original_submitted_payload` (masked, capped); `threat_intelligence` (or a `NOT_CHECKED` note in mock mode); `unknown_fields` | [base.py:226-291](src/services/ai/base.py#L226-L291) |
| 6 | Prompt | Static system prompt ([system_prompts.py](src/prompts/system_prompts.py), no interpolation) plus a user prompt that fences the JSON between `<<<BEGIN/END_UNTRUSTED_ALERT_DATA>>>` | [base.py:279-290](src/services/ai/base.py#L279-L290) |
| 7 | Fields requested | 12: `risk_level`, `alert_summary_ja`, `risk_reason_ja`, `client_notification_ja`, `internal_summary_ja`, `engineer_summary_en`, `recommended_initial_actions_ja`, `additional_confirmation_items_ja`, `unknown_items`, `backlog_comment_ja`, `email_subject_ja`, `email_body_ja` | [ai_output.py:22-68](src/models/ai_output.py#L22-L68) |
| 8 | Risk sent to AI | Yes | base.py:252-266, 288 |
| 9 | AI can change risk | No (Part 8) | — |
| 10 | Support text only | Yes. The AI output feeds only email/report text; no code path reads AI output into the risk decision | orchestrator.py:166-243 |
| 11 | AI fails | `AIGenerationError` / `AIConfigurationError` / any exception → `ai_output=None` → `PARTIAL` + fallback emails to the internal and engineer lists only | [orchestrator.py:177-189, 228-243](src/pipeline/orchestrator.py#L177-L243) |
| 12 | Timeout | `asyncio.wait_for(..., AI_TIMEOUT_SECONDS=60)` per attempt; up to `AI_MAX_ATTEMPTS=3` (hard cap 5) with 1-10 s backoff, transient errors only | [base.py:351, 376-399](src/services/ai/base.py#L351-L399); [config.py:54, 58](src/config.py#L54) |
| 13 | Malformed output | Pydantic `ValidationError` / `JSONDecodeError` → `AIGenerationError` (not retried) → PARTIAL. Refusal, `length` and `content_filter` → `AIOutputRejected` | [base.py:410, 439-457](src/services/ai/base.py#L410-L457); [openai_provider.py:168-179](src/services/ai/openai_provider.py#L168-L179) |

**Evidence of real OpenAI operation:**
- Repository artifacts: **none**. 2 result files show `provider=openai, model=unset, PARTIAL`. 16 `SUCCESS` files have no `ai_run` (pre-OpenAI; provider not recorded). The log has `ai_generation_success` = 0.
- Tests use `FakeProvider` ([tests/ai_fakes.py](tests/ai_fakes.py), [conftest.py:79-93](tests/conftest.py#L79-L93)) or a fake SDK client (`test_openai_provider.py`). These prove the request shape and the error handling, not live behaviour.
- `scripts/run_poc_cases.py` can run against the real API, but **no output from such a run is in the repository.**

**Status:** PROVEN ONLY BY TEST/MOCK; REQUIRES LIVE EXTERNAL VALIDATION.

---

## PART 10 — Data masking / privacy

Claim: *"Before anything goes to AI, personal data is masked."*

Flow: `NormalizedAlert` → `_truncate_free_text` → **`mask_alert_for_prompt`** (if `AI_MASKING_ENABLED`) → `mask_raw_payload_for_prompt` → `_truncate_free_text` → `json.dumps` → user prompt → OpenAI ([base.py:231-240, 279-290](src/services/ai/base.py#L231-L290)). Masking happens **before** prompt construction (PROVEN BY CODE).

| Data | Masked? | Evidence |
|---|---|---|
| `user_name` | Yes: first and last character kept (`j******e`) | [prompt_masking.py:39, 56-60, 78-82](src/services/ai/prompt_masking.py#L39-L82) |
| Username segment of `C:\Users\<name>\…` | Yes | [:44, 63-67, 90-95](src/services/ai/prompt_masking.py#L44-L95) |
| Unix home paths (`/home/<name>`, `/Users/<name>`) | **No** | No regex for them |
| Email addresses (any string field) | Mailbox partially masked, domain kept | [:45, 50-53](src/services/ai/prompt_masking.py#L45-L53) |
| `DOMAIN\user` in free text | User part masked | [:47](src/services/ai/prompt_masking.py#L47) |
| `alert_id`, `detection_uuid`, `target_uuid` | Replaced by `[INTERNAL_ID]` | [:41, 84-88](src/services/ai/prompt_masking.py#L41-L88) |
| Raw payload keys named user/username/owner/account/email/… | Masked at any depth | [:114-117, 125-162](src/services/ai/prompt_masking.py#L114-L162) |
| Raw payload keys named id/uuid/tenant_id/customer_id/… | `[INTERNAL_ID]` | [:119-122](src/services/ai/prompt_masking.py#L119-L122) |
| **Endpoint name, IP, URL, domain, file hash, OS, object path (except a Windows profile segment)** | **No, deliberately** | Docstring [:23-27](src/services/ai/prompt_masking.py#L23-L27) |
| Person names in free text (e.g. "user Tanaka logged in") | **No** | Only email and `DOMAIN\user` patterns are applied to free text |
| HTTP headers | Never stored or sent | Only the JSON body enters `raw_payload` |
| System prompt | Contains no alert values | Static string |
| Whole mechanism | **Switchable off** via `AI_MASKING_ENABLED=false` (default true; the AWS template sets true) | [config.py:173](src/config.py#L173); [base.py:233-238](src/services/ai/base.py#L233-L238) |

The policy itself is marked *"engineering proposal pending client sign-off"* ([config.py:169-172 comment](src/config.py#L169), [prompt_masking.py:4-7](src/services/ai/prompt_masking.py#L4-L7)).

Tests: `test_prompt_masking.py` (15 tests) and `test_ai_prompt.py::test_personal_data_and_internal_ids_are_masked_before_the_prompt`, which checks the payload handed to the fake provider. These prove the transformation. Whether any **real** ESET field carries personal data the policy misses: NOT PROVEN FROM REPOSITORY.

**Corrected wording:** "Before alert data is sent to the AI service, usernames, email mailboxes and internal ESET identifiers are masked. Device names, IP addresses, URLs, domains and file hashes are sent unmasked because they are needed for the analysis."

---

## PART 11 — AI output validation

```
AI RESPONSE (JSON text)
 ├─ Layer 1  provider-side strict JSON schema; risk_level enum pinned to one value   base.py:347, openai_provider.py:139-142
 ├─ Layer 2  AIOutput.model_validate_json (extra keys forbidden, Literal risk levels)  base.py:410, ai_output.py:23-27
 │           FAIL → AIGenerationError → PARTIAL + fallback (orchestrator.py:177-189)
 └─ Layer 3  validate_ai_output(output, risk_level)                                   orchestrator.py:195; output_validator.py:32-61
             ├─ risk_level == rule-engine level                                       :36-40
             ├─ 8 text fields + 2 list fields non-empty                              :24-28, 42-47
             ├─ no bracketed [LEVEL]/【LEVEL】 contradicting the level, in any field  :49-56
             └─ no prohibited phrase (52 EN/JA phrases, with negation skip)          :58-59; lint_checker.py:22-134
             FAIL → ai_run.status=BLOCKED, ai_output=None → PARTIAL + fallback      orchestrator.py:196-207
             PASS → compose 4 emails                                                 orchestrator.py:233
```

- **Blocked output prevents sending.** With `ai_output=None`, `compose_emails` returns `[]` ([email_composer.py:210-211](src/services/email_composer.py#L210-L211)), so only fallback notices are built. PROVEN BY CODE + `test_poc_cases.py::test_output_claiming_the_environment_is_safe_is_blocked`.
- **Fallback content bypasses validation.** It is a fixed template built from alert fields and rule output ([email_composer.py:142-175](src/services/email_composer.py#L142-L175)). It is not AI text. It goes only to the internal and engineer lists, and it contains unmasked `object_uri`, IP and domain.
- **Limits of the check:**
  - It is an exact-phrase list, not a semantic review ([lint_checker.py:4-8](src/services/ai/lint_checker.py#L4-L8)).
  - Prose that implies a different severity without a bracketed label passes.
  - Nothing checks that the AI's statements are factually consistent with the alert.
  - **No human reviews the text before the client email is sent.**
- **One post-validation edit:** `_client_subject` prepends `【LEVEL】` if the model omitted it ([email_composer.py:54-60](src/services/email_composer.py#L54-L60)). It is deterministic.

---

## PART 12 — Email composition

Specs: [email_composer.py:109-114](src/services/email_composer.py#L109-L114). One loop builds all of them: `_build` [:178-202](src/services/email_composer.py#L178-L202).

| Email | Type | Recipients | Subject | Body | Language | When |
|---|---|---|---|---|---|---|
| Client | `CLIENT_JA` | `client_notification_emails` (dashboard override, else env; [settings_store.get_effective](src/storage/settings_store.py)) | AI `email_subject_ja`, `【LEVEL】` forced ([:54-60](src/services/email_composer.py#L54-L60)) | AI `email_body_ja` verbatim ([:63-64](src/services/email_composer.py#L63-L64)) | JA | SUCCESS path only, if recipients set |
| C-Three | `CTHREE_JA` | `cthree_notification_emails` | `[LEVEL] detection — endpoint` ([:39-41](src/services/email_composer.py#L39-L41)) | Review request plus a **copy of the client draft** ([:67-79](src/services/email_composer.py#L67-L79)) | JA | SUCCESS path only, if recipients set |
| Internal | `INTERNAL_JA` | `internal_notification_emails` | same | AI internal summary, actions, Backlog draft ([:82-94](src/services/email_composer.py#L82-L94)) | JA | SUCCESS; plus the fallback notice on PARTIAL |
| Engineer | `ENGINEER_EN` | `engineer_notification_emails` | same | AI EN summary plus rule factors ([:97-105](src/services/email_composer.py#L97-L105)) | EN | SUCCESS; plus the fallback notice on PARTIAL |

- A type with no recipients is **silently skipped** (warning log, [:182-189](src/services/email_composer.py#L182-L189)). All four recipient settings default to blank ([config.py:181-184](src/config.py#L181-L184)).
- All composed emails are queued together ([orchestrator.py:235](src/pipeline/orchestrator.py#L235) → `email_outbox.add_emails`, one write) and handed off by the same immediate sweep ([:74](src/pipeline/orchestrator.py#L74)).

**CLIENT vs C-THREE: independent and parallel. There is no approval dependency.** Evidence:

1. One loop over `_NOTIFICATION_SPECS`, with no condition linking CLIENT_JA to CTHREE_JA.
2. One `add_emails` call with one shared `created_at`.
3. `dispatch_pending` iterates the outbox in order with no type-based hold ([email_dispatcher.py:78-111](src/services/email_dispatcher.py#L78-L111)).
4. A search for `approv|awaiting_review|pending_review|hold_client` over `src/` returns only a prompt sentence about isolation steps.
5. `docs/OPENAI_INTEGRATION.md:457` lists *"Decide whether client emails should instead wait for human approval"* as an **open item**.
6. **PROVEN BY EXECUTION** (§14.0, probe 3): all four were queued with an identical timestamp.
7. Local DB: 16 `CLIENT_JA` and 16 `CTHREE_JA` rows, each `ACCEPTED` after 1 attempt.

**C-Three's role in code is "receives a copy of the draft", not "approves it".**

---

## PART 13 — Email delivery

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Provider | "ESET Mail" Cloudflare Worker, `POST {EMAIL_API_URL}` (the only registered provider) | [email_delivery/__init__.py:14-25](src/services/email_delivery/__init__.py#L14-L25) |
| 2 | Function | `EsetMailProvider.send()` | [eset_mail.py:294-340](src/services/email_delivery/eset_mail.py#L294-L340) |
| 3 | Call | `httpx` POST, JSON body; `X-API-Key` plus HMAC-SHA256 signature/timestamp/nonce in `full` mode | [eset_mail.py:212-290](src/services/email_delivery/eset_mail.py#L212-L290) |
| 4 | Success | HTTP 200/202 **and** `success: true`; `id` stored as `remote_id` | [eset_mail.py:410-421](src/services/email_delivery/eset_mail.py#L410-L421) |
| 5 | Failure | Classified: timeout/transport/5xx/unrecognised 400/replay or clock-skew 401 → retryable; recognised validation 400 / other 401 / unconfigured → permanent | [eset_mail.py:325-338, 342-445](src/services/email_delivery/eset_mail.py#L325-L445) |
| 6/8 | Retries | `EMAIL_MAX_ATTEMPTS` default **3 total attempts** (not 3 retries) | [config.py:207](src/config.py#L207); [email_dispatcher.py:147-149](src/services/email_dispatcher.py#L147-L149) |
| 7/9 | Interval | Attempt 1 is immediate (`dispatch_soon`, [orchestrator.py:74](src/pipeline/orchestrator.py#L74)). Later attempts happen on the next sweeper tick, every `max(10, EMAIL_DISPATCH_INTERVAL_SECONDS)` = **60 s** by default ([email_dispatcher.py:205](src/services/email_dispatcher.py#L205); [config.py:208](src/config.py#L208)). The sweeper runs on a fixed cadence, so the gap is **up to** 60 s, not exactly 60 s. Worst case is about 2 minutes plus 3 × the 60 s HTTP timeout | PROVEN BY CODE |
| 10 | After retries | Written to `output/emails/dead_letter.json`, removed from the outbox, delivery row `FAILED` | [email_dispatcher.py:151-175](src/services/email_dispatcher.py#L151-L175) |
| 11 | Failed-email queue | Yes, as a file plus a dashboard listing ([email_outbox.py:104-151](src/services/email_outbox.py#L104-L151)). **There is no automatic replay**: replaying is manual | PROVEN BY CODE |
| 12 | Silent loss possible | **Yes.** See §14 rows E1-E6 | — |
| 13 | Delivery proven? | **Only the handoff.** [delivery_store.py:1-15](src/storage/delivery_store.py#L1-L15) says so: states are PENDING/ACCEPTED/FAILED "about *handoff*, not final delivery". Inbox delivery: **NOT PROVEN FROM REPOSITORY** | — |

**Precondition:** none of this runs unless `EMAIL_DELIVERY_ENABLED=true` ([email_dispatcher.py:63-64](src/services/email_dispatcher.py#L63-L64)). Otherwise emails stay in `outbox.json` indefinitely: not sent, no attempts counted. The default is `False`. The local `.env` has `true`. The **AWS template does not set it.**

**Tests:** `test_eset_mail_provider.py` (≈40 tests) checks signing and response classification against an in-test re-implementation of the worker's verifier. It proves the client's wire format matches *that re-implementation*, not the live worker. **No test covers `_hand_off`, the attempt counter, the sweeper or dead-lettering.** Every test forces `email_delivery_enabled=False` ([conftest.py:73-77](tests/conftest.py#L73-L77)).

**Live handoff evidence:** the local DB has 67 ACCEPTED handoffs with `remote_id` for synthetic alerts, and the log has 67 `email_handoff_accepted` events. That proves the worker accepted requests from this code in the developer's environment. It does not prove inbox delivery or production configuration.

---

## PART 14 — Failure and fallback paths

### 14.0 Behaviours confirmed by execution (temporary probes, removed afterwards)

| Probe | Observed |
|---|---|
| 1. `job_store.create_job` raises once, then ESET retries the same alert | First request **HTTP 500**; retry → **HTTP 200 `{"status":"duplicate"}`**. The alert is never processed |
| 2. `gather_threat_intel` raises | Job **FAILED**, outbox **0 entries**: nobody is notified |
| 3. Normal HIGH alert, all four recipient lists set | Queued `CLIENT_JA`, `CTHREE_JA`, `INTERNAL_JA`, `ENGINEER_EN` with an identical `created_at` |

### 14.1 Failure matrix

| Case | Alert retained? | Processing | Fallback | Human follow-up triggered? | Notification |
|---|---|---|---|---|---|
| Bad token / missing header | No (log line only) | Stops: 401/429 | — | No | None |
| Oversized / malformed JSON | No (≤4000-char log preview) | Stops: 413/400 | — | No | None |
| Duplicate within TTL | No (log line) | Stops: 200 "duplicate" | — | No | None (intended) |
| Capacity full (`MAX_CONCURRENT_PIPELINES=4`) | No | 503 + Retry-After; **relies on ESET retrying** (ESET retry behaviour: NOT PROVEN) | — | No | None |
| **DB failure at `create_job`** | No; **dedup key burned** | 500 | — | No | **None; retries within 1 h dropped** (probe 1) |
| DB failure at `update_job_status("PROCESSING")` | Job row stays PENDING | Pipeline aborts (logged, [webhook.py:140-145](src/api/webhook.py#L140-L145)) | Re-run at next restart only | No | None until restart |
| **Exception in normalize / intel / observation / risk** | Yes: job FAILED + result file ([orchestrator.py:145-160](src/pipeline/orchestrator.py#L145-L160)) | Stops | **None** | **No**: visible only on the dashboard/log | **None to anyone** (probe 2). (Intel *API* errors are caught and become UNKNOWN, so they do not trigger this) |
| Threat-intel API failure/timeout | Yes | Continues | Verdict UNKNOWN | No | Normal |
| AI failure / timeout / malformed / config | Yes: PARTIAL | Continues | Deterministic notice | Yes, via email to the internal + engineer lists (if configured) | **No client or C-Three email** |
| AI validation failure | Yes: PARTIAL, `ai_run.status=BLOCKED` | Continues | Same as above | Same | Same |
| Email composition exception | Yes (job SUCCESS/PARTIAL) | Continues | — | No (EMAIL stage "failed" event + log) | **None** ([orchestrator.py:44-50](src/pipeline/orchestrator.py#L44-L50)) |
| Outbox write failure (`add_emails`) | Yes | Continues | — | No (log) | **None**: emails exist only in memory ([orchestrator.py:60-65](src/pipeline/orchestrator.py#L60-L65)) |
| Delivery disabled | Yes | — | — | No | Queued forever, never sent |
| Handoff retryable failure | Yes (outbox) | Retried on the sweep | — | No | Later, or dead letter |
| Handoff permanent failure / retries exhausted | Dead letter file | Stops | — | No automatic alert; dashboard list only | None |

### 14.2 Silent or quiet loss paths (contradicting "none can be lost")

- **I1** Dedup key recorded before the job row ([webhook.py:308-310](src/api/webhook.py#L308-L310)). A failed `create_job` means retries are dropped (probe 1).
- **I2** Syslog frames: queue full → dropped ([syslog_runtime.py:83-93](src/services/syslog_runtime.py#L83-L93)); forward non-2xx (401/503) → logged, not retried ([:157-164](src/services/syslog_runtime.py#L157-L164)).
- **I3** 503 at capacity: the alert is lost unless the sender retries.
- **P1** Pre-AI exception → FAILED with no notification (probe 2).
- **E1** Composition exception → no emails ([orchestrator.py:44-50](src/pipeline/orchestrator.py#L44-L50)).
- **E2** Outbox write exception → no emails ([orchestrator.py:60-65](src/pipeline/orchestrator.py#L60-L65)).
- **E3** Corrupt `outbox.json` is treated as empty ([email_outbox.py:34-36](src/services/email_outbox.py#L34-L36)); the next write **overwrites pending emails**. This is the asserted behaviour of `test_email_composer.py::test_corrupt_outbox_file_is_recovered`.
- **E4** A dead-letter write failure is swallowed ([email_outbox.py:144-145](src/services/email_outbox.py#L144-L145)), then the email is removed from the outbox anyway.
- **E5** No recipients configured for a type → skipped with only a warning log.
- **E6** Dashboard `DELETE /dashboard/api/emails/{id}` discards a queued email (manual; open to anyone if `DASHBOARD_ACCESS_KEY` is blank).

---

## PART 15 — Test evidence

Suite run 2026-10-02: **463 tests, 462 passed, 1 failed** (CSP hash, unrelated). Global fixtures ([tests/conftest.py](tests/conftest.py)) apply to **every** test:
- AI provider replaced with `FakeProvider` (:79-93)
- `use_mock_threat_intel=True` (:77)
- `email_delivery_enabled=False` (:76)
- Temp DB and output directories (:15-30)

| Flow step | Test exists? | Real external service? | Mocked? | What it actually proves |
|---|---|---|---|---|
| Webhook route + auth | Yes: `test_security.py`, `test_webhook_endpoint.py`, `test_hardening.py` | No (TestClient) | ESET is simulated | Token enforcement, 401/429, response shape |
| Malformed/oversized ingest | Yes: `test_ingest_malformed.py` | No | — | 400/413 handling, no job row |
| Syslog listener | Yes: `test_syslog_listeners.py`, `test_syslog_security.py`, `test_syslog_handler.py` | No | Loopback forward patched | Frame extraction, allowlist, bounds, key mapping |
| Dedup | Yes: `test_deduplication.py`, the duplicate step in `test_webhook_endpoint.py` | No | — | Key match + TTL expiry (1 s TTL); the 1 h value is untested |
| Capacity / recovery | Yes: `test_pipeline_capacity.py` | No | — | Reservation lifecycle, 503, recovery concurrency |
| Normalization | Yes: `test_normalizer.py` | No | — | Field mapping on synthetic shapes |
| Threat intel | Partial: `test_indicator_validation.py`; `test_poc_cases.py` (mock + a stubbed "real" result) | **No** | VirusTotal and AbuseIPDB never contacted | Indicator sanitising; risk wiring with a canned verdict. **Not the API integration** |
| Risk engine | Yes: `test_risk_engine.py`, `test_poc_cases.py` | n/a | — | Every rule on synthetic alerts |
| AI prompt / masking | Yes: `test_ai_prompt.py`, `test_prompt_masking.py` | No | FakeProvider | What would be sent; masking transforms |
| OpenAI provider | Yes: `test_openai_provider.py` | **No** | Fake SDK client | Request kwargs, retry policy, error mapping |
| Output validation | Yes: `test_output_validator.py`, `test_lint_checker.py`, `test_poc_cases.py` | n/a | — | Blocking rules |
| Email composition | Yes: `test_email_composer.py` | n/a | — | Four types, recipients, fallback is team-only |
| Mail provider wire format | Yes: `test_eset_mail_provider.py` | **No** | Re-implemented worker verifier | Signing/classification vs. the in-test model of the worker |
| **Dispatcher retry / attempts / sweep / dead letter** | **No** | — | — | **Nothing** |
| End-to-end ingest → emails queued | Yes: `test_full_pipeline.py`, `test_poc_cases.py` | **No** | AI fake, intel mock, delivery off | Internal orchestration up to the outbox |
| End-to-end with real ESET / OpenAI / VirusTotal / AbuseIPDB / inbox | **No** | — | — | — |

---

## PART 16 — External integration evidence

| Integration | Code location | Actual API call in code | Credentials configured | Mock available | Real live evidence in repo | Status |
|---|---|---|---|---|---|---|
| ESET PROTECT (webhook) | [webhook.py:324](src/api/webhook.py#L324) | n/a (inbound) | Token: local yes (value not checked); prod via Secrets Manager (not verified) | Fixtures, `send_test_webhook.sh` | **None** | REQUIRES LIVE EXTERNAL VALIDATION |
| ESET PROTECT (syslog) | [syslog_runtime.py](src/services/syslog_runtime.py) | n/a (inbound) | Allowlist blank locally | `send_test_syslog.py` | **None** (0 forwards in log) | REQUIRES LIVE EXTERNAL VALIDATION |
| VirusTotal | [virustotal.py:109-182](src/services/threat_intel/virustotal.py#L109-L182) | Yes (httpx GET v3) | **No** (not in `.env`; would be ignored there anyway) | Yes (default) | **0** real calls | NOT PROVEN; default OFF |
| AbuseIPDB | [abuseipdb.py:71-141](src/services/threat_intel/abuseipdb.py#L71-L141) | Yes (httpx GET v2/check) | **No** | Yes (default) | **0** real calls | NOT PROVEN; default OFF |
| OpenAI | [openai_provider.py](src/services/ai/openai_provider.py) | Yes (SDK chat.completions) | Local: **model unset** (verified) | FakeProvider / fake SDK | **0** successes; 2 config failures | NOT PROVEN |
| Gemini (alternative) | [gemini_service.py](src/services/ai/gemini_service.py) | Yes | Not active | — | 16 SUCCESS results predate run metadata; provider not recorded | NOT PROVEN FROM REPOSITORY |
| ESET Mail worker | [eset_mail.py](src/services/email_delivery/eset_mail.py) | Yes (httpx POST, HMAC) | Local: delivery enabled | Worker verifier re-implemented in tests | **67 accepted handoffs** (synthetic alerts, dev environment) | Handoff PROVEN locally; inbox delivery NOT PROVEN |
| AWS Secrets Manager | [secrets.py](src/services/secrets.py) | Yes (boto3) | Template only | Tests stub boto3 | None | CONFIGURED BUT NOT VERIFIED |

**ESET specifically:**

| Evidence item | Present? |
|---|---|
| 1. Actual ESET webhook request | **No** |
| 2. Actual ESET payload | **No** |
| 3. Successful authentication by ESET | **No** |
| 4. Successful normalization of ESET data | **No** |
| 5. Successful processing | **No** |
| 6. Actual ESET alert reaching the risk engine | **No** |
| 7. Actual ESET alert resulting in an email | **No** |

---

## PART 17 — Timing

Search: no performance tests, benchmarks, latency metrics or monitoring exist for the pipeline. `grep latency|benchmark|perf_counter|p95` finds only the AI connection-test latency and AI trace `duration_ms`.

Raw timestamps exist from **19 local synthetic runs**. These are *not* a measurement of production timing. Their provider is unrecorded, they ran with mock intel and on a developer machine:

| Interval | n | min | median | max |
|---|---|---|---|---|
| job created → final job status | 19 | 0.1 s | 7.1 s | 10 357 s (one re-run, which inflates the max) |
| job created → client email accepted by mail worker | 16 | 6.0 s | 11.2 s | 161.4 s |

The code bounds the worst case without measuring it:
- AI: up to 3 × 60 s plus backoff
- Threat intel: 5 s
- Email: up to 3 attempts across about 2 min of sweeps, each with up to a 60 s HTTP timeout

**Verdict: NOT MEASURED / NOT PROVEN.** "Within seconds" or "a minute or two" cannot be stated from this repository.

---

## PART 18 — Final evidence-backed flow

```
ESET PROTECT
  ↓  (A) HTTP POST /webhook/eset   or   syslog frame → loopback POST /webhook/syslog
Token check
  ↓  (B)
Body read / parse / dedup / capacity / job saved   → HTTP 200 "queued"
  ↓  (C) background task
Normalize
  ↓  (D)
Threat-intel lookup (mock by default)
  ↓  (E)
Rule-based risk level
  ↓  (F)
AI text generation (masked input, pinned risk)
  ↓  (G)
Automated validation
  ↓  (H)
Compose emails (client + C-Three + internal + engineer, together)
  ↓  (I)
Result file + outbox
  ↓  (J)
Handoff to mail worker (if delivery enabled) → retries → dead letter
  ↓  (K)  ← outside the repository
Client inbox
```

**Step A: ESET → platform**
- Claim: ESET sends alerts to the platform.
- File / function: [webhook.py:324](src/api/webhook.py#L324) `receive_eset_webhook`; [syslog_runtime.py:172-279](src/services/syslog_runtime.py#L172-L279)
- Called by: ESET (external) / UDP/TCP peer
- Calls: `validate_eset_token`, `ingest_alert`
- Evidence: route exists; 20 synthetic `webhook_received` log events
- Status: receiver PROVEN BY CODE; ESET sending: **NOT PROVEN FROM REPOSITORY**
- Not proven: ESET's request format, auth header support, retry behaviour, field names

**Step B: Token check**
- File / function: [auth.py:14-49](src/middleware/auth.py#L14-L49) `validate_eset_token`
- Called by: FastAPI dependency on both ingest routes
- Calls: `auth_limiter`, `hmac.compare_digest`
- Evidence: code + `test_security.py`
- Status: PROVEN BY CODE
- Not proven: the production token value; syslog listeners have no token (allowlist only, blank by default)

**Step C: Receipt, dedup, persistence**
- File / function: [webhook.py:172-321](src/api/webhook.py#L172-L321) `read_json_body`, `ingest_alert`; [deduplication.py](src/storage/deduplication.py); [job_store.py:10](src/storage/job_store.py#L10)
- Called by: B
- Calls: `run_pipeline_task` via BackgroundTasks
- Evidence: code + tests + probe 1
- Status: PROVEN BY CODE
- Not proven: multi-process dedup. Known gap: dedup key recorded before the job row

**Step D: Normalize**
- File / function: [normalizer.py:92-122](src/services/normalizer.py#L92-L122)
- Called by: [orchestrator.py:109](src/pipeline/orchestrator.py#L109)
- Evidence: code + `test_normalizer.py`
- Status: PROVEN BY CODE (synthetic inputs)
- Not proven: that real ESET field names and values map correctly

**Step E: Threat intel**
- File / function: [aggregator.py:11-56](src/services/threat_intel/aggregator.py#L11-L56)
- Called by: [orchestrator.py:117](src/pipeline/orchestrator.py#L117)
- Calls: VirusTotal/AbuseIPDB `query` → mock (default) or `_query_real`
- Evidence: code; 0 real calls in log
- Status: **CONFIG-DEPENDENT; default = simulated and ignored by risk**
- Not proven: any live API exchange. Domains never queried

**Step F: Risk**
- File / function: [risk_engine.py:194-270](src/services/risk_engine.py#L194-L270) `assess_risk`
- Called by: [orchestrator.py:135](src/pipeline/orchestrator.py#L135)
- Calls: `observation_store.record_and_count`
- Evidence: code + 24 unit tests + PoC cases
- Status: PROVEN BY CODE
- Not proven: client approval of the rules; real ESET vocabulary for severity/handled/outbreak

**Step G: AI**
- File / function: [base.py:293-459](src/services/ai/base.py#L293-L459) `generate`; [openai_provider.py:156-188](src/services/ai/openai_provider.py#L156-L188)
- Called by: [orchestrator.py:168-169](src/pipeline/orchestrator.py#L168-L169)
- Calls: `prompt_masking`, OpenAI SDK
- Evidence: code; FakeProvider tests
- Status: PROVEN ONLY BY TEST/MOCK
- Not proven: any successful real OpenAI generation (local model is unset)

**Step H: Validation**
- File / function: [output_validator.py:32-61](src/services/ai/output_validator.py#L32-L61), [lint_checker.py](src/services/ai/lint_checker.py)
- Called by: [orchestrator.py:195](src/pipeline/orchestrator.py#L195)
- Evidence: code + tests
- Status: PROVEN BY CODE
- Not proven: semantic accuracy; there is no human review

**Step I: Compose**
- File / function: [email_composer.py:178-219](src/services/email_composer.py#L178-L219)
- Called by: [orchestrator.py:233](src/pipeline/orchestrator.py#L233)
- Evidence: code + tests + probe 3
- Status: PROVEN BY CODE
- Not proven: production recipient configuration (all default blank)

**Step J: Persist + queue**
- File / function: [output_writer.py:26](src/services/output_writer.py#L26); [email_outbox.py:52-82](src/services/email_outbox.py#L52-L82)
- Called by: [orchestrator.py:234-235](src/pipeline/orchestrator.py#L234-L235)
- Calls: `dispatch_soon`
- Status: PROVEN BY CODE
- Not proven: n/a (internal)

**Step K: Handoff**
- File / function: [email_dispatcher.py:58-185](src/services/email_dispatcher.py#L58-L185); [eset_mail.py:294-445](src/services/email_delivery/eset_mail.py#L294-L445)
- Called by: `dispatch_soon`, `run_dispatch_loop`, dashboard `POST /delivery/dispatch`
- Calls: Mail worker HTTP
- Evidence: code; 67 local accepted handoffs; **no dispatcher tests**
- Status: handoff PROVEN locally; **CONFIG-DEPENDENT** (default disabled; AWS template doesn't enable it)
- Not proven: inbox delivery; retry/dead-letter behaviour under test

**Client inbox**
- Status: **NOT PROVEN FROM REPOSITORY.** The mail service owns delivery after it returns 202.

---

## PART 19 — Client document verification

### 1. ESET detects an alert
- **Claim:** ESET detects an alert and it enters the system.
- **Code evidence:** receiver at [webhook.py:324](src/api/webhook.py#L324) / syslog [syslog_runtime.py](src/services/syslog_runtime.py). No ESET-side code or evidence.
- **Verdict:** 🌐 REQUIRES LIVE EXTERNAL VALIDATION
- **Correct client wording:** "When ESET PROTECT raises an alert and is configured to forward it to our platform (by webhook or syslog), our platform receives it. *Connection to your ESET tenant has not yet been tested.*"

### 2. Alert is securely received
- **Code evidence:** [auth.py:14-49](src/middleware/auth.py#L14-L49); [webhook.py:172-321](src/api/webhook.py#L172-L321); dedup [deduplication.py](src/storage/deduplication.py); job row [job_store.py:10](src/storage/job_store.py#L10)
- **Verdict:** ⚠️ PARTIALLY PROVEN. The webhook token check is proven. TLS depends on deployment. The syslog path has no token. Some failures can lose an alert (§14.2).
- **Correct client wording:** "Webhook alerts must carry a secret access token; requests without it are rejected. Accepted alerts receive a tracking ID and are saved before analysis begins. Repeat submissions of the same alert within one hour are discarded."

### 3. Alert information is organized
- **Code evidence:** [normalizer.py:92-122](src/services/normalizer.py#L92-L122)
- **Verdict:** ✅ PROVEN for synthetic input; 🌐 field mapping for real ESET data is unverified
- **Correct client wording:** "Key facts (what was detected, on which device, ESET's severity rating, and whether ESET handled it) are extracted into a standard format. Anything missing is marked 'unknown' rather than guessed."

### 4. Additional threat information is checked
- **Code evidence:** [aggregator.py](src/services/threat_intel/aggregator.py), [virustotal.py](src/services/threat_intel/virustotal.py), [abuseipdb.py](src/services/threat_intel/abuseipdb.py); default mock [config.py:166](src/config.py#L166); ignored by risk while mock [orchestrator.py:136](src/pipeline/orchestrator.py#L136)
- **Verdict:** 🔧 CONFIGURATION-DEPENDENT; 🧪 TEST-ONLY / MOCKED in every run on record. Domain checking ❌ NOT IMPLEMENTED
- **Correct client wording:** "The platform can check a file hash, URL or IP address from the alert against VirusTotal and AbuseIPDB; a malicious or suspicious result can raise the risk level. *This lookup is not yet enabled.*" (Or remove the step until it is enabled.)

### 5. Risk level is determined by fixed rules
- **Code evidence:** [risk_engine.py:194-270](src/services/risk_engine.py#L194-L270); AI cannot override it ([output_validator.py:36-40](src/services/ai/output_validator.py#L36-L40))
- **Verdict:** ✅ PROVEN (implementation). The rule table is **not yet approved** (docstring :25-26)
- **Correct client wording:** "The risk level (LOW, MEDIUM, HIGH, CRITICAL) is set by a fixed set of rules, never by the AI. The rules consider ESET's severity, whether the threat was handled or the device isolated, whether the device is a server, ransomware or outbreak indicators, and the same detection on 3 or more devices within an hour. Once a level is set by ESET's severity and handling status, later rules can only raise it. *This rule table is a proposal for your approval.*"

### 6. AI prepares the notification
- **Code evidence:** [base.py:293-459](src/services/ai/base.py#L293-L459), [openai_provider.py](src/services/ai/openai_provider.py), masking [prompt_masking.py](src/services/ai/prompt_masking.py)
- **Verdict:** 🧪 TEST-ONLY / MOCKED; 🌐 REQUIRES LIVE EXTERNAL VALIDATION (no successful OpenAI run on record)
- **Correct client wording:** "An AI service (OpenAI) drafts the wording of the notifications. Before data is sent to it, usernames, email mailboxes and internal ESET identifiers are masked. Device names, IP addresses, URLs, domains and file hashes are sent because they are needed for the analysis."

### 7. Notification is automatically checked
- **Code evidence:** [output_validator.py:32-61](src/services/ai/output_validator.py#L32-L61), [lint_checker.py](src/services/ai/lint_checker.py), [orchestrator.py:193-207](src/pipeline/orchestrator.py#L193-L207)
- **Verdict:** ✅ PROVEN (automated checks exist and block sending). ⚠️ The checks are rule-based, and **no person reviews the text before the client email is sent**
- **Correct client wording:** "The AI's draft is automatically checked: it is blocked if it changes the risk level, leaves a required section empty, or contains wording we prohibit (for example 'infection confirmed' or 'the environment is safe'). If it is blocked or the AI fails, the alert is still recorded, you are not sent an AI-written email, and our team is notified to follow up manually."

### 8. Emails are prepared
- **Code evidence:** [email_composer.py:109-219](src/services/email_composer.py#L109-L219)
- **Verdict:** ✅ PROVEN. ❌ Any implication that C-Three approves first is NOT PROVEN (it is contradicted by the code)
- **Correct client wording:** "Up to four emails are prepared: your notification (Japanese), a copy for C-Three Index including the reasoning and open questions, an internal summary, and an English technical summary for engineers. *Your notification and C-Three's copy are sent at the same time; C-Three's copy is for information and follow-up, not prior approval.*"

### 9. Email is delivered
- **Code evidence:** [email_dispatcher.py](src/services/email_dispatcher.py), [eset_mail.py](src/services/email_delivery/eset_mail.py); default disabled [config.py:197](src/config.py#L197)
- **Verdict:** 🔧 CONFIGURATION-DEPENDENT; handoff only ✅; inbox delivery ❌ NOT PROVEN
- **Correct client wording:** "The emails are handed to our mail service, which confirms receipt of each one. If the handoff fails, it is retried automatically (by default up to 3 attempts over about two minutes); emails that still cannot be handed off are kept in a failed-email list for manual follow-up. Final delivery to the inbox is handled by the mail service."

---

## PART 20 — Red flags in the client draft

| Phrase / claim | Verdict | Why |
|---|---|---|
| "automatically" (sends) | **PARTIALLY PROVEN** | Processing is automatic. Sending only when `EMAIL_DELIVERY_ENABLED=true` (default false; not set in the AWS template) and recipients are configured (default blank) |
| "securely" | **PARTIALLY PROVEN** | Webhook token proven. TLS depends on deployment. The syslog path is unauthenticated unless the allowlist is set. No payload signature |
| "within seconds" / "a minute or two" | **NOT PROVEN** | NOT MEASURED. The only data is 19 synthetic local runs |
| "none can be lost" | **NOT PROVEN (contradicted)** | Loss paths I1-I3, P1, E1-E6; two confirmed by execution |
| "same alert always gets the same level" | **PARTIALLY PROVEN** | Deterministic per input, but the outcome depends on platform history, live intel (if on) and tunable thresholds |
| "CRITICAL when 3+ machines within an hour" | **PROVEN** (code, configurable default) | Needs detection and endpoint names to be present; counts only non-duplicate alerts seen by this platform, or guessed payload count keys |
| "AI does not decide the risk level" | **PROVEN** | Schema pin plus a validator hard-check |
| "personal data is masked" | **PARTIALLY PROVEN** | Usernames, email mailboxes and IDs are masked. Hostnames, IPs, URLs, domains, Unix home paths and names in free text are not. The mechanism can be switched off. The policy is not signed off |
| "no unchecked text is ever sent" | **PARTIALLY PROVEN** | AI text passes rule-based checks. No human review. Fallback templates are not validated (internal recipients only) |
| "C-Three review" | **PARTIALLY PROVEN** | C-Three receives a review-style copy |
| "C-Three approval" | **NOT PROVEN (contradicted)** | Sent in parallel with the client email; no gate exists (probe 3; `OPENAI_INTEGRATION.md:457` open item) |
| "retry every minute" | **PARTIALLY PROVEN** | Sweeper every 60 s by default; the actual gap is ≤60 s; there is no per-email timer. No tests |
| "3 attempts" | **PROVEN BY CODE** (default) | 3 total attempts including the first. No tests |
| "failed-email queue" | **PROVEN BY CODE** | `dead_letter.json` + dashboard list; manual replay only; write failure is swallowed (E4). No tests |
| "email is delivered" | **NOT PROVEN** | Only the mail-service handoff is proven |
| "production ESET validation" | **NOT PROVEN — LIVE VALIDATION REQUIRED** | Zero real ESET payloads |
| "file hashes, IP addresses or domains are checked" | **NOT PROVEN / partly NOT IMPLEMENTED** | Mock by default, 0 real calls, domains never queried, one indicator per alert to VirusTotal |

### Highest-impact items to resolve before sharing any client flow

1. Get a real ESET test webhook (and/or syslog export) into the platform and keep the raw payload.
2. Decide whether the client email waits for C-Three approval. Today it does not.
3. Enable and verify real threat intel, or remove that step from the client flow. Note that API keys must be real environment variables or come from the Secrets Manager overlay; a `.env` line is ignored.
4. Set `EMAIL_DELIVERY_ENABLED=true` and the recipients in the actual deployment (the AWS template omits both), and set `OPENAI_MODEL`.
5. Fix ingest-time loss path I1 (record the dedup key only after the job row is saved) and notify the team on pre-AI `FAILED` jobs (P1).
6. Add tests for `email_dispatcher` (attempt counting, sweep, dead-lettering).
7. Measure end-to-end latency on the deployed stack before quoting any timing.
