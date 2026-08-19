# ESET SOC Lite — Personal Training Manual

*A from-first-principles audit of this repository, written so you can work on it as if you wrote it yourself. Every claim below is backed by a file and line you can go re-read. Where something could not be verified from the code, it's marked `UNKNOWN`.*

---

## Table of Contents

1. [What This Project Actually Is](#1-what-this-project-actually-is)
2. [Repository Map](#2-repository-map)
3. [Architecture](#3-architecture)
4. [Real User / Data Flows](#4-real-user--data-flows)
5. [Frontend Deep Dive](#5-frontend-deep-dive)
6. [Backend Deep Dive](#6-backend-deep-dive)
7. [API Documentation](#7-api-documentation)
8. [Database Deep Dive](#8-database-deep-dive)
9. [Authentication + Authorization](#9-authentication--authorization)
10. [Environment Variables + Configuration](#10-environment-variables--configuration)
11. [Dependencies](#11-dependencies)
12. [Error Handling](#12-error-handling)
13. [Security Audit](#13-security-audit)
14. [Testing](#14-testing)
15. [Build + Running the Application](#15-build--running-the-application)
16. [Deployment](#16-deployment)
17. [Git + Branching](#17-git--branching)
18. [Feature-to-File Map](#18-feature-to-file-map)
19. [Change Impact Guide](#19-change-impact-guide)
20. [Debugging Playbook](#20-debugging-playbook)
21. [Follow the Data](#21-follow-the-data)
22. [Important Functions](#22-important-functions)
23. [Critical Files (Tiers)](#23-critical-files-tiers)
24. [Architectural Decisions](#24-architectural-decisions)
25. [Technical Debt](#25-technical-debt)
26. [Red Flags — Things You Must Not Break](#26-red-flags--things-you-must-not-break)
27. [My Mental Model](#27-my-mental-model)
28. [Study Roadmap](#28-study-roadmap)
29. [Final Checklist](#29-final-checklist)

---

## 1. What This Project Actually Is

**In one sentence:** this is a small, single-process backend service that receives raw security-alert data from an antivirus/EDR platform (**ESET PROTECT Cloud**), figures out how dangerous each alert is, enriches it with reputation data, asks an AI model to write four different human-readable reports about it in two languages, and queues those reports as outbound emails — while a built-in live web dashboard lets a human watch and control the whole thing.

### Who uses it and why

- **ESET PROTECT Cloud** (an external product, not part of this repo) is configured to send alert data to this service, either as an HTTP webhook or as syslog messages.
- **SOC (Security Operations Center) analysts / engineers** use the live dashboard (`static/dashboard.html`, served at `/`) to watch alerts arrive, inspect what the AI wrote about them, manage who gets notified, retry failures, and read application logs — all without SSH-ing into the box or reading raw JSON files.
- **Downstream humans** — a client, a front-office partner ("C-Three Index"), an internal SOC team, and an engineering team — each receive a differently-worded notification email about the same alert, in the language and tone appropriate to their role (three are Japanese, one is English).
- **A separate service** ("ESET Mail", a Cloudflare Worker this repo does *not* contain — see `src/services/email_delivery/eset_mail.py`) actually sends the emails over SMTP; this repo only *hands off* composed emails to it.

### The problem it solves

Raw antivirus alerts are messy, inconsistent JSON blobs meant for machines. A human SOC team needs: (1) a *consistent* judgment of how serious each alert is, (2) outside opinions from threat-intelligence services about any file hash / IP / URL involved, and (3) a *readable, bilingual, factually-conservative* explanation to hand to different audiences — without an engineer manually triaging and writing four emails per alert, 24/7. This service automates all of that while being paranoid about **never inventing facts** the AI wasn't given (see the system prompt in `src/prompts/system_prompts.py` and the safety lint in `src/services/ai/lint_checker.py`).

### What happens from the moment the application starts

`run.py` boots one Uvicorn process running the FastAPI app defined in `src/main.py`. On startup (`src/main.py`'s `lifespan()` function):

1. Structured logging is configured (`src/utils/logging.py`).
2. The SQLite database schema is created if missing (`src/storage/database.py: init_db()`).
3. Syslog UDP (port 514) and TCP (port 601) listeners are started *inside this same process* (`src/services/syslog_runtime.py: start()`).
4. Any jobs left `PENDING`/`PROCESSING` from a crash are re-queued (`recover_unfinished_jobs()` in `src/main.py`).
5. A background loop starts that periodically retries any emails that failed to hand off to the mail service (`src/services/email_dispatcher.py: run_dispatch_loop()`).
6. The dashboard's static files are mounted at `/static`, and `/` serves `static/dashboard.html`.

From that point the server accepts:
- `POST /webhook/eset` and `POST /webhook/syslog` (HTTP alert ingestion)
- Raw syslog packets on UDP/TCP (alert ingestion over syslog protocol)
- Dashboard API calls under `/dashboard/api/*` and a WebSocket at `/dashboard/api/ws`
- `GET /health`, `GET /status/{correlation_id}`

### Major subsystems and how they talk to each other

```
┌────────────────────┐        ┌──────────────────────┐
│ ESET PROTECT Cloud  │──HTTP─▶│  Webhook ingest API   │
│ (external, not in   │──UDP──▶│  Syslog listener       │  (src/api/webhook.py,
│  this repo)         │──TCP──▶│  (embedded in same     │   src/ingestion/*,
└────────────────────┘        │   asyncio process)     │   src/services/syslog_runtime.py)
                                └──────────┬─────────────┘
                                           │ background task
                                           ▼
                                ┌──────────────────────┐
                                │ Pipeline Orchestrator  │  src/pipeline/orchestrator.py
                                │ normalize→risk→intel→  │
                                │ AI→lint→write→email    │
                                └───┬─────────┬──────────┘
                                    │         │
                     ┌──────────────┘         └───────────────┐
                     ▼                                          ▼
        ┌─────────────────────────┐                 ┌──────────────────────┐
        │ SQLite (jobs, dedup,     │                 │ JSON files on disk    │
        │ settings, email history) │                 │ output/alerts/*.json  │
        │ src/storage/*.py         │                 │ output/emails/outbox  │
        └─────────────────────────┘                 └──────────┬────────────┘
                     ▲                                          │
                     │ read/write                    hand off (HTTP + HMAC)
                     │                                          ▼
        ┌─────────────────────────┐                 ┌──────────────────────┐
        │ Live Dashboard (browser) │◀───WebSocket────│ ESET Mail worker      │
        │ static/dashboard.html/js │   events         │ (external Cloudflare  │
        │ + dashboard-viz.js       │───REST──────────▶│  Worker, not in repo) │
        └─────────────────────────┘   /dashboard/api  └──────────────────────┘
```

**Plain-language version:** an alert comes in one of two doors (webhook or syslog). It goes through a straight-line assembly line (the "pipeline") that cleans it up, scores its risk with fixed rules (not AI), asks two reputation-check websites about any file/IP/URL, asks Google's Gemini AI to write four reports about it, double-checks the AI didn't say anything it shouldn't, saves the whole result as a JSON file, and queues up to four emails. The whole time, a live webpage is watching over a WebSocket connection and updating in real time so a human can see it happen.

---

## 2. Repository Map

```
ESET-SoC/
├── run.py                     # Single entrypoint: `python run.py` starts everything
├── pyproject.toml             # Python project + dependency manifest (pip/setuptools)
├── supervisord.conf           # Optional process supervisor config (alternative to run.py)
├── .env.example                # Template for the real .env (never commit .env itself)
├── .gitignore
├── README.md                   # Operator-facing docs (very good — read it first)
├── ESET_SOC_Lite_Client_Status_and_PoC_Considerations_EN.docx   # Non-code business doc; excluded from audit (see below)
│
├── src/                        # ALL backend Python source
│   ├── main.py                 # FastAPI app object, lifespan startup/shutdown, static mount
│   ├── config.py                # Settings — the ONE place all env vars are declared/typed
│   │
│   ├── api/                    # HTTP route handlers ("controllers")
│   │   ├── router.py            # Aggregates all sub-routers into api_router
│   │   ├── webhook.py            # POST /webhook/eset, POST /webhook/syslog (ingest)
│   │   ├── health.py             # GET /health
│   │   ├── status.py             # GET /status/{correlation_id}
│   │   └── dashboard.py          # Everything under /dashboard/api/* + the WebSocket
│   │
│   ├── middleware/
│   │   └── auth.py               # validate_eset_token() — webhook bearer-token check
│   │
│   ├── ingestion/               # Turns raw external JSON into a common Pydantic shape
│   │   ├── base.py                # BaseIngestionHandler abstract class
│   │   ├── webhook_handler.py     # WebhookIngestionHandler
│   │   └── syslog_handler.py      # SyslogIngestionHandler (different key names)
│   │
│   ├── models/                  # Pydantic data contracts (the "shapes" of data in this app)
│   │   ├── raw_payload.py         # EsetRawPayload — lenient, everything optional
│   │   ├── normalized_alert.py    # NormalizedAlert — strict, "UNKNOWN" instead of missing
│   │   ├── threat_intel.py         # VirusTotalResult, AbuseIPDBResult, ThreatIntelResult
│   │   ├── ai_output.py            # AIOutput + 4 notification sub-schemas
│   │   ├── email_message.py        # EmailMessage — one queued outbound email
│   │   ├── pipeline_result.py      # PipelineResult — the final JSON written to disk
│   │   └── __init__.py             # Re-exports all of the above
│   │
│   ├── pipeline/
│   │   └── orchestrator.py         # process_alert_pipeline() — THE central function
│   │
│   ├── services/                 # Business logic ("the actual work")
│   │   ├── normalizer.py           # raw → NormalizedAlert
│   │   ├── risk_engine.py          # NormalizedAlert → (risk_level, rationale) — pure rules
│   │   ├── output_writer.py        # Writes PipelineResult JSON + index.json atomically
│   │   ├── email_composer.py       # PipelineResult → list[EmailMessage]
│   │   ├── email_outbox.py         # Pending-email JSON file persistence (output/emails/outbox.json)
│   │   ├── email_dispatcher.py     # Hands outbox emails to the mail provider, retries
│   │   ├── syslog_runtime.py       # Embeds UDP/TCP syslog listeners in this asyncio process
│   │   ├── ai/
│   │   │   ├── base.py               # BaseAIProvider abstract class
│   │   │   ├── gemini_service.py     # GeminiAIService — calls Google Gemini
│   │   │   ├── schema_builder.py     # Pydantic → Gemini-safe JSON schema (see docstring!)
│   │   │   └── lint_checker.py       # Blocks AI output containing forbidden claims
│   │   ├── threat_intel/
│   │   │   ├── base.py               # BaseThreatIntelProvider abstract class
│   │   │   ├── aggregator.py         # gather_threat_intel() — parallel, timeout-safe
│   │   │   ├── virustotal.py         # VirusTotalProvider (mock + real modes)
│   │   │   └── abuseipdb.py          # AbuseIPDBProvider (mock + real modes)
│   │   └── email_delivery/
│   │       ├── base.py               # EmailDeliveryProvider interface + DeliveryResult
│   │       ├── eset_mail.py          # EsetMailProvider — the concrete HTTP+HMAC transport
│   │       └── __init__.py           # get_provider() factory
│   │
│   ├── storage/                  # All persistence (SQLite)
│   │   ├── database.py             # db_session(), init_db() — schema DDL lives here
│   │   ├── job_store.py            # jobs table CRUD (the alert-processing job queue)
│   │   ├── deduplication.py        # dedup_log table (duplicate-alert suppression)
│   │   ├── settings_store.py       # app_settings table (dashboard-editable recipients)
│   │   └── delivery_store.py       # email_deliveries table (email handoff history)
│   │
│   ├── prompts/
│   │   └── system_prompts.py       # SYSTEM_PROMPT sent to Gemini — the AI's "rules"
│   │
│   └── utils/                    # Small cross-cutting helpers
│       ├── correlation.py          # generate/set/get correlation_id (request tracing)
│       ├── logging.py              # setup_logging() — structlog + console/file handlers
│       ├── retry.py                # retry_api_call() — tenacity decorator factory
│       ├── broadcaster.py          # EventBroadcaster — WebSocket fan-out
│       └── events.py               # emit()/emit_stage() — shared pub/sub used everywhere
│
├── syslog_server/
│   └── server.py                  # Standalone syslog process (legacy path — see §24)
│
├── static/                       # THE ENTIRE FRONTEND — plain HTML/CSS/JS, no framework
│   ├── dashboard.html              # Markup + all CSS (inline <style>)
│   ├── dashboard.js                 # App state, routing, API calls, WebSocket handling
│   └── dashboard-viz.js             # Hand-rolled SVG: pipeline flow graph + charts
│
├── scripts/                      # Manual testing helpers, not used by the app itself
│   ├── send_test_syslog.py          # Fires one fake alert at the UDP/TCP syslog listener
│   └── send_test_webhook.sh         # Fires low/medium/high/critical alerts at the webhook
│
└── tests/                        # Pytest suite
    ├── conftest.py                  # Shared fixtures: temp DB/output dirs, mocked Gemini
    ├── fixtures/*.json               # Sample alert payloads for manual/automated use
    ├── unit/                         # Pure-function tests (no HTTP, no DB unless noted)
    └── integration/                  # Full FastAPI TestClient tests (HTTP + DB + files)
```

### Directories NOT documented in depth, and why

| Path | Why excluded |
|---|---|
| `.venv/`, `__pycache__/`, `*.egg-info/` | Generated by Python tooling; never edited by hand; irrelevant to behavior. |
| `data/`, `logs/`, `output/` | **Not checked into git** (see `.gitignore`) — these are runtime-created directories: `data/soc_lite.db` (SQLite file), `logs/app.log`, `output/alerts/*.json`, `output/emails/outbox.json`. They exist only after you run the app. Their *shape* is documented in §8 and §21 because understanding what lives in them is essential; the directories themselves aren't part of the source tree. |
| `ESET_SOC_Lite_Client_Status_and_PoC_Considerations_EN.docx` | A binary Word document (business/status write-up for a client), not source code. Not parsed as part of this audit — it does not affect application behavior. |
| `plans/` | Listed in `.gitignore` as a user-exclusion; does not exist in the working tree at audit time. |

### What would break if a directory were changed

- **`src/models/`** — this is the contract every other layer depends on. Renaming a field here cascades into `src/services/normalizer.py`, `src/pipeline/orchestrator.py`, `src/prompts/system_prompts.py` (implicitly, since the prompt describes fields by name), `static/dashboard.js` (renders these fields), and every test fixture.
- **`src/storage/`** — the SQL schema (`database.py`) is the single source of truth for the `jobs`, `dedup_log`, `app_settings`, `email_deliveries` tables. Every other `storage/*.py` module assumes those `CREATE TABLE` statements ran first via `init_db()`.
- **`static/`** — there is no build step. Whatever bytes are in `dashboard.html`/`dashboard.js`/`dashboard-viz.js` are served *exactly as-is* by `StaticFiles` in `src/main.py`. Editing them takes effect on next browser refresh, no compile/restart needed (the Python server does need a restart for *backend* changes, but not for static file edits — though FastAPI's `--reload` isn't configured in `run.py`, so even backend changes need a manual restart).

---

## 3. Architecture

This is **not** a classic "frontend talks to backend talks to database" three-tier web app in the Node/React sense — there is no separate frontend server, no ORM, and the "database" is a hybrid of SQLite (for queue/job state) and flat JSON files (for the actual alert content). Here is the architecture as it actually exists in the code:

```
 EXTERNAL: ESET PROTECT Cloud
      │
      ├─ POST JSON ──────────────────────────────┐
      │                                            │
      └─ syslog UDP/TCP (RFC 5424 + JSON) ──┐      │
                                              ▼      ▼
                              ┌───────────────────────────────────┐
                              │ src/services/syslog_runtime.py     │  UDP/TCP listeners
                              │  UDPProtocol.datagram_received()   │  embedded in the SAME
                              │  handle_tcp_client()               │  asyncio event loop as
                              │  → forward_to_api()  (loopback     │  the FastAPI server
                              │    HTTP POST to /webhook/syslog)   │
                              └───────────────┬─────────────────────┘
                                               │
                          ┌────────────────────┴─────────────────────┐
                          ▼                                          ▼
              POST /webhook/eset                          POST /webhook/syslog
              src/api/webhook.py                            src/api/webhook.py
                          │                                          │
                          ▼  Depends(validate_eset_token)             ▼
              src/middleware/auth.py  ── 401 if bearer token wrong ──┘
                          │
                          ▼
              ingest_alert()  in src/api/webhook.py
                  1. handler.parse()      → src/ingestion/{webhook,syslog}_handler.py
                  2. compute_dedup_key()  → src/storage/deduplication.py (is_duplicate?)
                  3. job_store.create_job()  → SQLite `jobs` table, status=PENDING
                  4. background_tasks.add_task(run_pipeline_task, ...)
                          │ returns {"status":"queued","correlation_id":...} IMMEDIATELY
                          │ (HTTP response does not wait for the pipeline)
                          ▼
              run_pipeline_task()  (src/api/webhook.py, runs in FastAPI's background)
                          ▼
              process_alert_pipeline()   src/pipeline/orchestrator.py  ◀── the heart of the app
                 ┌─────────────────────────────────────────────────────────┐
                 │ 1. job_store.update_job_status(PROCESSING)                │
                 │ 2. normalizer.normalize()        → NormalizedAlert        │
                 │ 3. risk_engine.compute_risk()     → (risk_level, why)      │  pure rules, no AI
                 │ 4. threat_intel.aggregator.gather_threat_intel()           │  parallel, timeout-safe
                 │      → VirusTotalProvider.query(), AbuseIPDBProvider.query()│
                 │ 5. GeminiAIService.generate()      → AIOutput               │  Google Gemini API
                 │ 6. lint_checker.lint_ai_output()   → raises if unsafe claim │
                 │ 7. output_writer.write_result()    → output/alerts/<id>.json│
                 │ 8. email_composer.compose_emails() → list[EmailMessage]     │
                 │ 9. email_outbox.add_emails()        → output/emails/outbox.json
                 │10. email_dispatcher.dispatch_soon() → hands off to ESET Mail│
                 │      (fire-and-forget asyncio task, doesn't block pipeline)│
                 │11. job_store.update_job_status(SUCCESS / PARTIAL / FAILED) │
                 └─────────────────────────────────────────────────────────┘
                          │  every step also calls events.emit_stage(...)
                          ▼
              src/utils/events.py → src/utils/broadcaster.py (EventBroadcaster)
                          │  fan-out over all connected WebSocket clients
                          ▼
              Browser: static/dashboard.js `ws.onmessage` → handleEvent()
                          │  updates in-memory `state` object
                          ▼
              static/dashboard-viz.js renders the live flow graph / charts
              static/dashboard.js re-renders tables (Alerts, AI Content, Emails)
```

### Step-by-step explanation of every layer

1. **Ingress (two doors, one destination).** Both the HTTP webhook and the syslog listeners ultimately produce the exact same background pipeline call. The syslog listener doesn't process alerts itself — it just extracts embedded JSON from the syslog frame and re-POSTs it to `/webhook/syslog` over `127.0.0.1` (see `forward_to_api()` in `src/services/syslog_runtime.py`). This means **the webhook route is the single real ingestion chokepoint** — everything funnels through `ingest_alert()` in `src/api/webhook.py`.

2. **Auth middleware.** `validate_eset_token` (a FastAPI `Depends`) runs before the route body executes. It is not global middleware — it is attached per-route via `dependencies=[Depends(validate_eset_token)]` on the two webhook routes only. The dashboard uses a *separate* mechanism (`_check_access()` in `src/api/dashboard.py`).

3. **Deduplication happens before a job is even created.** `compute_dedup_key()` builds a key from `alert_id:occurred_at` (or a SHA-256 hash of the whole payload if those are missing) and checks it against the `dedup_log` SQLite table. A duplicate short-circuits with `{"status": "duplicate"}` and never touches the pipeline.

4. **The HTTP response returns before processing finishes.** `ingest_alert()` returns `{"status": "queued", "correlation_id": ...}` synchronously, but the actual work is scheduled via FastAPI's `BackgroundTasks.add_task(run_pipeline_task, ...)`, which runs *after* the response is sent, in the same process/event loop.

5. **The Orchestrator (`process_alert_pipeline`) is a straight-line, all-or-nothing state machine with three possible terminal outcomes**: `SUCCESS` (everything worked), `PARTIAL` (normalize/risk/intel worked but AI generation or linting failed — so there's a risk score but no email content), or `FAILED` (normalization itself blew up). Every path writes a result file — **no alert is ever silently dropped**, which is a deliberate design property called out in the orchestrator's docstring.

6. **Threat intel runs in parallel with a hard timeout**, using `asyncio.gather()` plus `asyncio.wait_for()` per-provider (`src/services/threat_intel/aggregator.py`). A slow or dead threat-intel API degrades to `UNKNOWN` rather than blocking the whole alert.

7. **The AI step is the most failure-prone** and is wrapped in its own nested `try/except` inside the orchestrator specifically so an AI outage/schema mismatch downgrades the result to `PARTIAL` instead of `FAILED` — risk score and threat intel are still valuable even without AI commentary.

8. **Email composition only happens on SUCCESS**, because `email_composer.compose_emails()` immediately returns `[]` if `result.ai_output is None` — `PARTIAL`/`FAILED` runs never generate emails (there's no AI content to send).

9. **The dashboard is a second, independent consumer of the same events.** It never triggers a pipeline run itself except through the *same* `ingest_alert()`/`run_pipeline_task()` machinery (see the "Retry" button, which calls `POST /dashboard/api/jobs/{id}/retry`, which re-invokes `run_pipeline_task` directly).

10. **State fan-out is push-based, not polled**, via `EventBroadcaster` (`src/utils/broadcaster.py`) — a plain in-memory `set` of connected `WebSocket` objects. `src/utils/events.py` provides the process-wide `emit()`/`emit_stage()` functions that every layer (job_store, output_writer, email_outbox, email_dispatcher, orchestrator) calls into, so the dashboard sees state changes the instant they happen, not on a polling interval (though the dashboard does have a few polling-based `setInterval` refreshes as a fallback, e.g. `renderAlerts` every 15s for relative timestamps).

---

## 4. Real User / Data Flows

### Flow 1 — Ingest a HIGH severity alert end-to-end (the core flow)

```
curl POST /webhook/eset  (Authorization: Bearer <token>)
    ↓
src/api/webhook.py: receive_eset_webhook()
    ↓ Depends(validate_eset_token)  →  src/middleware/auth.py
    ↓ raw_json = await request.json()
    ↓
ingest_alert(raw_json, webhook_handler, "WEBHOOK", background_tasks)
    ↓ webhook_handler.parse(raw_json)          src/ingestion/webhook_handler.py
    │     → EsetRawPayload(**data)              src/models/raw_payload.py
    ↓ compute_dedup_key(raw_payload)
    ↓ deduplication.is_duplicate(key)           src/storage/deduplication.py  (SQLite dedup_log)
    ↓ deduplication.record_seen(key, ttl)
    ↓ job_store.create_job(correlation_id, "WEBHOOK", payload_dict)   SQLite `jobs` table
    │     → events.emit("job_status_changed", {...status: PENDING...})   → WebSocket
    ↓ background_tasks.add_task(run_pipeline_task, correlation_id, payload_dict, "WEBHOOK")
    ↓
    HTTP 200 response: {"status": "queued", "correlation_id": "..."}     ← client gets this immediately
    ═══════════════════════ response sent; background work begins ═══════════════════════
    ↓
run_pipeline_task()  src/api/webhook.py
    ↓ set_correlation_id(...)     src/utils/correlation.py (binds to structlog + ContextVar)
    ↓ process_alert_pipeline(correlation_id, raw_payload, "WEBHOOK")   src/pipeline/orchestrator.py
        ↓ job_store.update_job_status(PROCESSING)
        ↓ events.emit_stage(..., "INGEST", "ok")
        ↓ alert = normalizer.normalize(EsetRawPayload(**raw_payload), "WEBHOOK")   src/services/normalizer.py
        ↓ events.emit_stage(..., "NORMALIZE", "ok")
        ↓ risk_level, risk_rationale = risk_engine.compute_risk(alert)   src/services/risk_engine.py
        ↓ events.emit_stage(..., "RISK", "ok", risk_level=...)
        ↓ intel = await threat_intel.aggregator.gather_threat_intel(alert)
        │     ↓ asyncio.gather(VirusTotalProvider.query(alert), AbuseIPDBProvider.query(alert))
        │       each wrapped in asyncio.wait_for(timeout=THREAT_INTEL_TIMEOUT_SECONDS)
        ↓ events.emit_stage(..., "INTEL", "ok")
        ↓ ai_output = await GeminiAIService().generate(alert, risk_level, intel)   src/services/ai/gemini_service.py
        │     ↓ builds prompt from alert+risk+intel, sends to gemini-3.1-flash-lite
        │     ↓ response_schema = build_gemini_schema(AIOutput)   src/services/ai/schema_builder.py
        │     ↓ retried up to 3x via @retry_api_call   src/utils/retry.py
        │     ↓ AIOutput.model_validate_json(raw_response)   src/models/ai_output.py
        ↓ events.emit_stage(..., "AI", "ok")
        ↓ lint_ai_output(ai_output)   src/services/ai/lint_checker.py  (raises LintFailureException if unsafe)
        ↓ events.emit_stage(..., "LINT", "ok")
        ↓ result = PipelineResult(...)   src/models/pipeline_result.py
        ↓ output_writer.write_result(result)   src/services/output_writer.py
        │     ↓ writes output/alerts/<correlation_id>.json  (atomic tempfile + os.replace)
        │     ↓ appends to output/alerts/index.json
        │     ↓ events.emit_stage(..., "OUTPUT", "ok")
        │     ↓ events.emit("alert_completed", result.model_dump())   → WebSocket
        ↓ emails = email_composer.compose_emails(result)   src/services/email_composer.py
        │     → for each of CLIENT_JA/CTHREE_JA/INTERNAL_JA/ENGINEER_EN with configured recipients,
        │       build an EmailMessage using settings_store.get_effective(field)
        ↓ email_outbox.add_emails(emails)   src/services/email_outbox.py
        │     ↓ appends to output/emails/outbox.json
        │     ↓ delivery_store.record_pending(message) for each   SQLite `email_deliveries` table
        │     ↓ events.emit("email_queued", message.model_dump())   → WebSocket
        ↓ events.emit_stage(..., "EMAIL", "ok")
        ↓ asyncio.create_task(email_dispatcher.dispatch_soon())    (fire-and-forget)
        │     ↓ email_dispatcher.dispatch_pending()   src/services/email_dispatcher.py
        │         ↓ for each queued email: provider.send(message)   src/services/email_delivery/eset_mail.py
        │             ↓ builds HMAC-signed HTTP request, POSTs to EMAIL_API_URL
        │             ↓ on 200/202 success: email_outbox.remove_email(), delivery_store.record_attempt(ACCEPTED)
        │             ↓ events.emit("email_accepted", {...})   → WebSocket
        │             ↓ events.emit_stage(..., "SEND", "ok")
        ↓ job_store.update_job_status(SUCCESS)
        │     → events.emit("job_status_changed", {...status: SUCCESS...})   → WebSocket
```

**On the browser side, simultaneously:**
```
static/dashboard.js: connectWs()  →  WebSocket to /dashboard/api/ws
    ↓ ws.onmessage → handleEvent(msg)
        "job_status_changed" → upsertJob() → renderAlerts()
        "pipeline_stage"      → applyStage() (dashboard-viz.js) → renderFlow() if Flow tab active
        "alert_completed"     → upsertJob() with risk_level → renderAlerts(); loadStats() if Overview active
        "email_queued"        → state.emails.unshift(d) → renderEmails()
        "email_accepted"      → remove from state.emails → renderEmails(); toast(...)
```

### Flow 2 — Duplicate alert suppression

```
Same alert_id + occurred_at sent twice within DEDUP_TTL_SECONDS (default 3600s)
    ↓
src/api/webhook.py: ingest_alert()
    ↓ compute_dedup_key() → same key both times
    ↓ deduplication.is_duplicate(key)  →  SELECT ... WHERE composite_key=? AND expires_at > now()
    ↓ TRUE on the second call
    ↓
returns {"status": "duplicate", "message": "Alert already processed", "correlation_id": <new_uuid>}
    (note: correlation_id is freshly generated even for the rejected duplicate — it is NOT the id of
     the original job, since no job_store lookup happens on the dup path)
    NOTHING is written to jobs table, NO pipeline runs, NO WebSocket event fires.
```

### Flow 3 — AI generation fails → PARTIAL result (graceful degradation)

```
process_alert_pipeline()
    ↓ normalize, risk, intel all succeed (as in Flow 1)
    ↓ ai_service.generate(alert, risk_level, intel)  raises (e.g. Gemini quota exceeded, timeout,
    │                                                          malformed JSON from the model)
    ↓ caught by the inner `except Exception as ai_error:` block in orchestrator.py
    ↓ events.emit_stage(..., "AI", "failed", detail=str(ai_error)[:200])
    ↓ result = PipelineResult(pipeline_status="PARTIAL", ai_output=None, error=f"AI generation failed: {ai_error}")
    ↓ output_writer.write_result(result)     ← still written! risk score + intel preserved
    ↓ events.emit_stage(..., "EMAIL", "skipped", detail="No AI content to send")
    ↓ job_store.update_job_status(PARTIAL, error=str(ai_error))
    ↓ NO emails are composed (email_composer.compose_emails only fires on the SUCCESS branch)
```
A human can later click **Retry** in the dashboard's Alerts tab (visible only for `FAILED`/`PARTIAL` rows), which calls `POST /dashboard/api/jobs/{id}/retry` → `src/api/dashboard.py: retry_job()` → re-runs `run_pipeline_task` with the *original stored* `raw_payload` from the `jobs` table.

### Flow 4 — Editing notification recipients from the dashboard (no restart)

```
User: Settings tab → types an email → clicks "Save recipients"
    ↓
static/dashboard.js: document.getElementById("saveRecipients").onclick
    ↓ api("/settings/recipients", {method:"PUT", body: JSON.stringify({...})})
    ↓
src/api/dashboard.py: update_recipients()
    ↓ _check_access(request)                          (X-Dashboard-Key header check)
    ↓ RecipientUpdate(**payload)  Pydantic validation
    ↓ settings_store.update_recipients(values)         src/storage/settings_store.py
    │     ↓ for each key: set_setting(key, value)  →  INSERT ... ON CONFLICT UPDATE  (SQLite app_settings)
    ↓ returns {"status": "saved", "updated": [...], "recipients": {...}}

Next alert's email_composer.compose_emails() call:
    ↓ settings_store.get_effective("client_notification_emails")
    ↓     → get_setting() finds a stored override → returns it (bypasses .env value entirely)
    ↓ if no override exists yet → falls back to `settings.client_notification_emails` (the .env value)
```
This is the one piece of "live config" in the whole app — everything else in `src/config.py` is read once at process start and never changes without a restart.

### Flow 5 — Startup crash recovery

```
Process crashes (or is killed) mid-pipeline, leaving a job stuck at PENDING or PROCESSING in SQLite.
    ↓
Next process start: src/main.py: lifespan()
    ↓ asyncio.create_task(recover_unfinished_jobs())
        ↓ job_store.get_unfinished_jobs()   SELECT * FROM jobs WHERE status IN ('PENDING','PROCESSING')
        ↓ for each: asyncio.create_task(run_pipeline_task(job["correlation_id"], job["raw_payload"], job["source"]))
```
Note this re-runs the **entire** pipeline from scratch for each unfinished job (not a resume-from-checkpoint) — the AI, threat intel, everything runs again. This is a deliberate simplicity trade-off (see §25 Technical Debt).

---

## 5. Frontend Deep Dive

**There is no JavaScript framework, no build tool, no `package.json`, no npm.** The entire frontend is three static files served byte-for-byte by FastAPI's `StaticFiles` mount (`src/main.py` line 108) plus a root route that serves `dashboard.html` directly (`src/main.py`, `dashboard_root()`).

| File | Role |
|---|---|
| `static/dashboard.html` | Structure + **all CSS** (a large `<style>` block using CSS custom properties for a single dark theme). No CSS framework (no Tailwind/Bootstrap). |
| `static/dashboard.js` | App state (`const state = {...}`), authentication, view routing, all `fetch()` calls to `/dashboard/api/*`, WebSocket connection + event handling, table/modal rendering. Loaded **second** in the `<script>` tags but must be understood **first** conceptually — it owns the shared `state` object and helpers (`esc()`, `api()`, `badge()`, `showModal()`) that `dashboard-viz.js` depends on. |
| `static/dashboard-viz.js` | Loaded first in the HTML (a deliberate ordering comment explains why: "it only binds DOM at load time, while dashboard.js's boot path calls into it") but is logically a *plugin* to `dashboard.js` — the live SVG pipeline-flow graph (`renderFlow()`) and the four hand-rolled SVG bar/series charts (`drawSeries`, `drawBars`, `drawRisk`, `drawStatus`, `drawSource`). No charting library (no Chart.js/D3) — every `<rect>`/`<line>`/`<text>` is built by hand via the `el()` helper. |

### "Routing" (client-side view switching, not URL routing)

There is no client-side router and no URL-based navigation (no `#hash` or History API usage). "Pages" are just `<section class="view" id="view-overview">` etc. inside one HTML document, toggled by `showView(name)` in `dashboard.js`:

```js
function showView(name) {
  state.view = name;
  document.querySelectorAll("nav a.tab").forEach(a => a.classList.toggle("active", a.dataset.view === name));
  document.querySelectorAll("section.view").forEach(s => s.classList.toggle("active", s.id === "view-" + name));
  ...
  if (name === "flow") renderFlow();
  if (name === "overview") loadStats();
  if (name === "logs") loadLogs();
  if (name === "ai") loadAiContent();
  if (name === "settings") loadSettings();
  if (name === "emails") loadDelivery();
}
```
Reloading the browser always lands on `overview` — there is no deep-linking to a specific tab or alert. Sidebar tabs are defined statically in the HTML (`nav a.tab` elements, each with `data-view="..."`), wired up via `document.querySelectorAll("nav a.tab").forEach(a => a.onclick = () => showView(a.dataset.view))`.

### The eight "pages" (views)

| View (`data-view`) | Purpose | Data source | Key functions |
|---|---|---|---|
| `overview` | Stat tiles + 4 SVG charts | `GET /dashboard/api/stats` | `loadStats()`, `drawSeries/Risk/Status/Source()` (dashboard-viz.js) |
| `flow` | Live per-alert pipeline lanes | WebSocket `pipeline_stage` events only (no REST fetch) | `renderFlow()`, `applyStage()`, `ensureRun()` (dashboard-viz.js) |
| `alerts` | Sortable/filterable table of every job | `GET /dashboard/api/jobs` (on boot) + live WS updates | `renderAlerts()`, `openAlert()` |
| `ai` | Browsable AI-generated notifications | `GET /dashboard/api/ai-content` | `loadAiContent()`, `renderAiContent()`, `notificationTabs()` |
| `emails` | Outbox + handoff history + live mail-service counters | `GET /dashboard/api/emails`, `/delivery`, `/delivery/service-status` | `loadDelivery()`, `renderDelivery()` |
| `logs` | Tailing structured JSON log | `GET /dashboard/api/logs` (polled every 3s if "Auto" checked) | `loadLogs()`, `renderLogs()` |
| `settings` | Edit notification recipients; view read-only runtime config | `GET/PUT /dashboard/api/settings*` | `loadSettings()` |
| `api` | Static reference docs + copyable curl example | Computed client-side from `location.origin` | `renderApiDocs()` |

### State management

**There is exactly one shared, in-memory JS object** — `state` at the top of `dashboard.js`:
```js
const state = {
  jobs: new Map(),   // correlation_id -> job row (the Alerts table's backing data)
  emails: [],          // pending outbox entries (the Emails table's backing data)
  ai: [],               // cached AI Content list
  runs: new Map(),      // correlation_id -> {stages: Map, started, source}  (Flow tab lanes)
  stats: null,
  view: "overview",
};
```
This is **not** Redux/Zustand/Context — it's a plain module-level object mutated directly and re-rendered imperatively (`renderAlerts()`, `renderEmails()`, `renderFlow()` each just re-generate `innerHTML` from `state` on every call — there is no virtual DOM diffing). `state.runs` is capped at `MAX_LANES = 7` (dashboard-viz.js) — oldest lane evicted first, so the Flow tab never grows unbounded.

**Two other storage locations:**
- `sessionStorage.getItem("dash_key")` / `sessionStorage.setItem("dash_key", key)` — the dashboard access key, persisted only for the browser tab's session (cleared on `lock()`). This is the *only* piece of persisted client state; refreshing the tab keeps you logged in, closing it logs you out.
- No `localStorage` usage anywhere in the codebase.
- No URL query-string state.

**Who changes state, who consumes it:**
- WebSocket `handleEvent()` is the *primary* writer (`upsertJob()`, `state.emails.unshift()`, `applyStage()`).
- REST responses from `boot()`, `loadStats()`, `loadAiContent()`, etc. are the *initial* writers (full replace on tab load / manual refresh).
- Render functions (`renderAlerts`, `renderEmails`, `renderFlow`, chart `draw*` functions) are the *only* readers — they run on every state mutation that could affect their tab, plus on `showView()` for tabs that need a fresh fetch.

### Important "components" (there are no component objects — these are function groups)

Because this isn't React/Vue, there's no component tree with props/children in the traditional sense. The closest equivalent is groups of functions that own one DOM region:

- **Modal system** (`showModal(title, bodyHtml)`, `wireTabs(box)`) — a single reusable `#overlay > .modal#modalBox` element whose `innerHTML` is replaced per-use. Used by `openAlert()`, `openEmail()`, `openStageDetail()` (dashboard-viz.js). Tab-switching inside a modal (e.g. the four AI notification languages) is handled generically by `wireTabs()` reading `data-tab`/`data-panel` attributes — this pattern (`notificationTabs()`) is reused for both the AI Content list and the Alert Detail modal.
- **Flow graph** (`renderFlow()`, `ensureRun()`, `applyStage()`, `openStageDetail()` in dashboard-viz.js) — the most complex piece of UI: builds raw SVG nodes/edges by hand for up to 7 concurrent "lanes," each showing 9 pipeline stages (`STAGES` array, shared between `dashboard.js` and the backend's `src/utils/events.py: STAGES` — **these two lists must stay in sync manually**, there's no shared schema).
- **Charts** (`drawSeries`, `drawBars` + its 3 callers `drawRisk/Status/Source`) — pure SVG generation from aggregate numbers, no external chart lib.

### Critical security detail: XSS escaping

Every value that ultimately comes from an *attacker-controllable* alert payload (detection names, endpoint names, subjects, IPs, etc.) **must** pass through `esc()` before being placed into `innerHTML`:
```js
const ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
function esc(v) {
  if (v === null || v === undefined) return "";
  return String(v).replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}
```
This is explicitly guarded by tests (`tests/integration/test_security.py: test_dashboard_escapes_all_rendered_data`, `test_dashboard_badges_use_class_allowlist`, and the equivalent in `test_dashboard_controls.py`) which grep the actual `.js` source for known-dangerous unescaped interpolation patterns. **If you add a new `${something}` template-literal interpolation of alert-derived data into `innerHTML` without wrapping it in `esc()`, these tests will fail** — that is intentional and is your regression guard.

Badge CSS classes are similarly guarded via an **allowlist**, not escaping: `badge(value)` in `dashboard.js` checks `BADGES.has(value)` and falls back to `"UNKNOWN"` if the value isn't one of the known constants, so a hostile `status` string can never break out of the `class="badge b-..."` attribute.

### What I should now be able to answer (Frontend)
- Where is the CSS for the whole dashboard defined? *(`static/dashboard.html`, inline `<style>`)*
- How does clicking "Pipeline Flow" in the sidebar change what's on screen? *(`showView("flow")` toggles `.active` classes, then calls `renderFlow()`)*
- What happens if I forget to call `esc()` on a new field I add to a table row? *(A stored-XSS vulnerability, and `test_dashboard_escapes_all_rendered_data` / `test_dashboard_js_escapes_rendered_data` will likely fail if the token pattern matches their checklist — but note: the tests check a fixed list of known tokens, so a genuinely new field needs a new assertion too.)*
- Where does the dashboard access key live between page loads? *(`sessionStorage`, key `dash_key`)*
- Why is `dashboard-viz.js` loaded before `dashboard.js` in the HTML, even though it depends on `dashboard.js`'s functions? *(It only registers DOM event listeners and defines functions at load time; those functions aren't *called* until `dashboard.js`'s `boot()` runs later, by which point both scripts have executed.)*

---

## 6. Backend Deep Dive

### Entry point and server initialization

`run.py` is the single command that starts the whole platform: `uvicorn.run("src.main:app", host=..., port=..., log_config=None)`. `log_config=None` is deliberate — it hands logging entirely to `structlog` (configured in `src/utils/logging.py`) instead of letting Uvicorn install its own logging config that would conflict.

`src/main.py` defines the FastAPI `app` and its `lifespan()` async context manager (see §1 and §4/Flow 5 for what startup does). Two module-level side effects happen at **import time**, not inside `lifespan()` — this matters for tests, which import `src.main` directly:
```python
app.state.broadcaster = EventBroadcaster()
events.set_broadcaster(app.state.broadcaster)
```
The comment in the code explains why: "so `app.state.broadcaster` always exists (the WebSocket route would otherwise raise `AttributeError` whenever lifespan has not run)". This matters because FastAPI's `TestClient` in `with client.websocket_connect(...)` context *does* run lifespan, but some simpler test flows might not.

### Layered structure

```
Route (src/api/*.py)
  ↓
Dependency / Middleware (src/middleware/auth.py — only on ingest routes;
                          _check_access() inline in dashboard.py — only on dashboard routes)
  ↓
Ingestion handler (src/ingestion/*.py) — only for the two /webhook/* routes
  ↓
Service layer (src/services/*.py) — the actual business logic, orchestrated by
  ↓
src/pipeline/orchestrator.py — the only place that calls services in sequence
  ↓
Storage layer (src/storage/*.py) — SQLite via aiosqlite
  ↓
Filesystem (output/alerts/*.json, output/emails/outbox.json) — via output_writer.py / email_outbox.py
```
There is **no separate "controller" vs "service" naming split** the way some frameworks use it — route functions in `src/api/*.py` are thin and call directly into `src/services/*` and `src/storage/*`. The **orchestrator** (`src/pipeline/orchestrator.py`) is the closest thing to a "use case" layer: it's the only module that knows the *order* services must run in.

### Why routes are grouped the way they are

`src/api/router.py` aggregates four sub-routers into one `api_router`, included once in `main.py`:
- `webhook.py` → prefix `/webhook` — external, authenticated-by-token ingest surface.
- `health.py` → prefix `/health` — unauthenticated liveness/readiness probe.
- `status.py` → prefix `/status` — unauthenticated (but UUID-gated) job lookup, meant for the alert *sender* to poll.
- `dashboard.py` → prefix `/dashboard/api` — internal, key-gated operator surface (REST + one WebSocket route).

### Background task model

There is **no external task queue** (no Celery/RQ/Redis). Two different async mechanisms are used:
1. **FastAPI `BackgroundTasks`** — used for one-shot work tied to an HTTP request/response cycle: running the pipeline after a webhook POST (`src/api/webhook.py`), and re-running it on retry (`src/api/dashboard.py: retry_job()`). These execute *after* the response is sent, in-process.
2. **Raw `asyncio.create_task()`** — used for work *not* tied to any single HTTP request: crash recovery on startup, the periodic email-dispatch sweep loop (`email_dispatcher.run_dispatch_loop()`), and the fire-and-forget `email_dispatcher.dispatch_soon()` called right after emails are queued.

Because everything shares **one process and one event loop**, there is no serialization/deserialization across a queue boundary, no separate worker process to deploy, and no message broker to run — but it also means **a CPU-bound or blocking call anywhere would stall the entire server**, including the syslog listeners and the dashboard WebSocket. (The Gemini SDK call is blocking, which is why it's specifically wrapped in `loop.run_in_executor(None, ...)` inside `gemini_service.py`.)

### Concurrency-safety mechanisms worth knowing

- `src/services/output_writer.py` uses an `asyncio.Lock()` (`_index_lock`) around read-modify-write of `index.json`, since multiple pipeline runs could finish concurrently.
- `src/services/email_outbox.py` uses its own `asyncio.Lock()` (`_outbox_lock`) around `outbox.json` read-modify-write, for the same reason.
- `src/services/email_dispatcher.py` uses a `_dispatch_lock` so the periodic sweeper, a pipeline-triggered dispatch, and a dashboard "Send queued now" click can never race and hand off the same email twice.
- All file writes (`output_writer.py`, `email_outbox.py`) use the **temp-file + `os.replace()`** pattern for atomicity — a crash mid-write never leaves a half-written JSON file at the real path.
- SQLite is opened in **WAL mode** (`PRAGMA journal_mode=WAL`, set in `src/storage/database.py: db_session()`) to allow concurrent readers alongside a writer.

### What I should now be able to answer (Backend)
- If I add a new webhook ingest source (say, a Slack integration), what new file(s) would I create? *(A new `src/ingestion/<name>_handler.py` implementing `BaseIngestionHandler.parse()`, plus a new route in `src/api/webhook.py` — or a new router file — calling `ingest_alert()` with that handler.)*
- Why does `run_pipeline_task()` import `process_alert_pipeline` *inside* the function body instead of at module level? *(To avoid a circular import — `src/api/webhook.py` is imported early via `router.py`, and `src/pipeline/orchestrator.py` imports from `src/services`, which could create an import cycle if wired at module scope. The comment in the code confirms this is deliberate.)*
- What would happen to in-flight alerts if the process were killed mid-pipeline? *(They'd be stuck at `PENDING`/`PROCESSING` in SQLite; on next startup, `recover_unfinished_jobs()` re-runs them from scratch — see Flow 5.)*

---

## 7. API Documentation

### Ingest API (authenticated via bearer token — see §9)

| Method | Endpoint | Purpose | Auth | Request | Response | Main file |
|---|---|---|---|---|---|---|
| POST | `/webhook/eset` | Ingest an ESET PROTECT webhook-format alert | Bearer token | JSON body matching `EsetRawPayload` fields (all optional) | `{"status": "queued"\|"duplicate"\|"error", "correlation_id": "...", ...}` | `src/api/webhook.py: receive_eset_webhook()` |
| POST | `/webhook/syslog` | Ingest an ESET syslog-JSON-export-format alert (also used internally by the UDP/TCP listeners) | Bearer token | JSON body with syslog key names (`threat_name`, `computer_name`, `hash`, `ip`, `handled`, ...) | Same shape as above | `src/api/webhook.py: receive_syslog_payload()` |

**Execution path for `POST /webhook/eset`:**
```
route (webhook.py) → Depends(validate_eset_token) [auth.py]
    → ingest_alert() → WebhookIngestionHandler.parse() [ingestion/webhook_handler.py]
    → deduplication.is_duplicate()/.record_seen() [storage/deduplication.py]
    → job_store.create_job() [storage/job_store.py]
    → background_tasks.add_task(run_pipeline_task)
    → HTTP 200 {"status":"queued", "correlation_id": "..."}
```

### Status / Health (unauthenticated)

| Method | Endpoint | Purpose | Auth | Response | Main file |
|---|---|---|---|---|---|
| GET | `/health` | Consolidated health check (DB, output dir writability, Gemini config presence, syslog listener state) | None | `{"status": "ok"\|"degraded", "database": {...}, "output_directory": {...}, "gemini_api": {...}, "syslog_listener": {...}}` | `src/api/health.py: health_check()` |
| GET | `/status/{correlation_id}` | Poll a specific job's status | None (but requires knowing the UUID) | `{"correlation_id", "source", "status", "created_at", "updated_at", "error", "output_file"}` or 404 | `src/api/status.py: get_job_status()` |

### Dashboard API (key-gated via `X-Dashboard-Key` header when `DASHBOARD_ACCESS_KEY` is set — see §9)

All routes below are prefixed `/dashboard/api` and call `_check_access(request)` as their first line (defined once in `src/api/dashboard.py`).

| Method | Endpoint | Purpose | Request | Response | Main file/function |
|---|---|---|---|---|---|
| GET | `/jobs` | List recent jobs (paginated, filterable) | Query: `limit`, `offset`, `status` | `{"jobs": [...]}` | `get_jobs()` |
| GET | `/jobs/{correlation_id}` | Job + its full pipeline result JSON if present | — | `{"job": {...}, "result": {...}\|null}` or 404 | `get_job_detail()` |
| POST | `/jobs/{correlation_id}/retry` | Re-run a FAILED/PARTIAL job with its stored payload | — | `{"status": "retrying", "correlation_id": "..."}` or 400/404 | `retry_job()` |
| GET | `/alerts` | Reverse-chronological alert index summary (from `index.json`) | — | `{"alerts": [...]}` | `get_alerts()` |
| GET | `/ai-content` | Recent AI-generated notifications | Query: `limit` | `{"items": [...]}` | `get_ai_content()` |
| GET | `/emails` | Pending outbox emails | — | `{"emails": [...]}` | `get_emails()` |
| DELETE | `/emails/{email_id}` | Discard a pending outbox email | — | `{"status": "removed", ...}` or 404 | `delete_email()` |
| GET | `/stats` | Aggregates for dashboard charts | Query: `hours` (1–168) | `{"totals", "by_status", "by_risk", "by_source", "series", "window_hours"}` | `get_stats()` |
| GET | `/logs` | Tail structured JSON log file | Query: `limit`, `level`, `q` | `{"lines": [...], "total_scanned"}` | `get_logs()` |
| GET | `/settings` | Recipient config + read-only runtime config + delivery status | — | `{"recipients", "runtime", "delivery"}` | `get_settings()` |
| PUT | `/settings/recipients` | Update dashboard-editable recipient overrides | JSON body: `RecipientUpdate` (4 optional string fields) | `{"status": "saved", "updated": [...], "recipients": {...}}` or 400 | `update_recipients()` |
| GET | `/delivery` | Email handoff config + history + counts | Query: `limit`, `status` | `{"config", "counts", "deliveries", "pending_in_outbox"}` | `get_delivery_overview()` |
| GET | `/delivery/service-status` | Live queue counters from the external mail service | — | `{"available", "queue"\|"error"}` | `get_mail_service_status()` |
| POST | `/delivery/dispatch` | Force-flush the outbox to the mail service now | — | `{"accepted", "failed", "pending"}` or `{"skipped": "..."}` | `trigger_dispatch()` |
| WS | `/ws` | Live event stream (see §5) | Query: `?key=...` if access key set | Streamed JSON: `{"type": "...", "data": {...}}` | `dashboard_ws()` |

**Execution path example — `PUT /dashboard/api/settings/recipients`:**
```
route (dashboard.py: update_recipients)
    → _check_access(request)                          [X-Dashboard-Key check]
    → RecipientUpdate(**payload)                       [Pydantic validation — unknown keys silently ignored
                                                          by model shape, extraneous JSON keys not in the
                                                          model are dropped since RecipientUpdate has no
                                                          extra="allow"]
    → settings_store.update_recipients(values)          [storage/settings_store.py]
        → set_setting(key, value) per key                [SQLite: INSERT ... ON CONFLICT DO UPDATE]
    → 200 {"status": "saved", "updated": [...]}
```

### WebSocket event types (payload shapes)

Emitted from `src/utils/events.py: emit()`/`emit_stage()`, called from various backend modules, consumed by `static/dashboard.js: handleEvent()`:

| Event type | Emitted by | Payload shape |
|---|---|---|
| `job_status_changed` | `job_store.create_job()`, `job_store.update_job_status()` | `{correlation_id, source, status, error, updated_at}` |
| `pipeline_stage` | `events.emit_stage()`, called throughout `orchestrator.py` and `output_writer.py`/`email_dispatcher.py` | `{correlation_id, stage, state, detail, ...extra}` — `stage` ∈ `INGEST/NORMALIZE/RISK/INTEL/AI/LINT/OUTPUT/EMAIL/SEND`; `state` ∈ `active/ok/failed/skipped` |
| `alert_completed` | `output_writer.write_result()` | Full `PipelineResult.model_dump()` |
| `email_queued` | `email_outbox.add_emails()` | `EmailMessage.model_dump()` |
| `email_sending` | `email_dispatcher._hand_off()` | `{email_id}` |
| `email_accepted` | `email_dispatcher._hand_off()` | `{email_id, correlation_id, notification_type, to, subject, remote_id}` |
| `email_failed` | `email_dispatcher._hand_off()` | `{email_id, correlation_id, error, attempts, permanent}` |

---

## 8. Database Deep Dive

**Technology: SQLite via `aiosqlite`**, file path from `settings.sqlite_db_path` (default `data/soc_lite.db`). There is **no ORM** (no SQLAlchemy) — every query in `src/storage/*.py` is hand-written parameterized SQL executed through `aiosqlite`.

### Connection management

`src/storage/database.py: db_session()` is an `@asynccontextmanager` that every storage function calls fresh — **there is no connection pool**; a new `aiosqlite.connect()` happens per call, configured with `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`, then closed on exit. This is simple but means high alert throughput opens/closes many SQLite connections; WAL mode keeps this workable for the intended low-to-moderate throughput.

### Schema (all DDL lives in `init_db()`, `src/storage/database.py`)

**`jobs`** — the alert-processing job queue / audit trail
| Column | Type | Notes |
|---|---|---|
| `correlation_id` | TEXT PRIMARY KEY | UUID4, generated by `generate_correlation_id()` |
| `source` | TEXT NOT NULL | `WEBHOOK` or `SYSLOG` |
| `status` | TEXT NOT NULL | `PENDING → PROCESSING → SUCCESS\|PARTIAL\|FAILED` |
| `raw_payload` | TEXT NOT NULL | JSON-serialized original payload (stringified) |
| `created_at` | REAL NOT NULL | Unix timestamp |
| `updated_at` | REAL NOT NULL | Unix timestamp |
| `error` | TEXT | Nullable; set on FAILED/PARTIAL |

Used by: `src/storage/job_store.py` (`create_job`, `update_job_status`, `get_job`, `list_jobs`, `get_unfinished_jobs`). Consumed by: orchestrator (writes), dashboard `/jobs*` routes (reads), `/status/{id}` (reads), crash recovery (reads).

**`dedup_log`** — duplicate-alert suppression
| Column | Type | Notes |
|---|---|---|
| `composite_key` | TEXT PRIMARY KEY | `alert_id:occurred_at`, or SHA-256 of the full payload as fallback |
| `received_at` | REAL NOT NULL | |
| `expires_at` | REAL NOT NULL | `received_at + DEDUP_TTL_SECONDS` |

Used by: `src/storage/deduplication.py` (`is_duplicate`, `record_seen`, `cleanup_expired`). **Note:** `cleanup_expired()` exists but is **never called anywhere in the running application** — expired rows are simply ignored by the `expires_at > now()` filter in `is_duplicate()`, so the table grows forever unless something external calls `cleanup_expired()`. (See §25 Technical Debt.)

**`app_settings`** — dashboard-editable configuration overrides
| Column | Type | Notes |
|---|---|---|
| `key` | TEXT PRIMARY KEY | e.g. `client_notification_emails` |
| `value` | TEXT NOT NULL | Comma-separated email list |

Used by: `src/storage/settings_store.py`. This is a generic key-value table but in practice only the four `RECIPIENT_KEYS` are ever written through the dashboard UI today.

**`email_deliveries`** — outbound-email handoff history (indexed on `status`)
| Column | Type | Notes |
|---|---|---|
| `email_id` | TEXT PRIMARY KEY | `{correlation_id}-{notification_type}`, e.g. `abc123-CLIENT_JA` |
| `correlation_id` | TEXT NOT NULL | Links back to `jobs` (no FK constraint enforced) |
| `notification_type` | TEXT NOT NULL | `CLIENT_JA\|CTHREE_JA\|INTERNAL_JA\|ENGINEER_EN` |
| `recipients` | TEXT NOT NULL | JSON array, stringified |
| `subject` | TEXT NOT NULL | |
| `status` | TEXT NOT NULL | `PENDING\|ACCEPTED\|FAILED` |
| `attempts` | INTEGER NOT NULL DEFAULT 0 | Incremented on every `record_attempt()` call |
| `remote_id` | TEXT | The mail service's own queue id, once accepted |
| `error` | TEXT | Nullable |
| `created_at` / `updated_at` | REAL NOT NULL | |

Used by: `src/storage/delivery_store.py`. **No relationships are enforced by SQL foreign keys anywhere** — `foreign_keys=ON` is set as a pragma but no table actually declares a `FOREIGN KEY` constraint. Cross-table consistency (e.g. `email_deliveries.correlation_id` matching a real `jobs.correlation_id`) is entirely by convention/application logic.

### The "other database": JSON files on disk

The *actual alert content* (normalized alert, risk rationale, threat intel, AI output) is **not** stored in SQLite at all — it's written as one JSON file per alert:

- `output/alerts/{correlation_id}.json` — full `PipelineResult` (see `src/models/pipeline_result.py`), written by `src/services/output_writer.py: write_result()`.
- `output/alerts/index.json` — an append-only array of lightweight summary records (`correlation_id`, `source`, `processed_at`, `risk_level`, `status`) used so the dashboard can list/order alerts without opening every file (`_read_results()` in `src/api/dashboard.py`).
- `output/emails/outbox.json` — an array of **pending-only** `EmailMessage` records (accepted/failed ones are removed, not marked). This is the "database" for the Emails tab's outbox view.

This split exists because SQLite holds *queue/workflow state* (small, frequently updated), while the JSON files hold *the actual generated content* (larger, write-once, read-many, and convenient to eyeball directly on disk during debugging).

### If I add/change/remove a field, what else changes?

| Change | Files you must also touch |
|---|---|
| Add a field to `EsetRawPayload` (raw incoming data) | Nothing structurally required — `EsetRawPayload` has `extra: "allow"`, so unknown fields are silently accepted. But to make it *do* anything you'd also update `src/services/normalizer.py` to map it onto `NormalizedAlert`, and `src/models/normalized_alert.py` to add the strict field. |
| Add a field to `NormalizedAlert` | `src/services/normalizer.py` (map raw → normalized), possibly `src/services/risk_engine.py` (if it affects risk), `src/prompts/system_prompts.py`/`gemini_service.py` prompt construction implicitly includes it via `alert.model_dump()`, and `static/dashboard.js: openAlert()` if you want it shown in the Alert Detail modal. |
| Add a field to `AIOutput` or its sub-schemas | `src/models/ai_output.py`, then `src/prompts/system_prompts.py` (tell the AI to fill it), `src/services/email_composer.py` (include it in the email body), `static/dashboard.js: notificationTabs()` (show it in the modal), and likely a new/updated test in `tests/unit/test_schema_builder.py` (since `build_gemini_schema` derives the Gemini schema automatically from the Pydantic model — no manual sync needed there, which is the whole point of that module). |
| Add a new SQLite table/column | `src/storage/database.py: init_db()` (DDL), a new/updated `src/storage/*.py` module, and note there is **no migration system** — `CREATE TABLE IF NOT EXISTS` means existing deployed databases with an old schema will **not** automatically get new columns; you'd need a manual `ALTER TABLE` or to document a fresh-DB requirement. |
| Add a new pipeline stage | `src/utils/events.py: STAGES` list, `src/pipeline/orchestrator.py` (call `events.emit_stage()` at the right point), **and** `static/dashboard.js: STAGES`/`STAGE_LABEL` (JS-side, must be kept in sync manually — no shared schema file). |

---

## 9. Authentication + Authorization

This application has **no user accounts, no login/registration/password-reset flow, no sessions in the traditional sense, no roles, and no per-user permissions.** There are exactly two shared secrets, each gating a different surface:

### 1. Ingest authentication — `ESET_WEBHOOK_AUTH_TOKEN`

A single, static bearer token shared by every caller of `/webhook/eset` and `/webhook/syslog`. Implemented in `src/middleware/auth.py: validate_eset_token()`, wired as a FastAPI dependency on those two routes only (`src/api/webhook.py`):

```python
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def validate_eset_token(request: Request, api_key: str | None = Security(api_key_header)) -> None:
    if not api_key:
        raise HTTPException(status_code=401)
    token = api_key[7:].strip() if api_key.lower().startswith("bearer ") else api_key
    if not hmac.compare_digest(token, settings.eset_webhook_auth_token):
        raise HTTPException(status_code=401)
```
- Accepts either `Authorization: Bearer <token>` or a bare `Authorization: <token>` (case-insensitive prefix check).
- Uses `hmac.compare_digest()` — a **constant-time comparison** — specifically to prevent timing side-channel attacks that could let an attacker guess the token character-by-character via response-time measurement.
- Logs `auth_failed_missing_header` / `auth_failed_token_mismatch` with the client IP on failure, but returns a bare `401` with **no body detail** (so a failed guess doesn't leak *why* it failed).
- There is only **one** token for **all** callers — no per-source or per-client tokens, no scopes, no expiry, no rotation mechanism built in. Rotating it means editing `.env` and restarting the process (all existing integrations must update simultaneously).

### 2. Dashboard authentication — `DASHBOARD_ACCESS_KEY`

A single, static key gating every `/dashboard/api/*` route and the `/ws` WebSocket. Implemented as `_check_access()` inside `src/api/dashboard.py`, called as the **first line of every route handler** (not a FastAPI dependency — it's called manually, so it's easy to forget on a new route; see §26):

```python
def _check_access(request: Request) -> None:
    if not settings.dashboard_access_key:
        return   # dashboard is fully open if no key is configured
    provided = request.headers.get("x-dashboard-key") or ""
    if not hmac.compare_digest(provided, settings.dashboard_access_key):
        raise HTTPException(status_code=401, detail="Invalid or missing dashboard key")
```
- If `DASHBOARD_ACCESS_KEY` is blank, **the entire dashboard API is open with no auth at all** — this is intentional for trusted local use, and `src/main.py: warn_on_insecure_exposure()` logs a `dashboard_exposed_without_key` warning at startup specifically when the bind host isn't loopback and no key is set.
- The WebSocket route (`dashboard_ws()`) checks the key via a **query parameter** (`?key=...`) instead of a header, because browsers cannot set custom headers on a WebSocket handshake. It also independently checks the `Origin` header (`_origin_allowed()`) to prevent Cross-Site WebSocket Hijacking (CSWSH) — a browser-specific attack where a malicious page opens a WebSocket to this server using the victim's cookies/session; since this app has no cookies, the real protection here is that the origin check stops *any* third-party page from opening a socket and passively receiving every alert.
- **The frontend "login screen"** (`static/dashboard.html: #login`) is not real authentication in the security sense — it's a UX gate. `attemptLogin(key)` just stores the key in `sessionStorage` and *probes* the API (`GET /dashboard/api/jobs?limit=1`); if the server accepts it (200), the login succeeds; if not (401), it's rejected. The actual enforcement is 100% server-side in `_check_access()` — a user could bypass the HTML login screen entirely and just set `sessionStorage.dash_key` via devtools, which changes nothing because the server still checks the real header on every call.

### Password reset / email verification / registration

**None of these exist.** There are no user accounts to register, verify, or reset a password for. This is a service-to-service / operator-tool authentication model, not a consumer-app one.

### Authorization (roles/permissions)

**There is no authorization layer beyond the two binary auth gates above.** Whoever has the webhook token can post any alert; whoever has the dashboard key can see, retry, or delete anything in the dashboard — there's no read-only vs admin distinction, no per-alert ownership, no audience-based access control on the Emails/AI Content tabs (an operator with the dashboard key can read the Client-facing, C-Three, Internal, *and* Engineer notifications for every alert, even though those are meant for four different audiences once they leave as email).

### Beginner translation

**Technical:** two shared-secret bearer/header tokens, compared with constant-time HMAC comparison, gate two independent route groups; no session state, no JWT, no OAuth.

**Simple:** think of it like two separate padlocks with two separate keys taped to the server config. One key lets a machine (ESET PROTECT Cloud) drop off alerts. The other key lets a human operator open the dashboard webpage. Anyone holding a key can do *everything* that key's door allows — there's no "read-only visitor" version of either key.

### What I should now be able to answer (Auth)
- Where is the webhook token compared, and why `hmac.compare_digest` instead of `==`? *(`src/middleware/auth.py`; constant-time comparison prevents timing attacks.)*
- What happens if `DASHBOARD_ACCESS_KEY` is left blank in production? *(The whole dashboard API is open to anyone who can reach the port; a warning is logged at startup if bound to a non-loopback host.)*
- Why does the WebSocket route check the key differently from the REST routes? *(Browsers can't set custom headers during the WS handshake, so the key is passed as a query string parameter instead.)*
- If I add a new `/dashboard/api/foo` route and forget to call `_check_access(request)`, what happens? *(It silently becomes an unauthenticated route — nothing else enforces the key. This is a real footgun; see §26.)*

---

## 10. Environment Variables + Configuration

All configuration flows through **one file**: `src/config.py`, a Pydantic `BaseSettings` subclass that reads from `.env` (path resolved relative to the project root) and environment variables, with `extra="ignore"` (unknown env vars are silently dropped, not errors). `.env.example` is the template; `.env` itself is gitignored.

| Variable | Used by | Purpose | Required? | Safe to expose to frontend? |
|---|---|---|---|---|
| `GEMINI_API_KEY` | `src/services/ai/gemini_service.py` | Auth for Google Gemini API | **Yes** (no default — app fails to start without it) | No — secret |
| `ESET_WEBHOOK_AUTH_TOKEN` | `src/middleware/auth.py` | Shared bearer token for ingest routes | **Yes** (no default) | No — secret |
| `APP_HOST` | `run.py`, `supervisord.conf` | Bind address for the API server | No (default `0.0.0.0`) | N/A (server-side only) |
| `APP_PORT` | `run.py`, `supervisord.conf` | Bind port | No (default `8000`) | N/A |
| `LOG_LEVEL` | `src/utils/logging.py` | Log verbosity | No (default `INFO`) | N/A |
| `OUTPUT_DIR` | `src/services/output_writer.py`, `src/api/*` | Where alert result JSON files are written | No (default `output/alerts`) | N/A |
| `SYSLOG_HOST` | `src/services/syslog_runtime.py` | Bind address for syslog listeners | No (default `0.0.0.0`) | N/A |
| `SYSLOG_UDP_PORT` | `src/services/syslog_runtime.py` | UDP syslog listener port | No (default `514`, needs root) | N/A |
| `SYSLOG_TCP_PORT` | `src/services/syslog_runtime.py` | TCP syslog listener port | No (default `601`, needs root) | N/A |
| `SQLITE_DB_PATH` | `src/storage/database.py` | SQLite file location | No (default `data/soc_lite.db`) | N/A |
| `DEDUP_TTL_SECONDS` | `src/storage/deduplication.py` (via `src/api/webhook.py`) | Duplicate-suppression window | No (default `3600`) | N/A |
| `THREAT_INTEL_TIMEOUT_SECONDS` | `src/services/threat_intel/aggregator.py` | Per-provider timeout | No (default `5`) | N/A |
| `AI_TIMEOUT_SECONDS` | Declared but — see note below | Intended AI call timeout | No (default `30`) | N/A |
| `MAX_RETRIES` | Declared — see note below | Intended generic retry count | No (default `3`) | N/A |
| `CLIENT_NOTIFICATION_EMAILS` | `src/services/email_composer.py` via `settings_store` | Default client recipients (comma-separated) | No (default blank = skip) | No — internal contact data |
| `CTHREE_NOTIFICATION_EMAILS` | same | Default C-Three recipients | No | No |
| `INTERNAL_NOTIFICATION_EMAILS` | same | Default internal team recipients | No | No |
| `ENGINEER_NOTIFICATION_EMAILS` | same | Default engineer recipients | No | No |
| `DASHBOARD_ACCESS_KEY` | `src/api/dashboard.py` | Gates the whole dashboard API/WS | No (blank = open) | No — secret (though it's a UI-facing "password," never put in client bundle/source) |
| `EMAIL_DELIVERY_ENABLED` | `src/services/email_dispatcher.py` | Turns handoff-to-mail-service on/off | No (default `false`) | N/A |
| `EMAIL_PROVIDER` | `src/services/email_delivery/__init__.py` | Which provider class to use | No (default `eset_mail`) | N/A |
| `EMAIL_API_URL` | `src/services/email_delivery/eset_mail.py` | ESET Mail worker endpoint | No (blank = not configured) | No |
| `EMAIL_API_KEY` | same | API key header for the mail worker | No | No — secret |
| `EMAIL_API_SECRET` | same | HMAC signing secret | No (required for `signed`/`full` modes) | No — secret, never transmitted |
| `EMAIL_SECURITY_MODE` | same | `full`\|`signed`\|`api-key-only` | No (default `full`) | N/A |
| `EMAIL_TIMEOUT_SECONDS` | same | HTTP timeout for the handoff call | No (default `60`) | N/A |
| `EMAIL_MAX_ATTEMPTS` | `src/services/email_dispatcher.py` | Handoff attempts before giving up | No (default `3`) | N/A |
| `EMAIL_DISPATCH_INTERVAL_SECONDS` | same | Sweeper loop interval | No (default `60`) | N/A |

**Note on `AI_TIMEOUT_SECONDS` / `MAX_RETRIES`:** both are declared in `Settings` but a repo-wide search shows they are **not actually referenced anywhere** in `src/services/ai/gemini_service.py` — the real AI retry behavior comes from the hardcoded `@retry_api_call(max_attempts=3, min_delay=1.0, max_delay=10.0)` decorator, not from these settings. This is a **confirmed** dead-configuration gap — see §25 Technical Debt. Changing `AI_TIMEOUT_SECONDS`/`MAX_RETRIES` in `.env` currently has **no effect** on AI call behavior.

**Also note:** `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` are referenced directly via `os.environ.get(...)` in `src/services/threat_intel/virustotal.py`/`abuseipdb.py` — **not** declared in `src/config.py`'s `Settings` class at all. They only matter when `use_mock_threat_intel` is `False` (which itself is **not** exposed as an env var — it's a hardcoded `True` default in `Settings`, i.e. real threat-intel API calls are effectively disabled unless someone edits `src/config.py` directly).

There is **no separate frontend `.env`** — the "frontend" (`static/*`) has zero environment variables; it derives everything it needs (like the API base URL) from `location.origin` at runtime in the browser (`renderApiDocs()` in `dashboard.js`).

---

## 11. Dependencies

From `pyproject.toml`:

| Dependency | Why it's used | Where | If removed |
|---|---|---|---|
| `fastapi` | The entire HTTP framework — routing, dependency injection, request/response models, WebSocket support | Everywhere in `src/api/`, `src/main.py` | Nothing works; this *is* the web server framework |
| `uvicorn[standard]` | ASGI server that actually runs the FastAPI app | `run.py`, `supervisord.conf` | No way to serve the app over HTTP |
| `pydantic` (v2) | All data models/validation — `EsetRawPayload`, `NormalizedAlert`, `AIOutput`, `PipelineResult`, etc. | `src/models/*.py`, `src/config.py` | The entire type-safety and validation layer disappears; nothing would parse/validate JSON |
| `pydantic-settings` | `BaseSettings` — typed env-var loading with `.env` support | `src/config.py` | Config would need to be hand-rolled with `os.environ` calls everywhere |
| `aiosqlite` | Async SQLite driver | `src/storage/database.py` and everything that calls `db_session()` | No async DB access; the job queue, dedup, settings, and delivery history all break |
| `httpx` | Async HTTP client for outbound calls | `src/services/threat_intel/{virustotal,abuseipdb}.py`, `src/services/email_delivery/eset_mail.py`, `src/services/syslog_runtime.py` (loopback forwarding) | No way to call VirusTotal/AbuseIPDB/ESET Mail or forward syslog to the webhook route |
| `google-generativeai` | Google's Gemini SDK | `src/services/ai/gemini_service.py`, `src/services/ai/schema_builder.py` | The entire AI-generation step disappears — no notifications would ever be produced |
| `structlog` | Structured (JSON-capable) logging used across the whole codebase | `src/utils/logging.py` and every module's `logger = structlog.get_logger(__name__)` | Logs become unstructured/plain-text; the dashboard's Logs tab (which parses JSON log lines) breaks entirely |
| `tenacity` | Retry-with-backoff decorator | `src/utils/retry.py`, consumed by `gemini_service.py` | The one `@retry_api_call` decorator used for Gemini calls would need to be hand-written |
| `pytest`, `pytest-asyncio` (dev only) | Test framework + async test support | `tests/` | The test suite could not run at all |

**No frontend dependencies exist** — `static/*` has zero third-party JS, so there is nothing to document in that category (deliberately, per the code comment: "no chart library, so nothing external is fetched").

---

## 12. Error Handling

### Where errors occur and how they're transformed, by layer

**Ingest-time validation errors** (malformed JSON, unparseable payload):
```
src/ingestion/{webhook,syslog}_handler.py: parse() raises ValueError
    → caught in src/api/webhook.py: ingest_alert()
    → logged as "ingest_invalid_payload"
    → returned as HTTP 200 with {"status": "error", "message": str(e), "correlation_id": ...}
```
Note this is **HTTP 200**, not 400 — a parse failure is reported *inside* the JSON body's `status` field, not via HTTP status code. A client checking only `response.status_code` would miss this.

**Auth errors:** `HTTPException(status_code=401)` with **no body detail** raised directly from `src/middleware/auth.py` / `_check_access()` in `dashboard.py` — FastAPI's exception handler converts these to a standard `{"detail": "..."}` JSON body automatically (though the webhook auth path passes no detail at all, so the body is empty/generic).

**Pipeline errors** — the most carefully handled case. `src/pipeline/orchestrator.py` has **three nested levels** of exception handling:
1. Innermost: AI generation + lint failures → downgrades to `PARTIAL`, preserves risk/intel.
2. Outermost: anything else (normalizer crash, risk engine crash, unexpected exception) → downgrades to `FAILED`, still writes a result file with whatever partial data exists (or a placeholder `NormalizedAlert` if normalization itself never completed).
3. The background task wrapper (`run_pipeline_task` in `webhook.py`) has its own top-level `try/except` that logs `background_pipeline_uncaught_error` — a final safety net so an unhandled exception in the orchestrator can never crash the whole server process (FastAPI background tasks that raise would otherwise produce an unhandled-exception log from the ASGI server, but here it's already caught).

**Threat-intel errors** — never propagate. Every provider's `query()` call is wrapped in `asyncio.wait_for(...)` inside `try/except` in `aggregator.py`; a timeout or exception becomes `VirusTotalResult(status="UNKNOWN", error=...)` rather than failing the alert.

**Email handoff errors** — classified as `retryable` vs not (`DeliveryResult.retryable`). `src/services/email_delivery/eset_mail.py: _interpret()` treats HTTP 400 as never-retryable (the request itself is malformed — retrying identical input fails identically) and HTTP 401 as non-retryable **unless** the rejection reason mentions "nonce" (a nonce-replay rejection is inherently transient since a fresh nonce is generated per attempt). Everything else defaults to retryable. `src/services/email_dispatcher.py: _hand_off()` decides the final outcome: `accepted` / `failed` (permanent or attempts exhausted) / left-queued-for-retry.

**Frontend errors:**
```
static/dashboard.js: api(path, opts)
    → fetch()
    → if res.status === 401: lock() [clears session, shows login] + throw
    → if !res.ok: parse response body's `.detail`, throw new Error(detail)
    → callers wrap this in try/catch and call toast(msg, true) to show a red toast notification
```
Most read-only `loadX()` functions (`loadStats`, `loadLogs`, `loadAiContent`, `loadSettings`) **silently swallow** fetch errors (`catch (e) { /* handled */ }` or `/* auth handled upstream */`) — a failed background refresh doesn't disrupt the UI, it just leaves stale data on screen. Mutating actions (retry, discard email, save recipients, dispatch now) **do** show a `toast()` on failure.

### What reaches the frontend / what the user sees

- A hard pipeline failure never reaches the browser as an HTTP error — it reaches it as a `FAILED` badge on a row in the Alerts table (pushed live via the `job_status_changed` WebSocket event), with the `error` text visible in the Alert Detail modal.
- A dashboard API call failure (e.g. wrong key, or a transient network blip) shows either the login screen again (on 401) or a toast (on mutation failure) or nothing at all (on a background refresh failure).

### Weak or inconsistent error handling — confirmed observations

- `POST /webhook/*` returns HTTP 200 even for a parse error (`{"status": "error", ...}`) — inconsistent with HTTP semantics; a caller relying on status codes alone would misinterpret this as success. **Confirmed** by reading `src/api/webhook.py: ingest_alert()`.
- `email_composer.compose_emails()` logs a warning (`email_composer_no_recipients_configured`) per notification type with no recipients, but this is easy to miss unless someone is actively watching the Logs tab — there's no dashboard-visible alert for "this alert type generates zero emails because nothing is configured."
- `src/storage/deduplication.py: cleanup_expired()` is dead code (never invoked) — not an error-handling bug per se, but means the `dedup_log` table has no automatic pruning, which will eventually (very slowly) bloat the SQLite file. **Confirmed** via repo-wide search — no caller exists.

---

## 13. Security Audit

*Code-level review only. No changes were made to the application during this audit.*

### Confirmed observations

**1. Dashboard access key defaults to a documented, well-known placeholder.**
- Severity: **High** (if left unchanged in a real deployment)
- Location: README.md states the default is `123456`; `.env.example` ships with `DASHBOARD_ACCESS_KEY=` blank, but the README explicitly documents `123456` as "currently" the key and instructs changing it.
- Why it matters: the dashboard exposes hostnames, usernames, file paths, hashes, and internal IPs from every ingested alert, and can trigger retries and email deletions.
- Current behavior: with a blank key, auth is disabled entirely (by design, for local trusted use); the app logs a warning at startup if bound non-locally with no key.
- Recommendation: this is already correctly flagged in the README's own "Security notes" section — the code behavior matches the documented risk. No code change needed; this is an *operational* configuration risk, not a code defect.

**2. No rate limiting on ingest endpoints.**
- Severity: Medium (informational — already documented by the project itself)
- Location: `src/api/webhook.py` — no rate limiter, no per-IP throttling.
- Why it matters: a flood of requests would consume Gemini API quota (cost) and threat-intel API quota, and could exhaust background-task capacity.
- Current behavior: every valid-token request is queued for processing unconditionally (after dedup).
- Recommendation: README already recommends a reverse-proxy-level limiter for internet-facing deployments. **Potential concern**, not a code bug — this is explicitly out of scope by design (single-tenant internal tool assumption).

**3. `/health` is unauthenticated and confirms the service's existence/subsystem state to anyone.**
- Severity: Low/Informational
- Location: `src/api/health.py`
- Why it matters: an unauthenticated actor can fingerprint that this specific service is running and see coarse subsystem health (DB up/down, Gemini configured, syslog listeners up/down) without any credentials.
- Current behavior: intentional — README explicitly notes this trade-off ("`/health` will confirm the service exists").
- Recommendation: acceptable for the stated threat model; flagging as informational only.

**4. `/status/{correlation_id}` is unauthenticated, gated only by UUID unguessability.**
- Severity: Informational
- Location: `src/api/status.py`
- Why it matters: anyone who obtains/guesses a valid correlation_id (128-bit UUID4, so guessing is infeasible) can see that job's status/metadata, including the raw output file *path* (not its content) if completed.
- Current behavior: matches README's documented trade-off exactly.

**5. `EsetRawPayload` accepts arbitrary extra fields (`extra: "allow"`).**
- Severity: Informational
- Location: `src/models/raw_payload.py`
- Why it matters: a malicious or malformed sender can submit arbitrarily large/nested extra JSON, all of which is preserved in `raw_payload` and later embedded in the AI prompt (`alert.model_dump(exclude={"raw_payload"})` — wait, note: the AI prompt build in `gemini_service.py` explicitly excludes `raw_payload`, so extra fields do **not** reach the AI prompt directly, only the *mapped* `NormalizedAlert` fields do). There is no explicit payload size cap observed anywhere in the ingestion path (FastAPI/Uvicorn has implicit limits, but none are configured explicitly in this codebase).
- Current behavior: extra fields are stored (in the `jobs.raw_payload` column and the alert's own `raw_payload` field) but not used in prompting.
- Recommendation: **Potential concern** — consider an explicit request body size limit for defense-in-depth on an internet-facing deployment. Not currently configured anywhere in the codebase (`UNKNOWN` whether Uvicorn's defaults are relied upon).

**6. XSS defense is a manually-maintained escaping discipline, not automatic (vanilla-JS frontend).**
- Severity: Low (mitigated by tests, but structurally fragile)
- Location: `static/dashboard.js`, `static/dashboard-viz.js`
- Why it matters: because there's no framework auto-escaping (unlike React's JSX), every new `innerHTML` interpolation of alert-derived data is a potential stored-XSS vector if a developer forgets `esc()`.
- Current behavior: `esc()` is applied consistently today, and `tests/integration/test_security.py` + `tests/integration/test_dashboard_controls.py` grep the source for a fixed list of known-dangerous unescaped patterns as a regression guard.
- Recommendation: **Confirmed as currently correct**, but flagged because the guard is a source-grep against a *fixed token list* — a genuinely new field added without an accompanying new grep assertion could slip through unnoticed by the existing tests. This is a structural fragility, not a live vulnerability.

**7. CSWSH (Cross-Site WebSocket Hijacking) is explicitly defended.**
- Severity: N/A — this is a confirmed *mitigation*, listed for completeness.
- Location: `src/api/dashboard.py: _origin_allowed()`
- Current behavior: rejects any WebSocket handshake whose `Origin` header doesn't match the `Host` header, closing with code `4403`. Verified by `tests/integration/test_security.py: test_ws_rejects_cross_origin` / `test_ws_allows_same_origin`.

**8. Webhook and dashboard secrets use constant-time comparison.**
- Severity: N/A — confirmed mitigation.
- Location: `src/middleware/auth.py`, `src/api/dashboard.py: _check_access()` — both use `hmac.compare_digest()`.

**9. Outbound email-delivery signing (HMAC) is correctly scoped to the exact transmitted bytes.**
- Severity: N/A — confirmed mitigation, but worth understanding.
- Location: `src/services/email_delivery/eset_mail.py: build_request()`. The docstring and code explicitly avoid re-serializing JSON after hashing (`content=body_bytes` is sent, not `json=payload`, specifically so `httpx` doesn't re-encode and invalidate the signature). This is a subtle but important correctness property for HMAC-signed requests generally.

**10. No secrets are logged in plaintext (spot-checked).**
- Severity: N/A — informational, could not exhaustively verify every log call.
- Observation: `structlog` calls throughout consistently log identifiers (correlation_id, email_id, client_ip) and error *messages*, not raw tokens/keys. `EMAIL_API_SECRET` is explicitly documented as "never transmitted" (used only for HMAC signing locally). No `logger.info(..., api_key=...)` or similar pattern was found in the reviewed files. **Not exhaustively verified** across every third-party library's own logging (e.g. `httpx`/`google-generativeai` internals) — `UNKNOWN` whether those libraries could log request bodies at debug level.

**11. AI safety lint is a keyword blocklist, not semantic verification.**
- Severity: Informational (design limitation, not a security bug)
- Location: `src/services/ai/lint_checker.py: PROHIBITED_PHRASES`
- Why it matters: the lint only catches the *exact* prohibited phrases listed (in English and Japanese). A model that phrases an equivalent claim differently (e.g. "the endpoint is now clean" instead of "infection confirmed") would not be caught.
- Current behavior: correctly documented as a lint, not a semantic guarantee — the system prompt (`src/prompts/system_prompts.py`) is the primary defense; the lint is a secondary net.
- Recommendation: **Potential concern**, inherent to any keyword-based approach; flagged for awareness, not as a defect.

### No SQL injection risk found
Every SQL statement across `src/storage/*.py` uses parameterized queries (`?` placeholders with a tuple/list of params) — no string interpolation into SQL was found anywhere in the codebase.

### No insecure deserialization found
All external JSON parsing goes through Pydantic model validation (`EsetRawPayload(**data)`, `AIOutput.model_validate_json(...)`), which rejects malformed/unexpected shapes rather than executing arbitrary code.

---

## 14. Testing

**Framework:** `pytest` + `pytest-asyncio` (configured `asyncio_mode = "auto"` in `pyproject.toml`, so `async def test_...` functions work without `@pytest.mark.asyncio` in most cases — though some tests still use the decorator explicitly, which is harmless/redundant under `auto` mode).

**Run command** (from README, verified against `pyproject.toml`'s `testpaths = ["tests"]`):
```bash
PYTHONPATH=. .venv/bin/pytest tests/ -v
```

### Structure

```
tests/
├── conftest.py                # Shared fixtures — see below, this is the most important file to read first
├── fixtures/*.json             # Sample payloads (low/medium/high/critical risk, syslog format)
├── unit/                       # No HTTP client, test pure functions directly
│   ├── test_risk_engine.py       # All severity/handled/isolated combinations of compute_risk()
│   ├── test_normalizer.py        # raw → NormalizedAlert field mapping + "UNKNOWN" fallback
│   ├── test_deduplication.py     # is_duplicate/record_seen/cleanup_expired against real (temp) SQLite
│   ├── test_lint_checker.py      # English + Japanese prohibited-phrase detection
│   ├── test_schema_builder.py    # Regression guard for the Gemini `required`-array bug (see §24)
│   ├── test_email_composer.py    # Email composition, recipient handling, outbox persistence, HMAC signing
│   └── test_schemas.py           # Basic Pydantic model default-value sanity checks
└── integration/                # Uses FastAPI's TestClient — real HTTP, real (temp) SQLite, real (temp) files
    ├── test_webhook_endpoint.py    # Basic ingest auth + success + duplicate flow
    ├── test_syslog_handler.py      # Syslog-format payload → webhook route
    ├── test_full_pipeline.py       # End-to-end orchestrator run, asserts output file + index.json content
    ├── test_dashboard_api.py       # jobs/alerts/emails/retry/websocket + root/static/health routes
    ├── test_dashboard_controls.py  # settings, stats, logs, ai-content, outbox mutation
    └── test_security.py            # Auth enforcement, WS origin/key checks, XSS-safe rendering (source greps)
```

### Critical fixture behavior (`tests/conftest.py`)

- **All persistent state is redirected to temp locations before any app module is imported**, via direct mutation of `settings.sqlite_db_path`, `settings.output_dir`, `settings.eset_webhook_auth_token`, `settings.dashboard_access_key` **at module import time**, before `from src.main import app`. This is necessary because several modules (`email_outbox.py`) capture path constants at import time (`OUTBOX_DIR`/`OUTBOX_PATH`), so `conftest.py` explicitly patches those module attributes too, right after import.
- `mock_gemini` fixture (`autouse=True`) — **every test automatically gets Gemini calls replaced** with a deterministic mock via `monkeypatch.setattr(GeminiAIService, "generate", mock_generate)`. **No test ever makes a real network call to Google.** This means `pipeline_status` almost always ends up `SUCCESS` in tests unless a test deliberately forces a failure.
- `clean_database`/`clean_output_dirs` fixtures (`autouse=True`) wipe state **between every single test** — tests are fully isolated from each other, order-independent.
- FastAPI's `TestClient` runs background tasks **synchronously within the request** (a `TestClient` behavior), which is why `test_dashboard_api.py: test_job_detail_includes_pipeline_result` can assert `detail["result"] is not None` immediately after posting — in production, this would require polling/waiting for the background task.

### What is tested

- ✅ Risk engine: all severity × handled × isolated combinations, plus unknown-severity fallback.
- ✅ Normalizer: raw → strict alert mapping, "UNKNOWN" defaults.
- ✅ Deduplication: real TTL expiry behavior against a temp SQLite DB.
- ✅ AI safety lint: English and Japanese prohibited phrases.
- ✅ Gemini schema builder: the exact `required`-field-preservation bug this module exists to fix (a genuinely excellent regression test — see `test_sdk_native_conversion_still_drops_required`, which asserts the *raw SDK* still has the bug it's working around, so if Google ever fixes it upstream, this test starts failing and tells you the workaround can be removed).
- ✅ Email composition: per-notification-type recipient handling, subject formatting, outbox round-trip, corrupt-file recovery, HMAC request signing.
- ✅ Full pipeline: end-to-end orchestrator run with real (temp) file/DB output verification.
- ✅ Every dashboard REST route + the WebSocket event stream (including asserting stage-ordering guarantees).
- ✅ Auth: webhook token (missing/wrong/near-miss/whitespace-tolerant), dashboard key (per-route enforcement), WS origin + key.
- ✅ XSS: both a data round-trip check (API must not render HTML) and a static-analysis-style source grep for unescaped patterns.

### What is NOT tested (confirmed gaps)

- ❌ **Real threat-intel API calls** (`_query_real()` in `virustotal.py`/`abuseipdb.py`) — only the mock path (`_query_mock()`) is exercised anywhere, since `settings.use_mock_threat_intel` defaults to `True` and no test flips it. The real-API code paths are **entirely unverified by the test suite**.
- ❌ **Real Gemini API behavior** — `mock_gemini` replaces `generate()` entirely; the actual prompt construction → Gemini call → response parsing round-trip against a live model is never exercised in CI/tests.
- ❌ **The syslog UDP/TCP listeners themselves** (`src/services/syslog_runtime.py`) — no test binds a real socket and sends a packet through `UDPProtocol`/`handle_tcp_client`. Only the *downstream* HTTP route they forward to (`/webhook/syslog`) is tested directly.
- ❌ **`email_dispatcher.run_dispatch_loop()`** (the periodic sweeper) — no test exercises the actual `while True: sleep; dispatch_pending()` loop; only `dispatch_pending()` itself is indirectly covered via other tests. **UNKNOWN** whether `dispatch_pending()` has direct dedicated unit tests — a search shows it's exercised indirectly through dashboard controls tests (`/delivery/dispatch` route) but not with a dedicated `test_email_dispatcher.py` file (no such file exists in `tests/unit/` or `tests/integration/`).
- ❌ **Crash recovery** (`recover_unfinished_jobs()` in `main.py`) — not exercised by any test; `TestClient` in tests doesn't leave jobs in `PENDING`/`PROCESSING` state across restarts in a way any test simulates.
- ❌ **`src/storage/deduplication.py: cleanup_expired()`** in the context of it never being called — the function itself is tested in isolation (`test_deduplication.py`), but there's no test confirming/denying that it's actually invoked anywhere in the running app (it isn't — confirmed by source search).
- ❌ **The standalone `syslog_server/server.py` process** — not imported or tested anywhere; it's a legacy alternate entrypoint (see §24).

### Testing confidence assessment

**High confidence** in: request/response contracts of every HTTP+WS route, the deterministic risk-scoring logic, the AI-output safety lint, the Gemini schema-generation workaround, email composition/outbox mechanics, and the frontend's XSS-escaping discipline.

**Low/no confidence** in: real third-party API integrations (VirusTotal, AbuseIPDB, live Gemini, live ESET Mail worker), the raw syslog network listeners, the background sweep loop's long-running behavior, and crash-recovery correctness. These are exactly the areas where **manual testing** (`scripts/send_test_syslog.py`, `scripts/send_test_webhook.sh`) is the only current safety net.

---

## 15. Build + Running the Application

There is no separate "build" step (no bundler, no compiled assets, no Docker image defined in-repo).

```bash
# ---- Prerequisites ----
# Python 3.11+ (required by pyproject.toml: requires-python = ">=3.11")

# ---- Installation ----
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"        # installs runtime + dev (pytest) deps, editable mode

# ---- Environment setup ----
cp .env.example .env
# edit .env: fill in GEMINI_API_KEY, ESET_WEBHOOK_AUTH_TOKEN, notification recipients

# ---- Database setup ----
# Nothing manual — init_db() runs automatically in src/main.py's lifespan on first start,
# creating data/soc_lite.db and all four tables if they don't exist yet.

# ---- Start everything (API + dashboard + syslog listeners, one process) ----
.venv/bin/python run.py
# Open http://localhost:8000/ for the dashboard.
# Binding UDP/TCP ports 514/601 requires root; without it, the process still starts —
# syslog listeners just log a warning and stay down (webhook ingestion is unaffected).
# For local dev without sudo: set SYSLOG_UDP_PORT=1514 / SYSLOG_TCP_PORT=1601 in .env.

# ---- Testing ----
PYTHONPATH=. .venv/bin/pytest tests/ -v

# ---- Manual smoke test (optional, separate terminal) ----
scripts/send_test_webhook.sh              # fires low/medium/high/critical sample alerts
scripts/send_test_syslog.py --severity HIGH   # fires one alert via the UDP syslog listener

# ---- Production build ----
# No separate "build" artifact — the same `run.py` command (or supervisord, see §16)
# is used in production. There is no minification/bundling of static/*.js since there's
# no framework requiring one.
```

**Single-process, multi-terminal note:** unlike a typical "run backend in one terminal, frontend dev server in another" setup, **this app needs exactly one terminal/process** — `run.py` starts the API, dashboard, and syslog listeners together. The only reason to run a second terminal is to send test traffic (`scripts/*`) or run the test suite.

---

## 16. Deployment

**Confirmed from the repository:** there is **no** CI/CD pipeline configuration (no `.github/workflows/`), **no** Dockerfile, **no** `docker-compose.yml`, **no** Vercel/Netlify/Render/Railway config files anywhere in the repo.

The only deployment-related artifact is **`supervisord.conf`**, which defines two managed processes:

```ini
[program:api]
command=.venv/bin/uvicorn src.main:app --host %(ENV_APP_HOST)s --port %(ENV_APP_PORT)s
autostart=true
autorestart=true

[program:syslog_server]
command=.venv/bin/python -m syslog_server.server
autostart=true
autorestart=true
```

This is a **notable inconsistency worth understanding**: `supervisord.conf` runs the API (`uvicorn src.main:app`) and the standalone `syslog_server/server.py` process **separately**, whereas `run.py` (the README's documented, recommended path) runs everything in **one** process, with the syslog listeners embedded via `src/services/syslog_runtime.py`. Both `src.main`'s `lifespan()` *and* `syslog_server/server.py`'s `main()` independently call `syslog_runtime.start()` — under `supervisord.conf`, this means **two separate processes would each try to bind the same UDP/TCP ports**, which would fail for the second one to start (port already in use). This strongly suggests `supervisord.conf` predates the embedding of syslog listeners into the main process and **may be stale** relative to the current, documented `run.py`-based architecture (see §24/§25 for more).

**Actual deployment flow, as far as the code shows:**
```
Code checked out on a server
  ↓
python3 -m venv .venv; pip install -e ".[dev]"
  ↓
.env configured with real secrets
  ↓
EITHER: `python run.py` directly (foreground/behind a process manager of the operator's choosing)
     OR: `supervisord -c supervisord.conf` (but see the port-conflict caveat above — likely needs
         the syslog_server program removed/disabled if using the embedded run.py-style process)
  ↓
Reverse proxy (TLS termination) — recommended by README, not configured in this repo
  ↓
Running application, logs to logs/app.log + logs/app.err.log (or logs/supervisord.log under supervisord)
```

**Environment variables in deployment:** same `.env` mechanism as local dev — `src/config.py` reads `.env` or process environment variables identically regardless of how the process is launched.

**UNKNOWN:** whether this project is deployed via any specific cloud service, container platform, or orchestrator — no such configuration exists in the repository to confirm or deny.

---

## 17. Git + Branching

- **Main branch:** `main` (also the remote's default/HEAD).
- **No other branches exist** in this checkout (`git branch -a` shows only `main` and `remotes/origin/main`).
- **Full commit history (3 commits total, all by the same author `Rishi-Bhati`):**
  1. `145a13a` — *"Initial commit of ESET SOC Lite Webhook Ingress & Analysis Service"* — the original pipeline: ingestion, models, risk engine, threat intel, AI service, output writer, SQLite job/dedup storage, syslog server, initial test suite. **No dashboard existed yet** in this commit (no `src/api/dashboard.py`, no `static/`).
  2. `cd76ab3` — *"Add comprehensive tests for dashboard API, controls, security, email composer, and schema builder"* — this is actually the commit that **introduces the entire dashboard** (`src/api/dashboard.py`, all of `static/`), the entire email-delivery subsystem (`src/services/email_delivery/`, `email_composer.py`, `email_outbox.py`, `email_dispatcher.py`), `settings_store.py`, `delivery_store.py`, the shared `events.py`/`broadcaster.py` event bus, and embeds the syslog listeners into the main process (`syslog_runtime.py`) — despite the commit message emphasizing "tests," this is the single largest functional commit in the repo's history.
  3. `74f3ab8` — *"Enhance email delivery with idempotency key and increase timeout for reliability"* — small, targeted: adds the `email_id` idempotency key to the ESET Mail handoff payload, raises the default `EMAIL_TIMEOUT_SECONDS` from 15 to 60.
- **Development pattern observed:** this is a young, single-developer project with large, feature-complete commits rather than many small incremental ones. There is no evidence of a PR-based workflow, feature branches, or a release-tagging scheme in the current history.

---

## 18. Feature-to-File Map

| Feature | Frontend | Backend (API) | Backend (Service/Logic) | Storage | Other |
|---|---|---|---|---|---|
| **Alert ingestion (webhook)** | Alerts tab renders results | `src/api/webhook.py` | `src/ingestion/webhook_handler.py`, `src/middleware/auth.py` | `jobs`, `dedup_log` tables | `scripts/send_test_webhook.sh` |
| **Alert ingestion (syslog)** | same | `src/api/webhook.py` (`/webhook/syslog`) | `src/ingestion/syslog_handler.py`, `src/services/syslog_runtime.py` (UDP/TCP), `syslog_server/server.py` (standalone alt) | same | `scripts/send_test_syslog.py` |
| **Deduplication** | — (invisible to UI) | `src/api/webhook.py: compute_dedup_key()` | `src/storage/deduplication.py` | `dedup_log` table | — |
| **Normalization** | Alert Detail modal shows normalized fields | — | `src/services/normalizer.py` | `NormalizedAlert` embedded in result JSON | `src/models/normalized_alert.py` |
| **Risk scoring** | Risk badge everywhere; Overview "Risk Distribution" chart | — | `src/services/risk_engine.py` | risk fields in result JSON + `index.json` | — |
| **Threat intelligence** | Alert Detail modal's VirusTotal/AbuseIPDB boxes | — | `src/services/threat_intel/{aggregator,virustotal,abuseipdb}.py` | embedded in result JSON | — |
| **AI notification generation** | AI Content tab, Alert Detail modal's notification tabs | — | `src/services/ai/{gemini_service,schema_builder}.py`, `src/prompts/system_prompts.py` | embedded in result JSON | `src/models/ai_output.py` |
| **Safety linting** | Flow tab's LINT stage node | — | `src/services/ai/lint_checker.py` | — | — |
| **Result persistence** | Alerts tab (via `index.json`), Alert Detail modal | `src/api/dashboard.py: get_job_detail/get_alerts` | `src/services/output_writer.py` | `output/alerts/*.json`, `index.json` | — |
| **Job/pipeline orchestration** | Flow tab (all 9 stages) | — | `src/pipeline/orchestrator.py` | `jobs` table | `src/utils/events.py` |
| **Pipeline retry** | "Retry" button on Alerts tab | `src/api/dashboard.py: retry_job()` | reuses `src/api/webhook.py: run_pipeline_task` | `jobs` table (status reset to PENDING) | — |
| **Crash recovery** | — (invisible) | — | `src/main.py: recover_unfinished_jobs()` | `jobs` table | — |
| **Live dashboard updates** | WebSocket handling in `dashboard.js`/`dashboard-viz.js` | `src/api/dashboard.py: dashboard_ws()` | `src/utils/{events,broadcaster}.py` | — | — |
| **Email composition** | Alert's notification content shown pre-send | — | `src/services/email_composer.py` | — | `src/models/email_message.py` |
| **Email outbox** | Emails tab's "Awaiting Handoff" table | `src/api/dashboard.py: get_emails/delete_email` | `src/services/email_outbox.py` | `output/emails/outbox.json` + `email_deliveries` table | — |
| **Email handoff/delivery** | Emails tab's "Mail Delivery" + "Handoff History" panels | `src/api/dashboard.py: get_delivery_overview, get_mail_service_status, trigger_dispatch` | `src/services/email_dispatcher.py`, `src/services/email_delivery/{base,eset_mail}.py` | `email_deliveries` table | — |
| **Recipient configuration** | Settings tab | `src/api/dashboard.py: get_settings, update_recipients` | `src/storage/settings_store.py` | `app_settings` table (overrides) + `.env` (fallback) | — |
| **Structured logging + Logs tab** | Logs tab | `src/api/dashboard.py: get_logs()` | `src/utils/logging.py` | `logs/app.log` (flat file, tailed) | — |
| **Dashboard auth** | Login screen (`dashboard.js`) | `src/api/dashboard.py: _check_access()` | — | — | `.env: DASHBOARD_ACCESS_KEY` |
| **Ingest auth** | — | `src/middleware/auth.py` | — | — | `.env: ESET_WEBHOOK_AUTH_TOKEN` |
| **Health check** | Health-status dots in dashboard header | `src/api/health.py` | — | — | — |
| **Job status polling** | — (sender-facing, not dashboard) | `src/api/status.py` | — | `jobs` table | — |
| **Charts (Overview tab)** | `static/dashboard-viz.js: drawSeries/Risk/Status/Source` | `src/api/dashboard.py: get_stats()` | aggregation logic inline in `get_stats()` | reads `jobs` table + result files | — |

---

## 19. Change Impact Guide — "Where Do I Go?"

### "I want to change a button" (e.g. the "Send queued now" button)
Find it in `static/dashboard.html` (its markup, e.g. `<button ... id="dispatchNow">`), then its click handler in `static/dashboard.js` (`document.getElementById("dispatchNow").onclick = ...`). Styling is in the `<style>` block of `dashboard.html` (search for the relevant class, e.g. `button.primary`).

### "I want to change a page" (e.g. add a column to the Alerts table)
1. Edit the `<table><thead>` markup in `static/dashboard.html` under `<section class="view" id="view-alerts">`.
2. Edit the row-generation template literal in `renderAlerts()` in `static/dashboard.js` to add the matching `<td>`.
3. If the new column needs data not already in `state.jobs` entries, trace back to where jobs are populated: `jobFromRow()` (from `GET /dashboard/api/jobs`) and `handleEvent()`'s `job_status_changed`/`alert_completed` cases (from the WebSocket). You may need to add the field to `src/api/dashboard.py: get_jobs()`'s response or to the relevant WebSocket event payload in `src/storage/job_store.py` / `src/services/output_writer.py`.
4. **Remember `esc()`** on any new interpolated value (see §5's security note).

### "I want to add a field to the alert (e.g. a new `mitre_technique` field from ESET)"
1. `src/models/raw_payload.py` — add `mitre_technique: str | None = Field(default=None)` to `EsetRawPayload`.
2. `src/models/normalized_alert.py` — add `mitre_technique: str = Field(default="UNKNOWN")` to `NormalizedAlert`.
3. `src/services/normalizer.py` — add the mapping line: `data["mitre_technique"] = raw.mitre_technique or "UNKNOWN"`.
4. `src/ingestion/syslog_handler.py` — if syslog exports use a different key name for the same concept, add it to the `mapped = {...}` dict.
5. Optionally, `src/services/risk_engine.py` if this field should influence risk scoring.
6. Optionally, `src/prompts/system_prompts.py` if the AI should reference it explicitly (it will already see it via `alert.model_dump()` in the prompt, but the system prompt may need updating to tell the AI what to *do* with it).
7. Optionally, `static/dashboard.js: openAlert()` to display it in the Alert Detail modal.
8. Add/update a test in `tests/unit/test_normalizer.py` and possibly `tests/fixtures/*.json`.

### "I want to add a new API endpoint"
1. Decide which router it belongs in: `src/api/webhook.py` (ingest), `src/api/dashboard.py` (operator surface), or a new file registered in `src/api/router.py`.
2. Write the route function. If it's a dashboard route, **call `_check_access(request)` as the first line** — this is not automatic (see §26).
3. If it needs new business logic, add a function to the relevant `src/services/*.py` module (don't put business logic directly in the route function beyond thin orchestration).
4. If it needs new persistence, add functions to a `src/storage/*.py` module (or a new one), and update `init_db()` in `src/storage/database.py` if a new table/column is needed.
5. Add a test in `tests/integration/`.
6. If the dashboard UI should surface it, update `static/dashboard.js`'s `api()`-calling code and the relevant `render*()` function, and add a row to the "Dashboard API" reference table on the API Docs tab (`renderApiDocs()`'s `routes` array).

### "I want to change authentication"
- **Ingest token logic:** `src/middleware/auth.py: validate_eset_token()`. Also check `tests/integration/test_security.py` (ingest-auth section) and update it.
- **Dashboard key logic:** `_check_access()` in `src/api/dashboard.py` (REST) and the inline key check inside `dashboard_ws()` (WebSocket) — **these are two separate implementations of the same idea**; changing one without the other will desync REST and WS auth behavior.
- **Frontend login UX:** `static/dashboard.html: #login`, `static/dashboard.js: attemptLogin()`, `lock()`.
- If you're adding a *new* kind of credential (e.g. per-client webhook tokens), you'd need: a new storage table (or extend `app_settings`), a new lookup in `validate_eset_token()` (currently a single hardcoded `settings.eset_webhook_auth_token` comparison), and likely a way to associate incoming alerts with which client sent them.

### "I want to change the database schema"
1. Edit the `CREATE TABLE` DDL in `src/storage/database.py: init_db()`.
2. **Remember there is no migration system** — `CREATE TABLE IF NOT EXISTS` won't alter an existing table. For an already-running deployment you'd need a manual `ALTER TABLE` (via a one-off script) or to delete/recreate `data/soc_lite.db` (losing history).
3. Update the relevant `src/storage/*.py` module's queries (column lists, `INSERT`/`SELECT` statements, and the row-to-dict mapping functions like `_row()` in `delivery_store.py`).
4. Update any dashboard API route that surfaces the new/changed column (`src/api/dashboard.py`).
5. Update the frontend if the new data should be visible (`static/dashboard.js`).
6. Update/add tests.

### "I want to change how data is displayed" (e.g. change the risk-distribution chart from a bar chart to a pie chart)
- Data **originates** in `src/api/dashboard.py: get_stats()` (the `by_risk` counter, built by scanning result JSON files via `_read_results()`).
- Data is **consumed** by `static/dashboard.js: loadStats()` → passed to `drawRisk(state.stats.by_risk)` in `static/dashboard-viz.js`.
- To change the visualization, you'd rewrite `drawRisk()` (and possibly the shared `drawBars()` helper it currently calls) — the backend response shape (`{"LOW": n, "MEDIUM": n, ...}`) likely wouldn't need to change for a chart-type swap.

### "I get a frontend error"
See the Debugging Playbook (§20) — start with browser devtools console + Network tab, check whether it's a WebSocket issue or a REST fetch issue, then trace back through `api()` in `dashboard.js` to the specific backend route.

### "I get a backend error"
Check `logs/app.log` (structured JSON — searchable, and also viewable live in the dashboard's Logs tab) for the `correlation_id` involved. Structlog's `correlation_id` context var (set via `src/utils/correlation.py: set_correlation_id()`) is bound to every log line emitted during that request/pipeline run, so grep by correlation_id to see the entire lifecycle of one alert.

### "An API is returning the wrong data"
1. Identify the exact route in `src/api/*.py`.
2. Check whether it reads from SQLite (`src/storage/*.py`) or from JSON files (`src/services/output_writer.py`'s `output/alerts/*.json` + `index.json`, or `src/services/email_outbox.py`'s `outbox.json`) — these are two different sources of truth and can drift if one write path fails while the other succeeds (see §25).
3. For SQLite-backed routes, you can inspect `data/soc_lite.db` directly with any SQLite browser/CLI to see ground truth.
4. For file-backed routes, the files are human-readable JSON — open them directly in `output/alerts/` or `output/emails/`.

---

## 20. Debugging Playbook

### General frontend problem

```
UI shows wrong/missing data
 ↓
Open browser devtools → Console tab: any JS errors? (a thrown error in a render function
   can silently break subsequent renders since there's no error boundary)
 ↓
Network tab: is the relevant /dashboard/api/* fetch firing? What status code / body?
 ↓
   401? → dashboard key issue. Check sessionStorage.dash_key vs. the server's
          DASHBOARD_ACCESS_KEY. Try `lock()` (click "Lock dashboard") and log back in.
   404? → wrong route, or the record genuinely doesn't exist (e.g. retry on unknown id)
   200 but wrong body? → the bug is server-side; move to the backend playbook below
 ↓
Is the WebSocket connected? Check the header pill — "live" (green pulsing dot) vs
   "reconnecting…" (red dot). If reconnecting, check server logs for why the process
   might have dropped the connection (restart? crash? auth mismatch on ?key=...?).
 ↓
If data looks right in the Network tab response but wrong on screen: the bug is in a
   render*() function or in state mutation logic (upsertJob, applyStage, etc.) — add a
   `console.log(state)` at the point of interest, or a debugger breakpoint in the
   relevant render function.
```

### General backend problem

```
Something processed incorrectly / an alert is stuck / an email didn't go out
 ↓
Find the correlation_id: from the Alerts tab (shortId column, hover/click for full id),
   or from the API response of the original POST /webhook/* call.
 ↓
Check job status: GET /status/{correlation_id}  or  GET /dashboard/api/jobs/{correlation_id}
 ↓
Grep logs/app.log for that correlation_id (or use the dashboard's Logs tab search box) —
   structlog binds correlation_id to every log line for that request via ContextVar, so this
   gives you the FULL chronological trace of what happened: which pipeline stage ran, what
   each service returned, and exactly where/why it failed if it did.
 ↓
Cross-reference with the pipeline_stage events for that run: Flow tab (if still in the
   MAX_LANES=7 most-recent window) or reconstruct from the log lines
   (event="pipeline_stage"? — actually pipeline_stage events aren't logged as such directly;
   the STAGE-specific log events like "pipeline_ai_phase_failed" are what to search for).
 ↓
If status is PENDING/PROCESSING and stuck (never finished): check if the process crashed/
   restarted (crash recovery should have re-queued it — check for a
   "recovery_retriggering_job" log line with that correlation_id). If not, check for a
   deadlock/hang — Python's single-process model means one stuck async call (e.g. a hung
   HTTP call to Gemini or a threat-intel API without proper timeout coverage) blocks
   everything downstream in that same alert's pipeline run (other alerts' pipelines are
   independent async tasks and are NOT blocked by one hung task, but the WHOLE PROCESS is
   blocked if something truly synchronous/CPU-bound hangs, since it's one event loop).
 ↓
If status is FAILED/PARTIAL: read the `error` field (dashboard job detail, or the `error`
   key in the result JSON file at output/alerts/{correlation_id}.json) — this is the
   original exception message, verbatim.
 ↓
If the alert never appears at all: check ingest auth (was the token correct? 401 in
   server logs under "auth_failed_*"), or check deduplication (was it silently dropped as
   a duplicate? look for "ingest_duplicate_dropped" in logs), or check whether the
   syslog listener even received it (for UDP/TCP path) — "syslog_udp_no_json"/
   "syslog_tcp_no_json" means the JSON-extraction regex in syslog_runtime.py found no
   embedded JSON object in the frame.
```

### Common failure patterns discovered in this repository (from the code, not speculation)

1. **Gemini schema `required` fields silently dropped** — already fixed and guarded by `schema_builder.py` + `test_schema_builder.py`, but if you ever bypass `build_gemini_schema()` and pass a raw Pydantic class as `response_schema` again, you'll reintroduce alerts silently going to `PARTIAL` because Gemini returns near-empty JSON that fails validation. **This is the single most well-documented historical bug in the codebase** (see the module docstring in `src/services/ai/schema_builder.py`).
2. **Privileged-port binding failure** — `SYSLOG_UDP_PORT=514`/`SYSLOG_TCP_PORT=601` require root. Without it, `syslog_runtime.start()` logs `syslog_udp_permission_denied`/`syslog_tcp_permission_denied` (critical level) but **does not crash the process** — webhook ingestion keeps working, only the syslog *network* path is down. A common local-dev confusion is "why isn't my syslog test script working" — check the startup logs for these specific warnings first.
3. **Two independent syslog-embedding code paths** (`src/services/syslog_runtime.py` called from both `src/main.py`'s lifespan *and* `syslog_server/server.py`'s standalone `main()`) — running both at once (e.g. via `supervisord.conf` alongside `run.py`) causes a port-bind conflict. See §16/§24.
4. **Email composed but never sent** — check `EMAIL_DELIVERY_ENABLED` (defaults `false`!). If disabled, emails sit in `outbox.json` forever (by design) until enabled, since `dispatch_pending()`'s first check is `if not settings.email_delivery_enabled: return {"skipped": "delivery disabled", ...}`.

### Adapted flow diagram (this app's actual layers)

```
UI problem?
 ↓
Is the component rendering? (check console for JS errors)
 ↓
Is state correct? (inspect `state` object, or the WS message that should have updated it)
 ↓
Is the event firing? (button onclick wired? check Network tab for the outgoing fetch)
 ↓
Did the backend receive it? (check server logs for the route being hit)
 ↓
Did auth pass? (401 in response → check token/key)
 ↓
Did validation pass? (422 from FastAPI/Pydantic → check the request body shape)
 ↓
Did the service layer succeed? (check structlog output for that correlation_id/module)
 ↓
Did the storage write succeed? (check SQLite directly, or the JSON file on disk)
 ↓
Was the WebSocket event emitted? (check for the relevant events.emit(...) call site executing —
   add a temporary log line if unsure, or check EventBroadcaster's client count)
 ↓
Is the frontend handling the event correctly? (handleEvent()'s branch for that msg.type)
```

---

## 21. Follow the Data

### Trace 1 — `file_hash` field, database (well, JSON file) → UI

```
1. Sent by ESET PROTECT in the webhook POST body: {"file_hash": "a4f5b6c7...f4a5", ...}
2. src/models/raw_payload.py: EsetRawPayload.file_hash (str | None)
3. src/services/normalizer.py: data["file_hash"] = raw.file_hash or "UNKNOWN"
4. src/models/normalized_alert.py: NormalizedAlert.file_hash (str, default "UNKNOWN")
5. src/services/threat_intel/virustotal.py: VirusTotalProvider.query() reads alert.file_hash
   as the lookup indicator if present and not "UNKNOWN"
6. src/services/ai/gemini_service.py: included in the prompt via
   alert.model_dump(exclude={"raw_payload"}) — the AI sees it and may reference it as a
   "confirmed fact" in engineer_notification_en.confirmed_information
7. src/models/pipeline_result.py: PipelineResult.normalized_alert.file_hash
8. src/services/output_writer.py: written verbatim into output/alerts/{correlation_id}.json
9. src/api/dashboard.py: get_job_detail() reads that JSON file straight off disk and
   returns it as-is inside {"result": {...}}
10. static/dashboard.js: openAlert() → `a.file_hash` where `a = r.normalized_alert`
11. Rendered: `<div>File Hash</div><div class="mono">${esc(a.file_hash)}</div>`
    inside the Alert Detail modal's kv grid.
```

### Trace 2 — `risk_level`, computed value → chart

```
1. src/services/risk_engine.py: compute_risk(alert) returns ("HIGH", "Alert severity is HIGH...")
   — a pure function of NormalizedAlert.severity/threat_handled/isolation_status, no I/O
2. src/pipeline/orchestrator.py: risk_level, risk_rationale = risk_engine.compute_risk(alert)
3. Immediately broadcast: events.emit_stage(correlation_id, "RISK", "ok", detail=risk_rationale,
   risk_level=risk_level)  → WebSocket "pipeline_stage" event
4. Also embedded in the final PipelineResult.risk_level, written to the alert's JSON file
5. Also appended as a lightweight field in output/alerts/index.json's per-alert record
6. src/api/dashboard.py: get_stats() reads ALL result files via _read_results(2000) and
   tallies collections.Counter() by risk_level → {"LOW": n, "MEDIUM": n, "HIGH": n, "CRITICAL": n}
7. static/dashboard.js: loadStats() → state.stats.by_risk
8. static/dashboard-viz.js: drawRisk(byRisk) → drawBars() generates SVG <rect> bars,
   one per risk level, width proportional to count, color from the --risk-N CSS variables
   (a single-hue blue ramp — see the CSS comment: "Risk = ordinal magnitude... identity
   from labels", i.e. color intentionally does NOT distinguish severity — text labels do)
```

### Trace 3 — User input → database (reverse direction): saving a notification recipient

```
1. User types "soc@example.com" into the "Internal team (JA)" input on the Settings tab
   (static/dashboard.html: <input id="in-internal">)
2. Clicks "Save recipients" → static/dashboard.js's click handler collects all 4 fields
   into `body = {client_notification_emails: "...", internal_notification_emails:
   "soc@example.com", ...}`
3. api("/settings/recipients", {method: "PUT", body: JSON.stringify(body)})
   → adds X-Dashboard-Key header if a key is stored, Content-Type: application/json
4. src/api/dashboard.py: update_recipients(request, payload: RecipientUpdate)
   → _check_access(request) first
   → Pydantic validates the body shape (RecipientUpdate model)
   → values = {k: v for k, v in payload.model_dump().items() if v is not None}
5. src/storage/settings_store.py: update_recipients(values)
   → for "internal_notification_emails": set_setting(key, value)
       → SQLite: INSERT INTO app_settings (key, value) VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value
6. Response returns the freshly-saved state; frontend calls loadSettings() again to
   re-render the form with the "saved here" source badge instead of "from .env"
7. NEXT alert that completes SUCCESSFULLY:
   src/services/email_composer.py: compose_emails() calls
   settings_store.get_effective("internal_notification_emails")
   → get_setting() finds the row just inserted → returns "soc@example.com" directly,
     bypassing settings.internal_notification_emails (.env) entirely
8. An EmailMessage is built with to=["soc@example.com"] and queued into outbox.json
```

---

## 22. Important Functions

**`process_alert_pipeline(correlation_id, raw_payload, source)`**
Location: `src/pipeline/orchestrator.py`
Purpose: the single function that runs every stage of alert processing in order, guaranteeing a result is always written no matter what fails.
Called by: `run_pipeline_task()` in `src/api/webhook.py` (both the initial ingest path and the dashboard retry path), and `recover_unfinished_jobs()` in `src/main.py`.
Calls: `job_store.update_job_status`, `normalizer.normalize`, `risk_engine.compute_risk`, `threat_intel.aggregator.gather_threat_intel`, `GeminiAIService.generate`, `lint_checker.lint_ai_output`, `output_writer.write_result`, `email_composer.compose_emails`, `email_outbox.add_emails`, `email_dispatcher.dispatch_soon`, `events.emit_stage` (repeatedly).
Inputs: a correlation id (string), the raw payload dict, and a source string (`"WEBHOOK"`/`"SYSLOG"`).
Outputs: `None` — all outcomes are side effects (DB writes, file writes, WebSocket broadcasts).
Side effects: writes to `jobs` table, writes a result JSON file, appends to `index.json`, may write to `outbox.json` and `email_deliveries` table, broadcasts multiple WebSocket events.
Important assumptions: `raw_payload` is a dict compatible with `EsetRawPayload(**raw_payload)` — if it's fundamentally malformed in a way Pydantic rejects, this raises and is caught by the outermost `except`, producing a `FAILED` result with `alert = NormalizedAlert(raw_payload=raw_payload)` as a placeholder.
Things that could break it: any new required field added to `NormalizedAlert` without a default; a change to `PipelineResult`'s required fields without updating every construction site inside this function (there are three — `SUCCESS`, `PARTIAL`, `FAILED` branches).

**`build_gemini_schema(model: type[BaseModel]) -> dict`**
Location: `src/services/ai/schema_builder.py`
Purpose: converts any Pydantic model into a Gemini-API-compatible JSON schema that correctly preserves `required` fields at every nesting level (working around a bug in the `google-generativeai` SDK's own converter).
Called by: `GeminiAIService.generate()` in `src/services/ai/gemini_service.py`.
Calls: its internal recursive helper `_resolve()`.
Inputs: a Pydantic `BaseModel` subclass (currently only ever called with `AIOutput`).
Outputs: a `dict` — an OpenAPI-subset schema dict with `$ref`/`$defs` inlined and unsupported keys stripped.
Side effects: none (pure function).
Important assumptions: the model has no genuinely recursive/self-referential structure (would infinite-loop `_resolve`'s `$ref` inlining) — not currently an issue since `AIOutput`'s nested models are all flat, non-recursive.
Things that could break it: adding a field type Gemini's schema subset doesn't support (e.g. `Union`/`anyOf` of more than the union types this converts cleanly); the `_ALLOWED_KEYS` set would need updating if a new JSON-Schema keyword needs to pass through.

**`compute_risk(alert: NormalizedAlert) -> tuple[str, str]`**
Location: `src/services/risk_engine.py`
Purpose: the ONLY place risk level is decided — pure, deterministic, rule-based (explicitly *not* AI-driven, per its docstring).
Called by: `process_alert_pipeline()`.
Calls: nothing (pure function, only string comparisons).
Inputs: a `NormalizedAlert`.
Outputs: `(risk_level: str, rationale: str)`.
Side effects: none.
Important assumptions: `alert.severity`/`threat_handled`/`isolation_status` are already normalized strings (uppercase-able severity, `"true"`/`"false"`/`"unknown"` lowercase for the booleans) — this function trusts the normalizer already did that conversion.
Things that could break it: passing a raw (non-normalized) alert object where these fields might be actual booleans or arbitrary strings would silently fall through to the `"UNKNOWN severity"` fallback branch rather than erroring loudly.

**`_check_access(request: Request) -> None`**
Location: `src/api/dashboard.py`
Purpose: the dashboard's sole authorization gate, called manually at the top of every dashboard route.
Called by: every function in `src/api/dashboard.py` except `dashboard_ws()` (which has its own separate inline check).
Calls: `hmac.compare_digest`.
Inputs: the FastAPI `Request` object (reads the `X-Dashboard-Key` header).
Outputs: `None`, or raises `HTTPException(401)`.
Side effects: logs `dashboard_auth_failed` on rejection.
Important assumptions: it is called as literally the first line of the route function.
**Things that could break it: it is NOT a FastAPI dependency — nothing enforces that a new route calls it. Forgetting this call on a new route is a real, easy-to-make mistake with no automatic safety net (see §26).**

**`gather_threat_intel(alert: NormalizedAlert) -> ThreatIntelResult`**
Location: `src/services/threat_intel/aggregator.py`
Purpose: runs both threat-intel providers concurrently with hard per-provider timeouts, guaranteeing the pipeline is never blocked by a slow/dead external API.
Called by: `process_alert_pipeline()`.
Calls: `VirusTotalProvider.query()`, `AbuseIPDBProvider.query()` via `asyncio.gather()` + `asyncio.wait_for()`.
Inputs: a `NormalizedAlert`.
Outputs: `ThreatIntelResult` (always succeeds — internal exceptions/timeouts become `UNKNOWN` results, never propagate).
Side effects: outbound HTTP calls (unless `use_mock_threat_intel` is `True`, the default).
Important assumptions: `settings.threat_intel_timeout_seconds` is a sane positive number.
Things that could break it: none observed — this function is deliberately defensive.

**`EsetMailProvider.send(message: EmailMessage) -> DeliveryResult`**
Location: `src/services/email_delivery/eset_mail.py`
Purpose: hands one composed email to the external ESET Mail worker over HTTP, with optional HMAC request signing.
Called by: `email_dispatcher._hand_off()`.
Calls: `is_configured()`, `build_request()`, `httpx.AsyncClient.post()`, `_interpret()`.
Inputs: an `EmailMessage`.
Outputs: a `DeliveryResult` (never raises — all failure modes, including transport errors and timeouts, are caught and returned as `DeliveryResult.fail(...)`).
Side effects: one outbound HTTP POST.
Important assumptions: `self.url`/`self.api_key` are non-empty (checked via `is_configured()` first); the worker's clock is within `CLOCK_SKEW_TOLERANCE_SECONDS` (180s) of this server's clock for `signed`/`full` modes.
Things that could break it: if `json.dumps(..., separators=(",", ":"))`'s exact byte output ever changed (e.g. Python version differences in float formatting, though this payload is all strings/lists so unlikely) the HMAC signature the worker recomputes would mismatch — this is why the code sends `content=body_bytes` instead of `json=payload` (see the module docstring).

---

## 23. Critical Files (Tiers)

### Tier 1 — Must Understand
These files define the shape of data and the core control flow. Nothing in the app makes sense without them.

- **`src/main.py`** — process entrypoint, startup/shutdown sequence, where everything is wired together.
- **`src/config.py`** — every environment variable and default in the system.
- **`src/pipeline/orchestrator.py`** — the central state machine; the single most important file to read to understand "what does this app actually do."
- **`src/models/normalized_alert.py`**, **`src/models/pipeline_result.py`**, **`src/models/ai_output.py`** — the core data contracts everything else is built around.
- **`src/api/webhook.py`** — the ingestion entrypoint and dedup/job-creation logic.
- **`src/api/dashboard.py`** — the entire dashboard backend surface (large but not complex; mostly thin CRUD-style handlers).
- **`static/dashboard.js`** — the frontend's entire state model, routing, and WebSocket handling.
- **`src/storage/database.py`** — the schema; without reading this you can't reason about any storage module.

### Tier 2 — Should Understand
Frequently touched when adding or changing a feature.

- **`src/services/risk_engine.py`**, **`src/services/normalizer.py`** — core business rules, small and pure.
- **`src/services/ai/gemini_service.py`**, **`src/services/ai/schema_builder.py`** — the AI integration and its one critical workaround.
- **`src/services/email_composer.py`**, **`src/services/email_dispatcher.py`**, **`src/services/email_delivery/eset_mail.py`** — the entire outbound-notification subsystem.
- **`src/storage/job_store.py`**, **`src/storage/settings_store.py`**, **`src/storage/delivery_store.py`** — the three "business" storage modules (vs. the more mechanical `deduplication.py`).
- **`src/utils/events.py`**, **`src/utils/broadcaster.py`** — how every backend module talks to the live dashboard.
- **`static/dashboard-viz.js`** — the flow graph and charts; complex but self-contained.
- **`src/middleware/auth.py`** — small but security-critical.

### Tier 3 — Useful Reference
Read when working in that specific area; not needed to hold the whole system in your head.

- **`src/services/threat_intel/*.py`** — mock/real dual-mode providers, mostly boilerplate HTTP calls.
- **`src/ingestion/*.py`** — thin adapters; easy to understand once you've read one.
- **`src/services/syslog_runtime.py`**, **`syslog_server/server.py`** — network-listener plumbing, rarely touched.
- **`src/utils/correlation.py`**, **`src/utils/retry.py`**, **`src/utils/logging.py`** — small, stable utilities.
- **`src/prompts/system_prompts.py`** — one string constant; important *content*, trivial *code*.
- **`src/models/raw_payload.py`**, **`src/models/threat_intel.py`**, **`src/models/email_message.py`** — simpler data contracts.

### Tier 4 — Mostly Infrastructure / Generated (don't memorize)
- **`scripts/*`** — manual test helpers, not imported by the app.
- **`supervisord.conf`** — an alternate/possibly-stale process manager config (see §16, §25).
- **`pyproject.toml`**, **`.env.example`**, **`.gitignore`** — standard project scaffolding.
- **`tests/*`** — important to *run*, but you don't need to memorize test code the way you need to memorize application code; read a specific test file when you touch the feature it covers.
- **`static/dashboard.html`**'s CSS block — large but purely presentational; skim once, reference as needed.

---

## 24. Architectural Decisions

The following are **inferred from the code** (marked accordingly) unless a docstring/comment states the reason explicitly (marked "confirmed").

**Single-process, embedded-everything architecture.** *(Confirmed — README + `src/main.py` comments state this explicitly.)* The API, dashboard, and syslog listeners all run in one Python process on one `asyncio` event loop. Likely design reason: this is a small-scale, single-tenant SOC tool, not a high-traffic multi-tenant SaaS — the operational simplicity of "one command starts everything" outweighs the scalability benefits of separate processes/containers for this use case.

**No task queue (Celery/RQ) — `asyncio.create_task`/`BackgroundTasks` instead.** *(Inferred.)* Likely design reason: at the expected alert volume for a SOC tool, a separate broker (Redis/RabbitMQ) and worker fleet would be pure operational overhead. The trade-off (discussed in §25) is that a process crash loses in-flight *concurrency* (though not data — jobs are durably recorded in SQLite before backgrounding, and crash recovery re-runs them).

**Hybrid storage: SQLite for queue/workflow state, flat JSON files for alert content.** *(Inferred, but strongly suggested by the code's separation of concerns.)* Likely design reason: alert results are write-once, read-many, and valuable as human-inspectable artifacts on disk (an analyst can literally `cat output/alerts/<id>.json`); SQLite is reserved for data that's *queried/updated* relationally (status transitions, TTL-based dedup lookups, settings key-value overrides, delivery attempt counters) — the kind of access pattern SQL is good at and flat files are not.

**No ORM.** *(Inferred.)* Given the schema is genuinely small (4 tables, no relationships enforced), hand-written parameterized SQL avoids an extra dependency and its learning curve for a codebase this size. This is a defensible choice at this scale; it would become a liability if the schema grew significantly.

**Service-layer abstraction for both AI and email delivery (`BaseAIProvider`, `BaseThreatIntelProvider`, `EmailDeliveryProvider`).** *(Confirmed — explicit in code comments, e.g. `email_delivery/base.py`'s docstring: "swapping ESET Mail for SES, SendGrid or an SMTP relay is a new subclass plus one config value.")* This is a textbook Strategy pattern, deliberately used so a provider swap never touches the orchestrator, dispatcher, or outbox.

**The pipeline degrades gracefully in stages (SUCCESS/PARTIAL/FAILED) rather than being all-or-nothing.** *(Confirmed — explicit in `orchestrator.py`'s module docstring: "No alert is ever silently lost.")* Likely design reason: risk scoring and threat intel are independently valuable even if the AI step fails (e.g. due to quota exhaustion) — a SOC analyst would rather see a `PARTIAL` result with a computed risk level than nothing at all.

**Recipients are dashboard-editable at runtime, but almost everything else in `.env` requires a restart.** *(Confirmed by the existence of `settings_store.py` specifically for this one category of config, versus everything else reading directly from the immutable `settings` singleton.)* Likely design reason: recipient lists are the one setting operators realistically need to change frequently (staff turnover, new client contacts) without redeploying; other settings (timeouts, ports, feature flags) are operational/infra concerns better handled by a proper restart-and-redeploy cycle.

**The AI safety lint exists as a second, independent check *after* structured-output generation, not instead of prompt engineering.** *(Confirmed — `lint_checker.py`'s docstring frames it as a post-generation check; the system prompt in `system_prompts.py` also states the same constraints.)* Likely design reason: defense-in-depth — a well-crafted system prompt reduces but does not guarantee the model never produces a prohibited claim (LLMs are not deterministic rule-followers), so a cheap, deterministic string-match lint acts as a final backstop specifically for the highest-stakes failure mode (falsely claiming an incident is resolved/contained).

**Correlation IDs are propagated via `structlog.contextvars`, not passed as explicit function parameters everywhere.** *(Confirmed via `src/utils/correlation.py`.)* Likely design reason: this lets *every* log line automatically carry the correlation_id without threading an extra parameter through every function signature in the call chain — a common structured-logging pattern.

**Two syslog embedding paths exist (`src/services/syslog_runtime.py` invoked from both `main.py` and the standalone `syslog_server/server.py`).** *(Inferred from git history — commit `cd76ab3`'s diff shows `syslog_server/server.py` shrinking from 181 lines to 34 as its logic was extracted into the new shared `syslog_runtime.py` module, used by the newly-embedded main-process path.)* This strongly suggests `syslog_server/server.py` is a **legacy entrypoint kept for backward compatibility** (its own docstring says exactly this: "Kept for backward compatibility — the primary path now embeds these listeners directly in the FastAPI process"), while `supervisord.conf` (unchanged since the initial commit) still references the old standalone-process model. This is very likely a genuine remaining inconsistency rather than an intentional dual-mode design — see §25.

---

## 25. Technical Debt

**1. `supervisord.conf` appears stale relative to the embedded-syslog architecture.**
- Location: `supervisord.conf` vs. `src/main.py` + `src/services/syslog_runtime.py`.
- Why problematic: running both `[program:api]` and `[program:syslog_server]` as supervisord defines them would cause two processes to race for the same UDP/TCP ports, since the API process (`src.main:app`) already embeds and binds those listeners itself via its `lifespan()`.
- Risk: an operator following `supervisord.conf` literally (rather than the README's `run.py` instructions) would hit a port-bind failure for whichever process starts second, with only a `CRITICAL` log line to explain why syslog ingestion is silently degraded on one path.
- Possible improvement: remove the `[program:syslog_server]` block from `supervisord.conf` (or repurpose `supervisord.conf` to run only `[program:api]` via `run.py`/uvicorn), and clarify in the README which of the two files is the current source of truth for production process management.

**2. `AI_TIMEOUT_SECONDS` and `MAX_RETRIES` settings are declared but unused.**
- Location: `src/config.py` declares both; no code in `src/services/ai/gemini_service.py` references either.
- Why problematic: an operator editing `.env` to change AI timeout/retry behavior would see no effect, with no error or warning — a silent configuration no-op.
- Risk: low (functional behavior is fine, since hardcoded `@retry_api_call(max_attempts=3, min_delay=1.0, max_delay=10.0)` provides working defaults) but confusing/misleading for anyone reading `.env.example` expecting these to be load-bearing.
- Possible improvement: either wire these settings into the `@retry_api_call` decorator's parameters and the (currently absent) actual timeout wrapper around the Gemini call, or remove them from `Settings`/`.env.example` to avoid the false impression they do something.

**3. `deduplication.cleanup_expired()` is dead code — never invoked anywhere in the running application.**
- Location: `src/storage/deduplication.py`.
- Why problematic: `dedup_log` rows accumulate forever; nothing prunes expired entries. `is_duplicate()`'s `expires_at > now()` filter means expired rows don't functionally interfere with correctness, but the table grows unboundedly over the service's lifetime.
- Risk: low in the near term (a small TEXT+REAL+REAL row is cheap; would take a very long uptime at high alert volume to matter), but it's the kind of thing that silently becomes a real problem months into production with no visible symptom until the SQLite file is unexpectedly large.
- Possible improvement: call `cleanup_expired()` periodically — e.g. from the existing `email_dispatcher.run_dispatch_loop()`-style periodic task pattern, or as a step in `recover_unfinished_jobs()`'s startup routine.

**4. Crash recovery re-runs the entire pipeline from scratch, not from a checkpoint.**
- Location: `src/main.py: recover_unfinished_jobs()`.
- Why problematic: a job that crashed *after* the AI call succeeded but *before* `output_writer.write_result()` completed would, on recovery, re-run threat intel and re-call Gemini entirely — wasting API quota/cost and potentially producing a *different* AI output for the same alert (since Gemini isn't perfectly deterministic even at `temperature=0.1`).
- Risk: medium in terms of cost/quota waste under frequent crashes; low in terms of correctness (the pipeline is idempotent in the sense that re-running it produces a valid, consistent result — just not necessarily byte-identical to what would have been written the first time).
- Possible improvement: store intermediate pipeline state (e.g. risk/intel results) in the `jobs` row so recovery can resume partway through rather than from the very beginning. This is a reasonable amount of added complexity, so the current "just redo it all" approach is a defensible simplicity trade-off for a low-crash-frequency service, not a clear-cut bug.

**5. Two independent implementations of dashboard key checking (REST vs. WebSocket).**
- Location: `_check_access()` in `src/api/dashboard.py` vs. the inline `if settings.dashboard_access_key: ...` block inside `dashboard_ws()`.
- Why problematic: any future change to the auth *logic* (e.g. supporting multiple valid keys, or a different header name) must be made in two places by hand; they've already drifted structurally (header vs. query param, by necessity) which makes it easy to miss updating one when fixing the other.
- Risk: low today (both are simple and currently correct, verified by tests), but a real maintenance hazard for future auth changes.
- Possible improvement: extract a single `_key_matches(provided: str) -> bool` helper both call, so the *comparison* logic (currently duplicated `hmac.compare_digest(...)` calls) has one source of truth even though the *header extraction* mechanism must differ.

**6. `_check_access()` is a manual convention, not an enforced dependency.**
- Location: every route in `src/api/dashboard.py`.
- Why problematic: nothing in FastAPI's routing prevents a new route from forgetting to call `_check_access(request)` — there's no compiler/framework-level guarantee, only developer discipline and the existing test suite's *specific, per-route* assertions.
- Risk: medium — this is a realistic, easy mistake for a future contributor (including a future you) to make, and its consequence (an unauthenticated data leak or mutation) is serious.
- Possible improvement: convert `_check_access` into a proper FastAPI dependency (`Depends(_check_access)`) applied at the router level (`APIRouter(dependencies=[Depends(_check_access)])` in `src/api/dashboard.py`'s router construction) instead of a function called manually inside each handler — this would make the check impossible to accidentally omit on new routes. See §26.

**7. Frontend/backend stage-list duplication (`STAGES` defined twice, must be kept in sync by hand).**
- Location: `src/utils/events.py: STAGES` vs. `static/dashboard.js: STAGES` (and `STAGE_LABEL`).
- Why problematic: adding, renaming, or reordering a pipeline stage requires editing two files in two languages with no shared schema or generated constant — a mismatch would show a stage as permanently "waiting" in the Flow tab UI without any error.
- Risk: low probability of occurring (pipeline stages are added rarely) but silent/hard-to-notice if it does.
- Possible improvement: expose the stage list from a backend endpoint (e.g. include it in `GET /health` or a new tiny `/dashboard/api/meta` route) and have the frontend fetch it once at boot instead of hardcoding a parallel copy.

**8. Threat-intel and real-Gemini code paths are entirely untested (see §14).**
- Risk: medium — these are exactly the code paths most likely to break silently in production (a third-party API changing its response shape) with zero test coverage to catch a regression before a real alert hits it.
- Possible improvement: add tests using recorded/fixture HTTP responses (e.g. via `httpx`'s mock transport) for `_query_real()` in both threat-intel providers, and at least a schema-shape test against a saved real Gemini response.

---

## 26. Red Flags — Things You Must Not Break

- **DO NOT casually modify `src/models/normalized_alert.py`, `src/models/ai_output.py`, or `src/models/pipeline_result.py`** without grepping for every place their fields are consumed — the normalizer, the AI prompt construction, the email composer's body-formatting functions, and the frontend's `openAlert()`/`notificationTabs()` all destructure these models by field name with no compile-time check on the JS side.

- **DO NOT bypass `build_gemini_schema()`** when constructing the Gemini `response_schema` — passing `AIOutput` (the raw Pydantic class) directly reintroduces the exact bug this module exists to fix (silently-optional fields → near-empty AI responses → everything downgrades to `PARTIAL`). This is thoroughly tested (`tests/unit/test_schema_builder.py`) specifically because it bit this project once already.

- **DO NOT add a new `/dashboard/api/*` route without calling `_check_access(request)` as the first line** (see §25, point 6) — there is no framework-level enforcement, only convention. Copy the pattern from any existing route in `src/api/dashboard.py`.

- **DO NOT interpolate alert-derived (attacker-controllable) data into `innerHTML` in `static/dashboard.js`/`dashboard-viz.js` without wrapping it in `esc()`.** Any field originating from an ingested alert payload (`detection_name`, `endpoint_name`, `raw_subject`, error messages, log lines, etc.) must be escaped. This is enforced (partially — see §13, finding 6) by `tests/integration/test_security.py` and `tests/integration/test_dashboard_controls.py`.

- **DO NOT rename or reorder the `STAGES` list in `src/utils/events.py`** without making the matching edit in `static/dashboard.js`'s `STAGES`/`STAGE_LABEL` — they are two independently-maintained copies of the same contract (see §25, point 7).

- **DO NOT assume `email_outbox.py`'s `outbox.json` is a complete history of every email ever composed** — it holds *only pending* emails; once accepted or permanently failed, entries are *removed*, not archived, there. The durable history lives in the `email_deliveries` SQLite table (`src/storage/delivery_store.py`) instead — if you need "every email ever sent," query that table, not the outbox file.

- **DO NOT change `EMAIL_SECURITY_MODE` or the HMAC signing logic in `src/services/email_delivery/eset_mail.py`** without confirming the change matches the external ESET Mail worker's own `SECURITY_MODE` — a mismatch here isn't caught by any test in this repo (the worker is external, `UNKNOWN`/out of scope for this codebase's test suite) and would only surface as every single email handoff failing with a signature-mismatch error at runtime.

- **DO NOT run `supervisord.conf` as-is alongside `run.py`** — see §25, point 1. Pick one process-management approach.

- **DO NOT expect `GEMINI_API_KEY` or `ESET_WEBHOOK_AUTH_TOKEN` to have safe defaults** — `src/config.py` declares both with `Field(...)` (no default value), meaning **the application will fail to start at all** (a Pydantic validation error at `Settings()` instantiation) if either is missing from `.env`/environment. This is a deliberate fail-fast design — don't "fix" a startup crash by giving these silent defaults.

- **DO NOT assume the `jobs.raw_payload` column and the `output/alerts/*.json` files are the same data** — `jobs.raw_payload` is the *original, unprocessed* input (used for retries); the JSON output file is the *fully processed* `PipelineResult`. They serve different purposes and should not be conflated when debugging.

---

## 27. My Mental Model

*What I'd say to another engineer with no access to the code, from memory:*

"It's a single Python process — one `uvicorn` command — that sits between an antivirus platform (ESET PROTECT Cloud) and a human SOC team. It accepts alerts two ways: an HTTP webhook, or raw syslog packets on UDP/TCP that get converted to the same HTTP call internally. Every accepted alert gets a UUID ('correlation_id') and is deduplicated against a short-TTL SQLite table before anything else happens.

Once accepted, the HTTP response comes back *immediately* saying 'queued' — the actual work happens in a FastAPI background task, in the same process. That work is a strict pipeline with no branching logic of its own: normalize the messy input into a strict internal shape, compute a risk level with fixed if/else rules (deliberately *not* AI — that's a compliance/predictability choice), fire off two threat-intel lookups in parallel with hard timeouts, then call Google's Gemini model to generate four separate bilingual incident reports using a schema-enforced structured-output call (with a specific, well-tested workaround for a bug in Google's own SDK that used to make required fields silently optional). A safety lint scans everything the AI wrote for a blocklist of phrases that would overstate certainty ('infection confirmed,' etc.) — the system prompt already tells the model not to say these, but the lint is a second, deterministic backstop. The pipeline is built so that no matter what fails — AI outage, malformed input, whatever — a result always gets written, either as SUCCESS, PARTIAL (risk score exists, no AI content), or FAILED.

Successful results generate up to four emails (client-facing, a front-office partner, internal team, engineering — three Japanese, one English), which get queued to a JSON file and then handed off, once, to a completely separate external mail service over an HMAC-signed HTTP call. This app deliberately does NOT own email retries/delivery tracking beyond that single handoff — a Cloudflare Worker elsewhere owns the actual send queue.

Storage is split: SQLite holds workflow state (job status, dedup keys, dashboard-editable settings, email handoff history) — small, queryable, transactional stuff. The actual alert content and generated AI reports live as plain JSON files on disk, one per alert, because they're write-once and meant to be human-inspectable.

There's a live dashboard — plain HTML/CSS/JS, zero framework, zero build step — that connects over a WebSocket to watch every pipeline stage happen in real time, rendered as a hand-drawn SVG flow graph, plus a few hand-drawn SVG charts. It has its own separate, much simpler auth: one shared key in an HTTP header, checked manually (not via a framework dependency) at the top of every dashboard route — which is honestly the single easiest thing to get wrong if you add a new route and forget the check.

There's no user-account system anywhere in this app. Two shared secrets — one for machines posting alerts, one for humans opening the dashboard — that's the entire auth model. No roles, no JWT, no sessions."

---

## 28. Study Roadmap

```
Step 1  → Read §1 and §3 of this guide (purpose + architecture diagram) — get the shape
          of the whole system in your head before opening any code.

Step 2  → Open src/main.py and src/config.py side by side. Understand every line of
          lifespan(). This is the "what happens when I run `python run.py`" question,
          fully answered.

Step 3  → Read src/models/raw_payload.py → normalized_alert.py → pipeline_result.py →
          ai_output.py, in that order. These four files are the vocabulary everything
          else speaks. Don't skip this even though it's "just" Pydantic classes.

Step 4  → Read src/pipeline/orchestrator.py top to bottom, cross-referencing each
          `events.emit_stage(...)` call against §3's flow diagram. This is the single
          most important file in the repo.

Step 5  → Read src/api/webhook.py + src/middleware/auth.py. Understand how a raw HTTP
          request becomes a call into Step 4's function.

Step 6  → Read the four "single responsibility" service files that Step 4 calls, in
          isolation: src/services/normalizer.py, risk_engine.py, threat_intel/aggregator.py,
          ai/gemini_service.py (+ ai/schema_builder.py's docstring — important history).

Step 7  → Run the app locally (§15) and the manual test scripts (scripts/send_test_webhook.sh).
          Watch it happen live in the dashboard. This makes everything above concrete.

Step 8  → Read src/storage/database.py (the schema) then job_store.py, deduplication.py.
          Open the resulting data/soc_lite.db with any SQLite viewer while the app is running.

Step 9  → Read the email subsystem in this order: models/email_message.py →
          services/email_composer.py → services/email_outbox.py →
          services/email_delivery/base.py → services/email_delivery/eset_mail.py →
          services/email_dispatcher.py. Cross-reference with the README's "Email outbox
          and delivery" section, which is unusually thorough.

Step 10 → Read src/api/dashboard.py fully, then static/dashboard.js fully, then
          static/dashboard-viz.js fully. By now you know what data each route returns,
          so reading the frontend is just "how is this rendered," not "what does this mean."

Step 11 → Read src/utils/events.py + broadcaster.py, and trace one event type
          (e.g. "pipeline_stage") from its emit() call site all the way to the DOM update
          in dashboard-viz.js's applyStage()/renderFlow(). This cements the real-time
          architecture.

Step 12 → Read the test suite, starting with tests/conftest.py (the fixtures explain a lot
          about what assumptions are safe to make), then skim every test file's names/
          docstrings to build a map of "what's covered" (§14 already has this — use it
          to verify your own read).

Step 13 → Read §13 (Security Audit), §25 (Technical Debt), and §26 (Red Flags) in this
          guide together — these are the "here's what to be careful about" distilled from
          everything above, worth a second pass once you have the full picture.

Step 14 → Pick one small, real change (e.g. §19's "add a field" walkthrough) and actually
          do it end-to-end, running the tests before and after. This is the fastest way to
          confirm your mental model is accurate rather than approximately accurate.
```

---

## 29. Final Checklist

- [ ] I understand the repository structure and why `output/`, `logs/`, `data/` aren't checked into git.
- [ ] I know there is no separate frontend framework — `static/*` is plain HTML/CSS/JS with zero build step.
- [ ] I know the backend entrypoint is `run.py` → `src/main.py: app` → `lifespan()`.
- [ ] I understand there is no client-side URL routing — tabs are toggled via `showView()`, not real navigation.
- [ ] I understand backend routing: four routers (`webhook`, `health`, `status`, `dashboard`) aggregated in `src/api/router.py`.
- [ ] I understand the database is a hybrid: SQLite (4 tables, no ORM, no migrations) for workflow state + flat JSON files for alert/email content.
- [ ] I understand authentication is two shared secrets (`ESET_WEBHOOK_AUTH_TOKEN`, `DASHBOARD_ACCESS_KEY`), not a user-account system.
- [ ] I understand there is no authorization/role system beyond "has the key or doesn't."
- [ ] I can trace an ingest request from `POST /webhook/eset` through `ingest_alert()`, `process_alert_pipeline()`, to a written JSON result file and a WebSocket broadcast.
- [ ] I can trace data from the JSON result file to the Alert Detail modal in the dashboard.
- [ ] I can trace a Settings-tab recipient edit from the input field to `app_settings` in SQLite to the next composed email.
- [ ] I know where each feature lives via §18's Feature-to-File Map.
- [ ] I know how to add a new alert field (§19) and what layers it touches.
- [ ] I know how to add a new dashboard API route safely (§19, including the `_check_access` footgun in §26).
- [ ] I know how to debug a stuck/failed alert using `correlation_id` + `logs/app.log` (§20).
- [ ] I know how to run the test suite and what it does/doesn't cover (§14).
- [ ] I know how to start the app locally, including the syslog-port-needs-root caveat (§15).
- [ ] I understand deployment is currently just `supervisord.conf` (possibly stale — §16, §25) or a manually-run `run.py`; there's no CI/CD/Docker in this repo.
- [ ] I know the fragile parts: `_check_access()`'s manual-not-enforced convention, the duplicate frontend/backend `STAGES` lists, the `build_gemini_schema()` workaround, and the dead `cleanup_expired()` function (§26).
- [ ] I know the single most historically significant bug this codebase has already fixed (the Gemini `required`-field-dropping issue) and where its regression test lives.
- [ ] I know that `EMAIL_DELIVERY_ENABLED` defaults to `false` — composed emails will sit in the outbox forever until this is explicitly turned on.
