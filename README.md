# ESET SOC Lite

Fault-tolerant ingestion, normalization, risk-scoring, threat-intel enrichment,
and AI notification pipeline sitting between **ESET PROTECT Cloud** and the SOC team.

## Running it

Everything — the ingestion API, the live dashboard, and the syslog UDP/TCP
listeners — runs in a single process, started with one command:

```bash
.venv/bin/python run.py
```

Then open **http://localhost:8000/** for the live dashboard.

Binding the syslog listeners to their default privileged ports (514/601) requires
root. Without it the process still starts — the syslog listeners log a warning and
stay down, and webhook ingestion is unaffected. Either run with `sudo`, or set
`SYSLOG_UDP_PORT=1514` / `SYSLOG_TCP_PORT=1601` in `.env` for local development.

## First-time setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
cp .env.example .env   # fill in GEMINI_API_KEY, ESET_WEBHOOK_AUTH_TOKEN, recipients
.venv/bin/python run.py
```

---

## Sending alerts to the ingest API

Both ingest routes require the shared token from `ESET_WEBHOOK_AUTH_TOKEN`, sent as
`Authorization: Bearer <token>` (a bare `Authorization: <token>` is also accepted).
Both respond immediately with a `correlation_id`; the pipeline then runs in the
background and streams to the dashboard live.

### `POST /webhook/eset` — ESET PROTECT webhook format

```bash
curl -X POST http://localhost:8000/webhook/eset \
  -H "Authorization: Bearer $ESET_WEBHOOK_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "ESET_PROTECT_CLOUD",
    "event_type": "Threat Detection",
    "alert_id": "alert-0001",
    "occurred_at": "2026-08-17T10:00:00Z",
    "severity": "HIGH",
    "detection_name": "Win32/TrojanDownloader.Agent.YHV",
    "endpoint_name": "FINANCE-PC-09",
    "endpoint_type": "Server",
    "user_name": "charlie.brown",
    "os_name": "Windows Server 2022",
    "action_taken": "Connection terminated",
    "threat_handled": false,
    "isolation_status": false,
    "object_type": "Process",
    "object_uri": "C:\\Windows\\System32\\cmd.exe",
    "file_hash": "a4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
    "url": "http://malicious-node.example/shell",
    "ip_address": "185.220.101.5",
    "domain": "malicious-node.example",
    "raw_subject": "High Risk Trojan Activity on FINANCE-PC-09",
    "raw_content": "A connection to a known C2 server was detected and blocked."
  }'
```

Response:

```json
{ "status": "queued", "correlation_id": "b3f1…" }
```

### `POST /webhook/syslog` — ESET syslog JSON export format

Same auth; the handler maps syslog key names (`threat_name`, `computer_name`,
`hash`, `ip`, `handled`, …) onto the same internal model.

```bash
curl -X POST http://localhost:8000/webhook/syslog \
  -H "Authorization: Bearer $ESET_WEBHOOK_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event": "Threat Detection",
    "id": "syslog-0001",
    "time": "2026-08-17T10:00:00Z",
    "severity": "HIGH",
    "threat_name": "Win32/HackTool.Mimikatz.B",
    "computer_name": "SYSLOG-TARGET-PC",
    "username": "local.admin",
    "os": "Windows Server 2022",
    "action": "Blocked",
    "handled": false,
    "hash": "b2f6ef8023abc456def89123456abcdef7890123456abcdef7890123456abcde",
    "ip": "198.51.100.22"
  }'
```

### Syslog over UDP/TCP

Point ESET's syslog export at the listener ports. Any RFC 5424 frame containing a
JSON object works — the listener extracts the JSON and feeds it through the same
pipeline:

```bash
logger -n 127.0.0.1 -P 514 -d '<14>1 2026-08-17T10:00:00Z host ESET-PROTECT - - - {"id":"s1","severity":"HIGH","threat_name":"X","computer_name":"H1"}'
```

### Field reference

Only the fields you send are used; anything missing normalizes to `"UNKNOWN"`
rather than being invented. The fields that actually drive behavior:

| Field | Effect |
|---|---|
| `severity` | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` — primary risk-engine input |
| `threat_handled` | bool/string — downgrades risk when true |
| `isolation_status` | bool/string — downgrades HIGH further when true |
| `alert_id` + `occurred_at` | deduplication key (falls back to a hash of the whole payload) |
| `file_hash`, `ip_address`, `url` | threat-intel lookups (VirusTotal / AbuseIPDB) |

**Duplicate suppression:** the same `alert_id` + `occurred_at` within
`DEDUP_TTL_SECONDS` (default 1h) returns `{"status": "duplicate"}` and is not
reprocessed. Vary `alert_id` when re-sending.

### Error responses

| Status | When |
|---|---|
| `400` | Body is not valid JSON, or is valid JSON but not an object, or fails to map onto the alert model |
| `401` | Missing or wrong `Authorization` token (checked before the body is read) |

A malformed frame from a sender is answered as a client error, not a `500` —
one bad payload never looks like a server fault and never creates a job.
Watch out for unescaped Windows paths: `"C:\\Users\\bob"` is required in JSON,
and a shell that eats one level of backslashes will produce an invalid escape.

### Checking a result

```bash
curl http://localhost:8000/status/<correlation_id>
```

Full output lands in `output/alerts/<correlation_id>.json`, with a rolling summary
in `output/alerts/index.json`.

---

## Dashboard

`/` serves a live control dashboard, protected by `DASHBOARD_ACCESS_KEY`
(currently `123456` — change it before this leaves your machine). Sections:

| Section | What it gives you |
|---|---|
| **Overview** | Stat tiles plus charts: alerts over time, risk distribution, pipeline outcomes, ingest source |
| **Pipeline Flow** | Live node graph — every alert becomes a lane whose nodes light up stage by stage (Ingest → Normalize → Risk → Intel → AI → Lint → Output → Email) as it runs. Click a node for that stage's detail |
| **Alerts** | Every alert, filterable by status and free-text; click for full detail; Retry on failed/partial |
| **AI Content** | The generated bilingual notifications, browsable with a tab per audience |
| **Emails** | Pending outbox; open an email to read it, or discard it |
| **Logs** | Structured application log with level filter, search, and auto-refresh |
| **Settings** | Edit notification recipients live (saved to the database, no restart) and view runtime config |
| **API Docs** | Ingest endpoints, a copyable curl for this host, and the dashboard API reference |

Alerts are only ever created by posting to the ingest routes — the dashboard
never fabricates traffic.

### Live updates

The dashboard holds a WebSocket to `/dashboard/api/ws` and receives
`pipeline_stage`, `job_status_changed`, `alert_completed`, and `email_queued`
events, so the flow graph and tables move without polling. It reconnects
automatically if the server restarts.

## Email outbox and delivery

Successful runs generate up to four notification emails (client, C-Three
front-office, internal team — Japanese; engineer — English) into
`output/emails/outbox.json`. That file holds **only emails still awaiting
handoff**. Recipients per type are editable in the dashboard's Settings section,
falling back to `.env`:

```
CLIENT_NOTIFICATION_EMAILS=a@example.com,b@example.com
CTHREE_NOTIFICATION_EMAILS=
INTERNAL_NOTIFICATION_EMAILS=
ENGINEER_NOTIFICATION_EMAILS=
```

A type with no configured recipients is skipped with a warning. Alerts that fail
before or during the AI stage (`PARTIAL`/`FAILED`) produce no emails, since there
is no generated content to send.

### Who owns what

The **ESET Mail** worker owns the send queue — it persists every accepted email,
retries failures, recovers messages stuck mid-send, and dispatches over SMTP on
its own cron. This platform does **not** duplicate any of that. Its only job is
to hand each composed email over exactly once:

```
compose → outbox.json → POST /api/send → 202 Accepted → mail service owns it
```

So the states recorded here describe *handoff*, not final delivery:

| State | Meaning |
|---|---|
| `PENDING` | still in `outbox.json`, not yet accepted |
| `ACCEPTED` | handed over; `remote_id` is the mail service's queue id |
| `FAILED` | could not be handed over (bad credentials, bad payload, or attempts exhausted) |

Whether an `ACCEPTED` email actually reached the mailbox is visible in the mail
service's own dashboard under that `remote_id`. The Emails section surfaces its
live queue counters (queued / sending / sent / failed) for convenience.

Handoff is retried by a sweeper every `EMAIL_DISPATCH_INTERVAL_SECONDS`, which
only ever picks up messages still sitting in the outbox — accepted ones are
already gone from it, so nothing is sent twice. "Send queued now" in the Emails
section forces a sweep immediately.

### Swapping the provider

Delivery lives behind `EmailDeliveryProvider` in
`src/services/email_delivery/`. To use a different transport, add a subclass,
register it in that package's `__init__.py`, and set `EMAIL_PROVIDER` — nothing
in the orchestrator, dispatcher, or outbox changes.

### Configuration

```
EMAIL_DELIVERY_ENABLED=true
EMAIL_API_URL=https://eset-mail.villdesign.workers.dev/api/send
EMAIL_API_KEY=...
EMAIL_API_SECRET=...          # HMAC signing secret, never transmitted
EMAIL_SECURITY_MODE=full      # must match the worker's SECURITY_MODE
EMAIL_TIMEOUT_SECONDS=60       # avoid ambiguous retry windows after slow worker starts
EMAIL_MAX_ATTEMPTS=3          # handoff attempts, not delivery retries
EMAIL_DISPATCH_INTERVAL_SECONDS=60
```

The request body includes the outbound `email_id` as an idempotency key so the worker
can reject a duplicate retry if a timeout makes the first send ambiguous.

Requests are signed exactly as the API reference specifies:
`HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + SHA256(body))`, with the
hash taken over the exact bytes transmitted (compact JSON — re-serialising would
invalidate the signature).

## Security notes

Read before exposing this beyond localhost:

- **`DASHBOARD_ACCESS_KEY` is currently `123456`** — a placeholder for local work.
  The dashboard exposes every ingested alert (hostnames, usernames, file paths,
  hashes, internal IPs) and can edit recipients, so replace it with a long random
  value before exposing the port. Leaving it blank disables auth entirely; the
  service then logs a `dashboard_exposed_without_key` warning at startup whenever
  `APP_HOST` is not `127.0.0.1`.
- **`ESET_WEBHOOK_AUTH_TOKEN` is the only thing protecting ingest.** Use a long
  random value, not the `test` default.
- **Terminate TLS in front of this service** (reverse proxy). Both the webhook
  token and the dashboard key are bearer secrets sent in cleartext otherwise.
- `/health` and `/status/{correlation_id}` are unauthenticated. `/status` requires
  knowing an unguessable UUID, but `/health` will confirm the service exists.
- There is no rate limiting on ingest; a flood will consume Gemini quota. Put a
  proxy-level limit in front if the endpoint is internet-facing.

## Tests

```bash
PYTHONPATH=. .venv/bin/pytest tests/ -v
```

Covers the risk engine, normalizer, dedup, lint checks, AI schema construction,
email composition/outbox, every HTTP endpoint, the auth surface, WebSocket
streaming, and XSS-safe rendering.
