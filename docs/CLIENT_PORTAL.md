# Client portal: operator runbook

For engineers who run the platform. The feature overview, the full settings table and the complete API list are in the README section [Client portal and weekly report](../README.md#client-portal-and-weekly-report). The client-facing quick start is [CLIENT_PORTAL_GUIDE_JA.md](CLIENT_PORTAL_GUIDE_JA.md). Deployment (the Caddy `/client` route, `ClientCidr`, rollout) is in [AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md), section 5.

## Before you start

- **Everything is configured at runtime from the engineering dashboard.** There is no CLI, and after deployment no `.env` edit is needed. Environment variables only set defaults. A value saved in the dashboard is stored in the database, takes precedence, and applies on the next read without a restart. Deleting the dashboard value returns the setting to its env default.
- **Exception:** `DASHBOARD_ACCESS_KEY` is an environment variable only. Change it in the deployment secret and restart the container.
- **Manage it in the dashboard's Client Portal tab first.** It has three panels: **Portal Settings**, **Client accounts** (the portal address, the on/off switch, and the accounts) and **Weekly reports**. The API calls in this runbook do the same things and are an alternative for scripts.

## Credentials

Three credentials exist. Each is accepted only on its own routes, and none can be used on another's.

| Credential | Header | Accepted on |
|---|---|---|
| Webhook token | `Authorization: Bearer <ESET_WEBHOOK_AUTH_TOKEN>` | `/webhook/*` |
| Dashboard key | `X-Dashboard-Key: <DASHBOARD_ACCESS_KEY>` | `/dashboard/api/*`, `/status/*` |
| Client session | `X-Client-Session: <token from sign-in>` | `/client/api/*` (except sign-in) |

## Enabling the portal

1. **Set `DASHBOARD_ACCESS_KEY` to at least 16 characters** in the deployment secret (in AWS, the `app` secret; see AWS_DEPLOYMENT.md, section 5). Restart the container after changing it.
2. **Create the client accounts** in the **Client accounts** panel (see [Client accounts](#client-accounts)).
3. **Set `client_portal_url`** to the public address, for example `https://soc-poc.example.com/client/`. It is used for links in emails only.
4. **Check the weekly report schedule** (`weekly_report_weekday`, `weekly_report_time`). The default is Monday 09:00 JST.
5. **Check the recipients** in the dashboard Settings tab: `weekly_report_emails` and `recommendation_notification_emails`. Blank falls back to `client_notification_emails`. These addresses are only used once the emails are switched on, which is not in this release.
6. **Set `client_portal_enabled` to on.** Use the **Enable portal** button in the **Client accounts** panel, or the **Enable client portal** setting in Portal Settings. The portal stays off until you do this. If the key is blank or shorter than 16 characters, the dashboard refuses with **409** and the message says which problem it found.
7. **Verify:**
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' "$BASE/client/"              # 200: the sign-in page always loads
   curl -s -o /dev/null -w '%{http_code}\n' "$BASE/client/api/auth/me"  # 404 while off; 401 once on (no session sent)
   ```

## API access used in this runbook

The examples below use these shell variables. Keep the key out of shared logs and shell history.

```bash
BASE=https://soc-poc.example.com
KEY='...'                                   # DASHBOARD_ACCESS_KEY
H=(-H "X-Dashboard-Key: $KEY" -H 'Content-Type: application/json')
```

## Client accounts

There is no self-service sign-up and no self-service password change. Engineers create and reset every account.

Manage accounts in the **Client accounts** panel on the dashboard's Client Portal tab:

- **Portal address and switch:** the panel shows the client portal URL with a **Copy** button, and the portal state with an **Enable portal** or **Disable portal** button. If the switch cannot be turned on, the reason is shown next to it (for example, a dashboard key that is too short).
- **Add an account:** enter a username and, optionally, a display name and a password. Leave the password blank to generate a strong one.
- **Accounts table:** username, display name, status (**Active**, **Disabled** or **Locked**), last sign-in, active sessions, and actions.
- **Actions per account:** **Reset password**, **Disable** or **Enable**, **Unlock** (shown only when the account is locked), **Sign out everywhere**, and **Delete**. Reset password opens a field: type a new password, or leave it blank to generate one. Delete asks you to confirm in the same row.
- **Generated and reset passwords** are shown once, in a box above the table, with a **Copy** button. Passwords are not stored, so the box cannot show one again after it is dismissed, or after you leave the Client Portal tab. If a password is lost, reset it.

The same actions as API calls, as an alternative for scripts:

```bash
# List accounts (id, username, disabled, locked, locked_until, active_sessions)
curl -s "${H[@]}" "$BASE/dashboard/api/portal/users"

# Create an account. Omit "password" to have one generated.
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users" \
  -d '{"username":"tanaka.a","display_name":"田中様（A社）"}'        # 201; "generated_password" is returned once

# Reset a password (omit the body to generate one). Also clears any lockout and ends all sessions.
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users/<id>/password" -d '{}'

# Disable or enable an account (disabling also ends its sessions)
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users/<id>/disable"
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users/<id>/enable"

# Clear a lockout
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users/<id>/unlock"

# End all sessions without changing anything else
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users/<id>/revoke-sessions"

# Delete an account (its sessions go with it)
curl -s -X DELETE "${H[@]}" "$BASE/dashboard/api/portal/users/<id>"
```

Rules:

- **Username:** 3 to 64 characters, letters, digits, `.` `_` `@` `-`. Unique, ignoring case.
- **Password:** 12 to 256 characters, and not the same as the username. Passwords are stored only as scrypt hashes.
- **Generated passwords** are 24 characters and are returned only in the response that creates or resets the account. Pass them to the client through a channel you trust, and do not paste them into tickets or chat logs.
- **Audit log** (structlog): `client_user_created`, `client_user_password_reset`, `client_user_disabled`, `client_user_enabled`, `client_user_unlocked`, `client_user_sessions_revoked`, `client_user_deleted`. Passwords and tokens are never logged.

## Sessions

- After sign-in the browser keeps the session token in `sessionStorage`, so it ends when the tab closes. There are no cookies. The token is sent in the `X-Client-Session` header.
- A session ends after `client_session_idle_minutes` (default 60) without activity, or `client_session_max_hours` (default 12) after sign-in, whichever comes first.
- Changing those two settings also applies to sessions that already exist, from their next use.
- To end a user's sessions immediately, use **Sign out everywhere**, **Disable**, or **Reset password** in the Client accounts panel (or the `revoke-sessions`, `disable` or `password` API calls).

## Changing settings

Read and change values through the API, or in the dashboard under Client Portal, Portal settings.

```bash
curl -s "${H[@]}" "$BASE/dashboard/api/portal-settings"                                    # all values, defaults, sources

curl -s -X PUT "${H[@]}" "$BASE/dashboard/api/portal-settings/weekly_report_weekday" -d '{"value":"TUE"}'
curl -s -X PUT "${H[@]}" "$BASE/dashboard/api/portal-settings/weekly_report_time" -d '{"value":"10:00"}'
curl -s -X DELETE "${H[@]}" "$BASE/dashboard/api/portal-settings/weekly_report_time"      # back to the env default
```

An invalid value returns **422** with the reason. An unknown key returns **404**. The reference table of every setting is in the README.

Moving the weekday or time within the same week does not produce a second report for that period, because the period key depends only on the week of the due slot.

## Weekly report

### What is produced, and when

- **Due slot:** the most recent scheduled weekday and time (JST) at or before now.
- **Period:** the full ISO week before the due slot's week, by the alert's received time. Example: the slot Monday 9 November 2026 09:00 JST covers Monday 2 November 00:00 to Monday 9 November 00:00 JST (end exclusive), period key `2026-W45`.
- **Workbook** (archived and downloadable): LOW and MEDIUM alerts only, with the 12 fields `alert_id`, `eset_alert_id`, `received_at_jst`, `occurred_at_jst`, `risk_level`, `detection_name`, `endpoint_name`, `action_taken`, `threat_handled`, `ai_alert_summary_ja`, `ai_risk_reason_ja`, `engineer_recommendations`. Japanese headers, plus an info sheet.
- **Summary:** counts for all four levels are recorded for every period. CRITICAL and HIGH alerts are counted and listed (up to `weekly_report_max_findings_listed`) in the email body, but they are not in the workbook.
- **Zero LOW/MEDIUM alerts in the period:** the counts and findings are still recorded, but no workbook is written (`has_file: false`). The portal shows "no file" for that week, and the download endpoints return 404.

### Archive location

Workbooks are written to `reports/weekly/<period_key>.xlsx` beside `OUTPUT_DIR`. With the default `OUTPUT_DIR=output/alerts` that is `output/reports/weekly/2026-W45.xlsx`. It shares the persistent volume that holds `OUTPUT_DIR`.

### Scheduling, retries and the baseline

- The scheduler checks every `weekly_report_check_interval_seconds` (default 60). It does nothing while `weekly_report_enabled` is off.
- **First enable:** the current period is recorded as a baseline (status `SKIPPED`), so no report is produced for a past week. The first report is the next scheduled one.
- **Idempotent:** each period is claimed in the database and produced once, including across restarts.
- **Failures** are recorded as `FAILED` with the error text. The scheduler retries a failed period until it has been attempted **3 times in total**. A run stuck in `CLAIMED` for 15 minutes is taken over on the next check. Manual runs are not limited by that cap.
- **Missed slots:** only the most recent due slot is considered. If the service was down for the whole slot and the next slot has also passed, that period is **not** produced automatically. Run it by hand through the API (below). **Generate / Run now** in the panel only produces the latest due period.

### Status values

| Status | Meaning |
|---|---|
| `GENERATED` | Counts stored, workbook archived if there were LOW/MEDIUM alerts. No email sent |
| `QUEUED` | Report email handed to the outbox (only when email is enabled) |
| `NO_RECIPIENTS` | Email enabled, but no recipients are configured (`weekly_report_emails`, then `client_notification_emails`) |
| `FAILED` | Generation or queueing failed. See `error` |
| `CLAIMED` | A run currently owns the period |
| `SKIPPED` | Deliberately not produced (the first-enable baseline) |

### Email

**Not enabled in this release.** `weekly_report_email_enabled` defaults to off and has no env variable, so it can only be switched on from the dashboard. When it is on, the email goes to `weekly_report_emails` (or `client_notification_emails` if blank). The workbook is attached only if `email_attachments_enabled` is on and the file is no larger than `email_attachment_max_bytes`. Otherwise the email links to the portal.

### Operating the report

Use the **Weekly reports** panel on the dashboard's Client Portal tab:

- **Header:** whether automatic generation is on, the schedule (day and time, JST), the next run, the next period and the latest due period. A line says whether email delivery is on. Email is off in this release, so reports are generated only.
- **Generate / Run now:** produces the latest due period. If that period is already generated, nothing is generated again, and the panel points you to **Regenerate**.
- **Preview xlsx:** downloads the workbook for the latest due period. Nothing is stored or sent.
- **History table:** one row per period, with status, counts for LOW, MEDIUM, HIGH and CRITICAL, file (Yes or No), trigger (Scheduled, Manual or Baseline), completed time and any error.
- **Per row:** **Download** (when the period has a file) and **Regenerate**. Regenerate asks you to confirm first. It overwrites the archived file and, when email is on, sends the report again.
- **High-risk findings:** a period with HIGH or CRITICAL alerts has a **High-risk findings (n)** list. Expand it to see each alert's ID, risk, detection, endpoint and AI summary.

The same operations as API calls, as an alternative for scripts:

```bash
# Schedule, next run, latest due period, and history (status, counts, attempts, error, has_file)
curl -s "${H[@]}" "$BASE/dashboard/api/reports/weekly"

# Preview a period's workbook. Nothing is stored or sent. Omit period_key for the latest due period.
curl -s "${H[@]}" -o preview.xlsx "$BASE/dashboard/api/reports/weekly/preview?period_key=2026-W45"

# Produce a period now. {} means the latest due period. A period already produced returns "action":"none".
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/reports/weekly/run" -d '{"period_key":"2026-W45"}'

# Regenerate a finished period. Overwrites the archive. When email is on, re-queues it as weekly-report-2026-W45-r1, -r2, ...
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/reports/weekly/run" -d '{"period_key":"2026-W45","regenerate":true}'

# Download the archived workbook
curl -s "${H[@]}" -o report.xlsx "$BASE/dashboard/api/reports/weekly/2026-W45/download"
```

The run response's `action` is `generated`, `queued`, `no_recipients`, `none` or `failed`.

## Recommendations

- Engineers add and retract recommendations in the dashboard: open an alert, then use the **Recommendations** section of its detail.
- Clients see **active** recommendations on the alert and in exports (`engineer_recommendations`). Retracted ones are hidden from clients, but kept in the record along with the retraction reason.
- API:
  ```bash
  curl -s -X POST "${H[@]}" "$BASE/dashboard/api/alerts/<correlation_id>/recommendations" \
    -d '{"body":"Isolate the endpoint and reset the affected account.","author":"engineer-a"}'
  curl -s -X POST "${H[@]}" "$BASE/dashboard/api/recommendations/<id>/retract" \
    -d '{"author":"engineer-a","reason":"Superseded by a later step"}'
  ```
  Body is up to 4000 characters, author up to 100, reason up to 500. The create response always carries `"notification": {"queued": false, "reason": "email_notifications_deferred"}`.
- **No email is sent for recommendations in this release.** The recipient setting is kept for when that is switched on.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| Sign-in page says the portal is unavailable. API returns **404** `client portal disabled` | `client_portal_enabled` is off, or the dashboard key is blank or shorter than 16 characters (the server logs `client_portal_refused_unsafe_config` with the reason) | Check the setting in Portal settings. Fix the key in the secret and restart if it is wrong |
| Turning the portal on returns **409** | The dashboard key is blank or too short. The message says which | Fix the key, restart the container, then turn the portal on again |
| The app refuses to start in production: `client portal is enabled but ...` | The portal was enabled, and the key was then blanked or shortened | Restore a key of 16+ characters. If that is not possible right now, delete the `rt.client_portal_enabled` row in the `app_settings` table (the env default `CLIENT_PORTAL_ENABLED=false` then applies) and restart |
| A correct password gets **401** `Invalid username or password` | The account is locked (`client_login_max_failures` wrong passwords in a row, locked for `client_login_lockout_minutes`), or it is disabled. The API deliberately returns the same message for all of these | `GET` the user list. Unlock or enable the account, or wait out the lockout |
| **429** `Too many failed attempts` | More than `AUTH_MAX_FAILURES` (default 20) failed credential checks from one address within `AUTH_FAILURE_WINDOW_SECONDS` (default 600). This blocks authenticated routes from that address, not only the login | Wait for `Retry-After`. If many clients share one address, the portal is probably behind a proxy: set `FORWARDED_ALLOW_IPS` so each client has its own address |
| A client is signed out after a while | Idle timeout (60 min by default), absolute limit (12 h), a revoked session, or a disabled account | Expected. Sign in again. Adjust the settings if the timeouts are too short |
| A week shows "no file" | No LOW or MEDIUM alerts in that period, so no workbook was written | Expected. The counts are still shown. The download endpoints return 404 |
| A period shows `FAILED` | The generation error is in `error`. The scheduler retries up to 3 attempts in total | Fix the cause, then run the period by hand (`POST .../run`, see Operating the report). Manual runs are not limited |
| No report at the due time | `weekly_report_enabled` is off, or the service was down through the slot and the next slot has passed | Check the setting. Run the missed period through the API (see Operating the report) |
| The report email never arrives | Email is not enabled in this release (`weekly_report_email_enabled` is off by default). If it is on and the status is `NO_RECIPIENTS`, no recipients are set | Expected while email is off. Set recipients if you enable it |
| Export returns **429** `An export is already running` | One export at a time per user | Wait for the first export to finish |
| Export returns **400** `limit must be between 1 and N` | The requested count is above `client_export_max_alerts` | Lower the count, or raise the setting |
| The **Portal Settings** panel shows a load error | The browser may be using a cached copy of the dashboard's static files | Hard-refresh the page (Ctrl+Shift+R, or Cmd+Shift+R on macOS) |
| Run now / regenerate returns **400** for a week | A manual run of a week that has not ended yet is refused, because it would archive a partial report and stop the scheduler from producing the real one | Wait until the week has ended. Preview still works for the current week |
| A client API request returns **413** | Requests to `/client/api/*` are limited to 64 KB (this protects the unauthenticated login from memory exhaustion) | Expected for oversized bodies; normal use is far below the limit |
| Many clients behind one proxy share the login throttle, or a client can dodge the per-address limit | `FORWARDED_ALLOW_IPS=*` makes the app trust the leftmost `X-Forwarded-For` entry. That is only safe when your edge **replaces** the header (the AWS Caddy setup does). If your platform appends to a client-supplied header, set `FORWARDED_ALLOW_IPS` to the proxy's address instead. The per-account lockout applies either way | Review `FORWARDED_ALLOW_IPS` for your platform |

## Deployment

Caddy routing (`/client`, `ClientCidr`), patching an existing instance with `deploy/aws/update_config.sh`, and rollout with `deploy/aws/release.sh` are all covered in [AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md), section 5. Changing `DASHBOARD_ACCESS_KEY` or any other environment variable requires a container restart. Dashboard changes do not.
