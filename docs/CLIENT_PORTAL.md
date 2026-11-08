# Client portal: operator runbook

For engineers who run the platform. The feature overview, the full settings table and the complete API list are in the README section [Client portal and weekly report](../README.md#client-portal-and-weekly-report). The client-facing quick start is [CLIENT_PORTAL_GUIDE_JA.md](CLIENT_PORTAL_GUIDE_JA.md). Deployment (the Caddy `/client` route, `ClientCidr`, rollout) is in [AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md), section 5.

## Before you start

- **Everything is configured at runtime from the engineering dashboard.** There is no CLI, and after deployment no `.env` edit is needed. Environment variables only set defaults. A value saved in the dashboard is stored in the database, takes precedence, and applies on the next read without a restart. Deleting the dashboard value returns the setting to its env default.
- **Exception:** `DASHBOARD_ACCESS_KEY` is an environment variable only. Change it in the deployment secret and restart the container.
- **Manage it in the dashboard's Client Portal tab first.** It has four panels: **At a glance** (the portal on/off switch and address, how many accounts can sign in, the weekly report schedule and latest report, and a **What to do next** list), **Client accounts**, **Weekly reports** and **Portal settings** (grouped into sections; only the weekly report schedule is expanded by default). The API calls in this runbook do the same things and are an alternative for scripts.

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
6. **Set `client_portal_enabled` to on.** Use the **Enable portal** button in the **At a glance** panel, or the **Enable client portal** setting under Portal settings, **Advanced**. The portal stays off until you do this. If the key is blank or shorter than 16 characters, the dashboard refuses with **409** and the message says which problem it found.
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

Manage accounts in the **Client accounts** panel on the dashboard's Client Portal tab (the portal address and switch are in the **At a glance** panel above it):

- **Portal address and switch (At a glance panel):** the client portal URL with a **Copy** button, and the portal state with an **Enable portal** or **Disable portal** button. If the switch cannot be turned on, the reason is shown next to it (for example, a dashboard key that is too short). If the portal is on but the server is refusing sign-ins, the state reads **On, but refusing sign-ins**.
- **Add an account:** press **Add account**, then enter a username and, optionally, a display name and a password. Leave the password blank to generate a strong one.
- **Accounts table:** account (username and display name), status (**Active**, **Disabled**, **Locked** and/or **Under attack**; underneath it says how many addresses or networks are locked out and whether the account is in backstop mode, see [Sign-in protection](#sign-in-protection)). The At a glance steps also list accounts that are under attack, last sign-in in JST (with the number of active sessions when there are any), and actions.
- **Actions per account:** **Reset password**, **Enable** (shown when the account is disabled) and **Unlock** (shown when it is locked) are always visible; **Disable**, **Sign out everywhere** and **Delete** are under **More**. Reset password opens a field: type a new password, or leave it blank to generate one. Delete asks you to confirm in the same row.
- **Generated and reset passwords** are shown once, in a box above the table, with a **Copy** button. Passwords are not stored, so the box cannot show one again after it is dismissed, or after you leave the Client Portal tab. If a password is lost, reset it.

The same actions as API calls, as an alternative for scripts:

```bash
# List accounts (id, username, disabled, locked, locked_until, locked_addresses,
# locked_networks, throttled (= backstop mode), failed_attempts (= account score), active_sessions)
curl -s "${H[@]}" "$BASE/dashboard/api/portal/users"

# Create an account. Omit "password" to have one generated.
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users" \
  -d '{"username":"tanaka.a","display_name":"田中様（A社）"}'        # 201; "generated_password" is returned once

# Reset a password (omit the body to generate one). Also clears every lock-out, forgets the
# account's known addresses and ends all sessions.
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users/<id>/password" -d '{}'

# Disable or enable an account (disabling also ends its sessions)
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users/<id>/disable"
curl -s -X POST "${H[@]}" "$BASE/dashboard/api/portal/users/<id>/enable"

# Clear every lock-out of the account: locked-out addresses and networks, and the account score
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
- **Audit log** (structlog): `client_user_created`, `client_user_password_reset`, `client_user_disabled`, `client_user_enabled`, `client_user_unlocked`, `client_user_sessions_revoked`, `client_user_deleted`, each with `user_id` and `account` (the stored username). Passwords and tokens are never logged.

## Sign-in protection

The rule the design is built around: **nothing an attacker does from other networks can make a correct password fail from yours.** There is no account-wide refusal. Behind Caddy the client address is the one the trusted proxy reports (`FORWARDED_ALLOW_IPS`, see [Deployment](#deployment)).

- **Per address** (an IPv4 address, an IPv6 `/64`): after `client_login_max_failures` (default 10) wrong passwords in a row, **that address** is locked out of **that account** for `client_login_lockout_minutes` (default 15). The account still signs in normally from anywhere else.
- **Account score:** every wrong password for the account, from any address, adds 1 to a score. The score drains continuously by `client_login_account_max_failures` (default 100) every `client_login_account_decay_hours` (default 24), so roughly 4 per hour. It never resets at a boundary.
- **Backstop mode** (score at or above `client_login_account_max_failures`): a wrong password from an address that has **not** signed in to the account in the last 30 days is also counted against its **network** (IPv4 `/24`, IPv6 `/48`). After `client_login_backstop_max_failures` (default 3) such failures, that network is locked out of the account for `client_login_lockout_minutes`. Each further wrong password from it doubles the lock (15 min, 30 min, 1 h, ...), up to `client_login_backstop_max_lock_hours` (default 24). A network's count is kept for 7 days after its last wrong password, so the lock does not start over when it ends. A real user on a network the attacker is not using is never affected, even on a new device or a new network, and can still mistype twice. An address that signed in recently is not network-locked either.
- **Same answer, same work:** every refusal (unknown username, wrong password, locked-out address or network, disabled account) gets the same `401 Invalid username or password`. Every attempt does the same work whatever the outcome: it reads the policy, looks the name up once, runs the password hash (against a dummy hash for an unknown name), then runs the same database statements in one transaction. So the response does not reveal whether an account exists. This is a same-work guarantee, not a measured constant time.
- **Passwords** must be 12 to 256 characters and not the username, and they must not be built only from a short list of common words and names (plus digits, symbols, keyboard walks such as `qwerty` or `1qaz2wsx`, or the username). That rejects `Welcome2026!!`, `P@ssw0rd2026`, `Tokyo2026Summer!` and `qwertyuiop12`. Generated passwords and passphrases such as `correct horse battery` pass. The rule applies when a password is set; existing passwords are not re-checked.
- **Unlock** (dashboard or `POST .../unlock`) clears the account's locked-out addresses and networks and its score. **Reset password** does the same and also forgets the account's known addresses.
- Every address is also limited by the shared `AUTH_MAX_FAILURES` / `AUTH_FAILURE_WINDOW_SECONDS` limit (429 for that address).
- Old records are removed automatically: an address after 24 hours without a failure (or 30 days after its last sign-in), and a network after 7 days without a failure. The table is capped at 50,000 rows that do not mark a known address. Address rows go first, then network rows, and a known address is never evicted.

**How many guesses an attacker gets (defaults).** Take an attacker who knows the username, has unlimited addresses spread over *k* networks (IPv4 `/24` or IPv6 `/48`), and never knows the password.

- *Outside backstop mode* each checked guess raises the score by 1, and the score only falls by 100 a day. So all such guesses together are at most 99 + 100 per day, whatever the number of addresses.
- *In backstop mode* each network gets 3 guesses, then locks of 15 min, 30 min, 1 h, 2 h, 4 h, 8 h and 16 h. That is at most 9 guesses on the first day (3 + 6 more inside 24 h), then about 1 a day (the lock is capped at 24 h).
- *Total:* at most about **199 + 9k on the first day and 100 + k per day after.** For one network (for example ten IPv4 addresses in one `/24`, or an IPv6 `/60`), that is about 208, then about 101 a day. For 10 networks it is about 289, then about 110 a day.
- The test suite simulates this attacker over two days: 1 network got 166 and 66 checked guesses, and 4 networks got 169 and 66.
- *Earlier designs:* the original account-wide lock allowed 960 a day (10 per 15 minutes) but let anyone lock the client out. The interim account-wide slow-down allowed about 3,960 a day.
- Only an attacker with very many separate networks (a botnet) gets more: about *k* a day, plus 9 per new network. Against that, the password rule above and the `client_account_throttled` alert are the defence.

Log events, for alerting:

- `client_account_throttled`: the account entered backstop mode. Fields: `user_id`, `client_ip`, `account_failures`. This is the "account under attack" signal; the dashboard also shows **Under attack** on the account.
- `client_account_locked`: an address or network was locked out of an account. Fields: `user_id`, `client_ip`, `scope` (`address` or `network`), `lockout_minutes`, `failed_attempts`.
- `client_login_rejected`, with `reason` = `bad_password`, `address_locked`, `network_locked`, `disabled` or `unknown_user`.
- `untrusted_proxy_headers`: a private-network peer sent `X-Forwarded-For` that was not applied. See [Deployment](#deployment).

**What was typed into the username box is never logged** (a password pasted there by mistake would otherwise end up in the log). Events name an existing account only by `user_id`. An unknown name is logged as `reason=unknown_user` and `client_ip`, with no identifier or hash of the name. `client_login_failed` carries only `client_ip`.

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
- **Missed slots:** only the most recent due slot is considered. If the service was down for the whole slot and the next slot has also passed, that period is **not** produced automatically. Run it by hand through the API (below). **Create report now** in the panel only produces the latest due period.

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

- **Header:** whether automatic creation is on and the schedule (day and time, JST), a line saying whether email delivery is on, and which week **Create report now** would produce. Email is off in this release, so reports are generated only. The next run and the period it covers are shown in the **At a glance** panel.
- **Create report now:** produces the latest due period. If that period is already generated, nothing is generated again, and the panel points you to **Regenerate**.
- **Preview (xlsx):** downloads the workbook for the latest due period. Nothing is stored or sent.
- **History table:** one row per period (dates and period key), with status and any error, the alert total with the non-zero levels underneath (and "No Excel file" when the period has no workbook), the completed time in JST with the trigger (Scheduled, Manual or Baseline) underneath, and the actions.
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
| A correct password gets **401** `Invalid username or password` | The client's own address is locked out of the account (`client_login_max_failures` wrong passwords in a row from it), or, in backstop mode, its network is (wrong passwords from that network), or the account is disabled. Other people's wrong passwords from other networks never cause this. The API deliberately returns the same message for all of these. `client_login_rejected` in the log has the `reason` | `GET` the user list (`locked_addresses`, `locked_networks`, `throttled`). Unlock or enable the account, or wait |
| **429** `Too many failed attempts` | More than `AUTH_MAX_FAILURES` (default 20) failed credential checks from one address within `AUTH_FAILURE_WINDOW_SECONDS` (default 600). This blocks authenticated routes from that address, not only the login | Wait for `Retry-After`. If many clients share one address, the portal is probably behind a proxy: set `FORWARDED_ALLOW_IPS` so each client has its own address |
| A client is signed out after a while | Idle timeout (60 min by default), absolute limit (12 h), a revoked session, or a disabled account | Expected. Sign in again. Adjust the settings if the timeouts are too short |
| A week shows "no file" | No LOW or MEDIUM alerts in that period, so no workbook was written | Expected. The counts are still shown. The download endpoints return 404 |
| A period shows `FAILED` | The generation error is in `error`. The scheduler retries up to 3 attempts in total | Fix the cause, then run the period by hand (`POST .../run`, see Operating the report). Manual runs are not limited |
| No report at the due time | `weekly_report_enabled` is off, or the service was down through the slot and the next slot has passed | Check the setting. Run the missed period through the API (see Operating the report) |
| The report email never arrives | Email is not enabled in this release (`weekly_report_email_enabled` is off by default). If it is on and the status is `NO_RECIPIENTS`, no recipients are set | Expected while email is off. Set recipients if you enable it |
| Export returns **429** `An export is already running` | One export at a time per user | Wait for the first export to finish |
| Export returns **400** `limit must be between 1 and N` | The requested count is above `client_export_max_alerts` | Lower the count, or raise the setting |
| The **Portal settings** panel shows a load error | The browser may be using a cached copy of the dashboard's static files | Hard-refresh the page (Ctrl+Shift+R, or Cmd+Shift+R on macOS) |
| Run now / regenerate returns **400** for a week | A manual run of a week that has not ended yet is refused, because it would archive a partial report and stop the scheduler from producing the real one | Wait until the week has ended. Preview still works for the current week |
| A client API request returns **413** | Requests to `/client/api/*` are limited to 64 KB (this protects the unauthenticated login from memory exhaustion) | Expected for oversized bodies; normal use is far below the limit |
| Many clients behind one proxy share the login throttle, or a client can dodge the per-address limit | `FORWARDED_ALLOW_IPS=*` makes the app trust the leftmost `X-Forwarded-For` entry. That is only safe when your edge **replaces** the header (the AWS Caddy setup does). If your platform appends to a client-supplied header, set `FORWARDED_ALLOW_IPS` to the proxy's address instead. In the Docker Compose setup the proxy reaches the container from Docker's bridge gateway, so `docker-compose.yml` trusts Docker's private networks. If the log shows `untrusted_proxy_headers`, the proxy is not trusted and every client shares its address | Review `FORWARDED_ALLOW_IPS` for your platform |

## Deployment

**Client addresses behind a proxy.** The sign-in lock-out and the 429 throttle work per client address, so the app must see each visitor's real address:

- **AWS (Caddy):** `FORWARDED_ALLOW_IPS=*`, already set by the template.
- **Docker Compose with a proxy on the host:** the proxy reaches the container from Docker's bridge gateway (an address in `172.16.0.0/12` or `192.168.0.0/16`), not from `127.0.0.1`. `docker-compose.yml` therefore sets `FORWARDED_ALLOW_IPS` to `127.0.0.1,172.16.0.0/12,192.168.0.0/16`, which overrides `.env`. With trusted networks (not `*`), uvicorn reads `X-Forwarded-For` from the right, so a header forged by a visitor is not believed. This is safe while the port stays published on `127.0.0.1` only. If you publish it on all interfaces, set the proxy's exact address instead.
- **Misconfiguration:** when a request from a private-network peer carries `X-Forwarded-For` that was not applied, the app logs `untrusted_proxy_headers` with the peer address (at most hourly per peer). That means every client currently shares that address.

Caddy routing (`/client`, `ClientCidr`), patching an existing instance with `deploy/aws/update_config.sh`, and rollout with `deploy/aws/release.sh` are all covered in [AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md), section 5. Changing `DASHBOARD_ACCESS_KEY` or any other environment variable requires a container restart. Dashboard changes do not.
