# Hiding test alerts (or, if needed, removing them)

For engineers with AWS access. **Hiding is the normal way** to get test alerts out of the way: the alert's data stays on the server, but the dashboard, the client portal, exports and the weekly / on-demand reports leave it out. It needs no downtime and `unhide` reverses it. Permanent removal (`purge`, at the end) is only for when the data itself must go.

"Test alerts" here means two kinds of alert, both approved:

- **Developer test alerts:** sample alerts we sent directly to the platform while building and testing the webhook. They are recognised by their made-up ESET alert ids (step 3).
- **ESET PROTECT test webhooks:** notifications sent from the ESET PROTECT console's test function while the webhook was being set up. They are audit-log events with the subject "TEST", not threat detections. About 21 arrived over roughly 15 hours before 2 October 2026, and the dashboard shows them as MEDIUM with "UNKNOWN" fields (`ESET_FLOW_EVIDENCE_AUDIT.md`, addendum).

## How hiding works

`hide` adds one row per alert to the `hidden_alerts` table. Nothing else changes. The platform leaves those alerts out of:

| Where | Hidden alerts |
|---|---|
| Dashboard: activity table, Alerts view, AI Content, stats, spreadsheet export | Left out |
| Client portal: alert list, Home charts and counts, alert detail, export | Left out (detail returns "not found") |
| Weekly reports and on-demand reports | Left out of counts, findings and the workbook |
| Dashboard alert detail opened by id (`/dashboard/api/jobs/<id>`) | Still opens, for engineers |

Not changed: emails and reports already sent, weekly report files already generated (regenerate a week's report from the Weekly reports panel if it must change), and the application log.

The same can be done over the dashboard API (dashboard key, from the admin network): `POST /dashboard/api/alerts/hide` with `{"correlation_ids": [...], "reason": "..."}`, `POST /dashboard/api/alerts/unhide` with `{"correlation_ids": [...]}`, and `GET /dashboard/api/alerts/hidden`.

## Steps

**Prerequisite:** the platform version with hidden alerts must be deployed. It creates the `hidden_alerts` table on start-up. Until it is, `hide` refuses with "no hidden_alerts table".

All commands run on the instance: AWS Console → EC2 → `eset-soc-lite-poc` → Connect → Session Manager, then `sudo -i`.

**Run the script inside the app container, never as root on the host.** The database is in SQLite WAL mode. If root opens it, even just to read, SQLite can create its `soc_lite.db-wal` / `-shm` files owned by root, and the app (UID 10001) can no longer write its database. Piping the script into `docker exec` runs it as the app's own user, against `/data`:

```bash
S="docker exec -i soc-lite python - --data-dir /data"   # used below as: $S <command> < /opt/soc-lite/purge_alerts.py
```

1. **Put the script on the host** at `/opt/soc-lite/purge_alerts.py`. It is not in the container image. Paste it with `cat > /opt/soc-lite/purge_alerts.py`, or use the compressed paste block and check its `sha256sum`.

2. **If anyone has already run the script as root on the host**, fix the ownership first:
   ```bash
   ls -l /srv/soc-data/app/          # every file should be owned by 10001
   chown -R 10001:10001 /srv/soc-data/app
   ```

3. **List the alerts** (read-only):
   ```bash
   $S list --csv - < /opt/soc-lite/purge_alerts.py > /tmp/alerts.csv
   $S list < /opt/soc-lite/purge_alerts.py | grep -E "test alert id|ESET|check"
   ```
   The summary line says how many developer tests and ESET test webhooks were found. The CSV has the id, received time (JST), `hidden`, `test_evidence`, `payload_subject` (the subject or event type from the original payload), source, risk, ESET severity, ESET alert id, endpoint and detection. `--known-tests` selects the first two kinds below; the "(check)" kinds are never selected automatically.
   - `test alert id …`: a developer test. The ESET alert id came from our test tools (`send_test_webhook.sh`, `send_test_syslog.py`, `run_poc_cases.py`, the sample payloads), or is a hand-typed id containing test, repro, demo, sample or dummy (`test-001`, `live-repro-…`). Real ESET alert ids don't look like this.
   - `ESET test webhook (subject TEST)`: ESET PROTECT's test notification.
   - `ESET audit-log event, not a detection (check)`: an ESET audit-log event without the TEST subject. It may still be a test; check its time and subject.
   - `test host name … (check)`: only the host name matches our sample data, and a real host could share it. Check each one.
   - Blank: no sign of a test.

   **Cross-check the ESET test webhooks.** About 21 are expected, received over roughly 15 hours just before 2 October 2026 (JST). The ESET format was read from the AI's summary of one of them, not from a saved payload, so the key names are not certain. If the count is far off, open one of the MEDIUM rows with "UNKNOWN" fields from that window in the dashboard and look at its original payload. Put any test alerts the rules miss in `/tmp/test_ids.txt`, one id per line, and never a real detection such as "ウイルス対策検出". The script reads its own code from standard input, so the container can't see host files: copy the list into the data volume with `install -o 10001 -g 10001 /tmp/test_ids.txt /srv/soc-data/app/test_ids.txt`, then add `--ids-file /data/test_ids.txt` to the commands below.

4. **Dry run** (changes nothing). Read the whole list, check that no real detection is in it, and send it to your manager:
   ```bash
   $S hide --known-tests < /opt/soc-lite/purge_alerts.py
   ```

5. **Hide them.** The app keeps running:
   ```bash
   $S hide --known-tests --apply < /opt/soc-lite/purge_alerts.py
   ```

6. **Verify.** In the dashboard and the client portal, the test alerts are gone and the counts went down by the expected number. The list now shows them as `hidden`:
   ```bash
   $S list < /opt/soc-lite/purge_alerts.py | grep -c " yes "
   ```

**Undo:** the same selection with `unhide`, for example `$S unhide --known-tests --apply < /opt/soc-lite/purge_alerts.py`, or particular alerts with `--id`.

## Permanent removal (only if the data must go)

`purge` deletes an alert from six database tables (`jobs`, `alert_index`, `ai_traces`, `email_deliveries`, `alert_recommendations`, `alert_observations`), its result file `output/alerts/<id>.json` (the client portal rebuilds its list from these, so it must go too), `output/alerts/index.json` and the email outbox / dead-letter files. It first writes a backup folder in the data volume with a full copy of the database, the moved result files and the removed records.

The app must be stopped, because it rewrites `index.json` and the outbox while running. Webhooks get an error for about a minute, so pick a quiet time. With the container stopped, run the script in a one-off container from the same image, as the app's user:

1. Take a snapshot of the data volume: EC2 → Volumes → `eset-soc-lite-poc-data` → Actions → Create snapshot.
2. Dry run, then apply:
   ```bash
   source /opt/soc-lite/image.env
   P="docker run --rm -i --user 10001:10001 -v /srv/soc-data/app:/data --entrypoint python $IMAGE_URI - --data-dir /data"
   $P purge --known-tests < /opt/soc-lite/purge_alerts.py              # dry run, app still running
   docker stop soc-lite
   $P purge --known-tests --apply --confirm-app-stopped < /opt/soc-lite/purge_alerts.py
   docker start soc-lite
   ```
3. Check `curl https://eset-soc.villdesign.com/health` returns `"status":"ok"`, then the dashboard and the portal.
4. Keep the backup (`/srv/soc-data/app/purge-backup-<UTC time>/`) until your manager confirms, then delete it, because it still contains the removed alerts.

**Undo a purge:** stop the container. Copy the backup's `soc_lite.db` over `/srv/soc-data/app/soc_lite.db`, delete any `soc_lite.db-wal` and `soc_lite.db-shm` next to it, move the backup's `alerts/` files back to `output/alerts/`, and add the `index` / `outbox` / `dead_letter` records from `removed_records.json` back into their files. Run `chown -R 10001:10001 /srv/soc-data/app`, then start the container. Alerts that arrived after the purge are not in the backup, so restore only if nothing arrived since, or restore from the snapshot instead.
