#!/usr/bin/env python3
"""
List alerts, hide chosen alerts (for example leftover test alerts) from every
view and report, or permanently remove them, in an ESET SOC Lite data directory.

Standard library only, so it runs with the host's python3 against the data
volume directly; it does not import the application.

    # 1. List every alert, with why each one looks like a test
    python3 purge_alerts.py --data-dir /srv/soc-data/app list --csv alerts.csv

    # 2. Hide the test alerts: dry run first, then --apply. Data stays on the
    #    server, the app can keep running, and `unhide` reverses it.
    python3 purge_alerts.py --data-dir /srv/soc-data/app hide --known-tests
    python3 purge_alerts.py --data-dir /srv/soc-data/app hide --known-tests --apply

    # Only if they must be deleted for good: purge, with the container stopped
    python3 purge_alerts.py --data-dir /srv/soc-data/app purge --known-tests \
        --apply --confirm-app-stopped

`hide` adds one row per alert to hidden_alerts (created by the platform version
that supports hiding; deploy it first). The platform then leaves those alerts
out of the dashboard, the client portal, exports and weekly / on-demand reports.

What one alert (correlation id) leaves behind, all of which `purge` removes:
  database  jobs, alert_index, ai_traces, email_deliveries, alert_recommendations,
            alert_observations
  files     output/alerts/<id>.json (the result file; the client portal rebuilds
            alert_index from these, so it must go too), its entry in
            output/alerts/index.json, and its emails in output/emails/outbox.json
            and output/emails/dead_letter.json

Before changing anything, --apply writes a backup directory holding a full copy
of the database, the removed result files (moved, not deleted) and every
removed JSON record, so the purge can be undone.

Not touched: emails and weekly reports already sent, weekly report files and
their stored counts, the application log, and dedup_log (its keys are hashes
that expire within minutes).
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile

# Tables keyed by the alert's correlation id, in deletion order.
ALERT_TABLES = (
    "alert_recommendations",
    "ai_traces",
    "email_deliveries",
    "alert_observations",
    "alert_index",
    "jobs",
)
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")  # ids become file names: no paths
JST = dt.timezone(dt.timedelta(hours=9))

# ESET alert ids sent by our own test tooling; real ESET alerts never carry these.
#   scripts/send_test_webhook.sh   test-alert-<epoch>-<n>
#   scripts/send_test_syslog.py    syslog-sim-<epoch>
#   scripts/run_poc_cases.py       poc-<level>-NNNN-<hex>   (tests/fixtures/poc_cases)
#   tests/fixtures/sample_*.json, README examples: the fixed ids below
TEST_ALERT_ID_RE = re.compile(
    r"^(test-alert-\d+-\d+|syslog-sim-\d+|poc-(critical|high|medium|low)-\d{4}(-[0-9a-f]{6})?"
    r"|alert-0001|syslog-0001|high-alert-99999|low-alert-12345|med-alert-67890"
    r"|critical-alert-77777|critical-multi-endpoint-88888|syslog-alert-88888)$"
)
# Host names in that test data. Weaker evidence (a real host could share a name),
# so a host match is only flagged for review, never selected by --known-tests.
TEST_ENDPOINTS = {
    "FINANCE-PC-09", "DESKTOP-CLIENT-01", "DESKTOP-CLIENT-02", "DOMAIN-CONTROLLER-01",
    "SEC-PC-01", "SYSLOG-TARGET-PC", "MAC-FS-01", "MAC-PC-014", "MAC-PC-027",
    "MAC-PC-031", "MAC-PC-040",
}


# Hand-typed ids from manual curl tests (test-001, dup-test-001, live-repro-<epoch>,
# ai-content-repro-<epoch>, ...). A UUID can't contain these words (hex only).
TEST_WORD_RE = re.compile(r"test|repro|demo|sample|dummy", re.IGNORECASE)


# ESET PROTECT's "test webhook" sends an audit-log event, not a detection: subject
# "TEST" with fields such as domain / action / result / user / details (seen on the
# deployment around 2026-10-01; ESET_FLOW_EVIDENCE_AUDIT.md, addendum).
SUBJECT_KEYS = {"subject", "title", "raw_subject", "event_subject", "summary"}
AUDIT_KEYS = {"domain", "action", "result", "user", "details"}
DETECTION_KEYS = {"detection_name", "threat_name", "detection", "threat", "detectionname",
                  "threatname", "file_hash", "hash", "sha1", "sha256", "object_uri"}


def _walk(obj, depth=0):
    """(lower-cased key, value) pairs of a payload, nested dicts up to 3 levels."""
    if depth > 3 or not isinstance(obj, dict):
        return
    for k, v in obj.items():
        yield str(k).lower(), v
        if isinstance(v, dict):
            yield from _walk(v, depth + 1)


def eset_test_evidence(payload: dict | None) -> str:
    """Why a stored payload looks like ESET PROTECT's test webhook ('' = no sign)."""
    if not isinstance(payload, dict):
        return ""
    pairs = list(_walk(payload))
    keys = {k for k, _ in pairs}
    if any(k in SUBJECT_KEYS and isinstance(v, str) and v.strip().casefold() == "test" for k, v in pairs):
        return "ESET test webhook (subject TEST)"
    if len(keys & AUDIT_KEYS) >= 3 and not keys & DETECTION_KEYS:
        return "ESET audit-log event, not a detection (check)"
    return ""


def test_evidence(alert: dict) -> str:
    """Why this alert looks like one of our test alerts ('' = no sign)."""
    aid = alert.get("eset_alert_id") or ""
    if TEST_ALERT_ID_RE.match(aid):
        return f"test alert id {aid}"
    if TEST_WORD_RE.search(aid):
        return f"test alert id {aid} (hand-typed)"
    eset = eset_test_evidence(alert.get("_payload"))
    if eset:
        return eset
    if (alert.get("endpoint_name") or "") in TEST_ENDPOINTS:
        return f"test host name {alert['endpoint_name']} (check)"
    return ""


def _parse_payload(raw_payload: str | None) -> dict | None:
    try:
        data = json.loads(raw_payload or "")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _payload_alert_id(payload: dict | None) -> str | None:
    if payload:
        value = payload.get("alert_id") or payload.get("id")
        return str(value) if value is not None else None
    return None


def _payload_subject(payload: dict | None) -> str:
    """A short label from the original payload (subject or event type), for the reviewer."""
    for k, v in _walk(payload or {}):
        if k in SUBJECT_KEYS | {"event_type", "event", "type"} and isinstance(v, str) and v.strip():
            return v.strip()[:80]
    return ""


class Paths:
    def __init__(self, data_dir: str, db: str | None):
        self.data_dir = data_dir
        self.db = db or os.path.join(data_dir, "soc_lite.db")
        self.alerts = os.path.join(data_dir, "output", "alerts")
        self.index = os.path.join(self.alerts, "index.json")
        self.emails = os.path.join(data_dir, "output", "emails")
        self.outbox = os.path.join(self.emails, "outbox.json")
        self.dead_letter = os.path.join(self.emails, "dead_letter.json")

    def result_file(self, cid: str) -> str:
        return os.path.join(self.alerts, f"{cid}.json")


def jst(epoch: float | None) -> str:
    if epoch is None:
        return ""
    return dt.datetime.fromtimestamp(epoch, JST).strftime("%Y-%m-%d %H:%M:%S")


def connect(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        sys.exit(f"Database not found: {path}")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def existing_tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def read_json_list(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        sys.exit(f"Unexpected format (not a JSON list): {path}")
    return data


def write_json_atomic(path: str, data) -> None:
    """Replace `path` atomically, keeping its owner and mode: mkstemp creates the
    file 0600 and owned by whoever runs this (root on the host), which the
    platform container's non-root user could not read."""
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".purge_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, st.st_mode & 0o7777)
        if hasattr(os, "chown"):
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except PermissionError:
                pass  # not root: the file was ours to begin with
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


# ------------------------------------------------------------------ list

def list_alerts(conn: sqlite3.Connection) -> list[dict]:
    """Every alert, newest first: indexed alerts plus jobs that never produced a
    result (failed or still pending), so nothing is invisible to the reviewer."""
    tables = existing_tables(conn)
    rows: dict[str, dict] = {}
    if "alert_index" in tables:
        for r in conn.execute(
            "SELECT correlation_id, source, received_at, risk_level, eset_severity, "
            "eset_alert_id, endpoint_name, detection_name, pipeline_status FROM alert_index"
        ):
            rows[r["correlation_id"]] = dict(r)
    if "jobs" in tables:
        for r in conn.execute("SELECT correlation_id, source, status, created_at, raw_payload FROM jobs"):
            row = rows.get(r["correlation_id"])
            if row is None:
                row = rows[r["correlation_id"]] = {
                    "correlation_id": r["correlation_id"], "source": r["source"],
                    "received_at": r["created_at"], "pipeline_status": r["status"],
                    "risk_level": None, "eset_severity": None, "eset_alert_id": None,
                    "endpoint_name": None, "detection_name": None,
                }
            payload = _parse_payload(r["raw_payload"])
            row["_payload"] = payload
            row["payload_subject"] = _payload_subject(payload)
            if not row.get("eset_alert_id"):  # the original payload still has it
                row["eset_alert_id"] = _payload_alert_id(payload)
    hidden = hidden_set(conn) or set()
    for row in rows.values():
        row["test_evidence"] = test_evidence(row)
        row["hidden"] = "yes" if row["correlation_id"] in hidden else ""
        row.pop("_payload", None)
    return sorted(rows.values(), key=lambda r: r.get("received_at") or 0, reverse=True)


LIST_COLUMNS = ("correlation_id", "received_jst", "hidden", "test_evidence", "payload_subject", "source",
                "risk_level", "eset_severity", "eset_alert_id", "endpoint_name", "detection_name",
                "pipeline_status")
SURE = ("test alert id", "ESET test webhook")  # evidence strong enough for --known-tests


def cmd_list(args, paths: Paths) -> int:
    conn = connect(paths.db)
    alerts = list_alerts(conn)
    out_rows = [{**a, "received_jst": jst(a.get("received_at"))} for a in alerts]
    dev = sum(r["test_evidence"].startswith("test alert id") for r in out_rows)
    eset = sum(r["test_evidence"].startswith("ESET test webhook") for r in out_rows)
    check = sum(r["test_evidence"].endswith("(check)") for r in out_rows)
    # Summary on stderr, so `--csv -` (CSV on stdout) stays a clean file.
    print(f"{dev} developer test alert(s) and {eset} ESET test webhook(s) found (selected by "
          f"--known-tests); {check} more need checking by hand.", file=sys.stderr)
    if args.csv == "-":
        sys.stdout.reconfigure(encoding="utf-8")  # whatever the terminal's locale
        sys.stdout.write(chr(0xFEFF))  # BOM so Excel opens Japanese names correctly
        w = csv.DictWriter(sys.stdout, fieldnames=LIST_COLUMNS, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(out_rows)
    elif args.csv:
        # utf-8-sig so Excel opens Japanese names correctly
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=LIST_COLUMNS, extrasaction="ignore")
            w.writeheader()
            w.writerows(out_rows)
        print(f"Wrote {len(out_rows)} alerts to {args.csv}", file=sys.stderr)
    else:
        for r in out_rows:
            print("  ".join(str(r.get(c) or "-") for c in LIST_COLUMNS))
        print(f"{len(out_rows)} alerts")
    return 0


# ------------------------------------------------------------------ select

def selected_ids(args, conn: sqlite3.Connection) -> list[str]:
    ids: list[str] = list(args.id or [])
    if args.ids_file:
        with open(args.ids_file, encoding="utf-8-sig") as f:
            for line in f:
                line = line.split("#", 1)[0].split(",", 1)[0].strip()
                if line and line != "correlation_id":
                    ids.append(line)

    if args.known_tests:
        ids.extend(a["correlation_id"] for a in list_alerts(conn)
                   if a["test_evidence"].startswith(SURE))

    filters, params = [], []
    if args.endpoint:
        filters.append("endpoint_name = ?"); params.append(args.endpoint)
    if args.detection:
        filters.append("detection_name = ?"); params.append(args.detection)
    if args.source:
        filters.append("source = ?"); params.append(args.source)
    if args.received_from:
        filters.append("received_at >= ?"); params.append(parse_jst(args.received_from))
    if args.received_to:
        filters.append("received_at < ?"); params.append(parse_jst(args.received_to))
    if filters:
        if not (args.endpoint or args.detection or args.source):
            sys.exit("A date range alone is too broad: combine it with --endpoint, "
                     "--detection or --source, or list the ids.")
        sql = "SELECT correlation_id FROM alert_index WHERE " + " AND ".join(filters)
        ids.extend(r[0] for r in conn.execute(sql, params))

    if not ids:
        sys.exit("Nothing selected: pass --id, --ids-file, --known-tests or a filter "
                 "(or nothing matched it).")
    bad = [i for i in ids if not ID_RE.match(i)]
    if bad:
        sys.exit(f"Invalid alert ids (expected correlation ids): {bad[:5]}")
    return sorted(set(ids))


def parse_jst(value: str) -> float:
    """'2026-11-01' or '2026-11-01 09:00' in JST -> epoch seconds."""
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(value, fmt).replace(tzinfo=JST).timestamp()
        except ValueError:
            pass
    sys.exit(f"Bad date (use YYYY-MM-DD or 'YYYY-MM-DD HH:MM', JST): {value}")


# ------------------------------------------------------------------ purge

def plan(conn: sqlite3.Connection, paths: Paths, ids: list[str]) -> dict:
    tables = existing_tables(conn)
    marks = ",".join("?" * len(ids))
    counts = {}
    for t in ALERT_TABLES:
        if t in tables:
            counts[t] = conn.execute(
                f"SELECT COUNT(*) FROM {t} WHERE correlation_id IN ({marks})", ids
            ).fetchone()[0]
    idset = set(ids)
    return {
        "counts": counts,
        "files": [paths.result_file(i) for i in ids if os.path.exists(paths.result_file(i))],
        "index": [r for r in read_json_list(paths.index) if r.get("correlation_id") in idset],
        "outbox": [r for r in read_json_list(paths.outbox) if r.get("correlation_id") in idset],
        "dead_letter": [r for r in read_json_list(paths.dead_letter) if r.get("correlation_id") in idset],
        "unknown": [i for i in ids if not _known(conn, tables, paths, i)],
    }


def _known(conn, tables, paths: Paths, cid: str) -> bool:
    if os.path.exists(paths.result_file(cid)):
        return True
    for t in ("jobs", "alert_index"):
        if t in tables and conn.execute(f"SELECT 1 FROM {t} WHERE correlation_id = ?", (cid,)).fetchone():
            return True
    return False


def print_plan(conn: sqlite3.Connection, ids: list[str], p: dict) -> None:
    by_id = {a["correlation_id"]: a for a in list_alerts(conn)}
    print(f"Selected {len(ids)} alert(s):")
    for cid in ids:
        a = by_id.get(cid)
        if a:
            print(f"  {cid}  {jst(a.get('received_at'))}  {a.get('eset_alert_id') or '-'}  "
                  f"{a.get('risk_level') or '-'}  {a.get('endpoint_name') or '-'}  "
                  f"{a.get('detection_name') or '-'}")
        else:
            print(f"  {cid}  (no database record)")
    print("Would remove:")
    for t, n in p["counts"].items():
        print(f"  {t:<22} {n} row(s)")
    print(f"  {'result files':<22} {len(p['files'])}")
    print(f"  {'index.json entries':<22} {len(p['index'])}")
    print(f"  {'outbox emails':<22} {len(p['outbox'])}")
    print(f"  {'dead-letter emails':<22} {len(p['dead_letter'])}")
    if p["unknown"]:
        print(f"WARNING: {len(p['unknown'])} id(s) not found anywhere: {', '.join(p['unknown'][:10])}")


def apply(conn: sqlite3.Connection, paths: Paths, ids: list[str], p: dict, backup_dir: str) -> None:
    os.makedirs(os.path.join(backup_dir, "alerts"), exist_ok=False)

    # 1. Full database copy (consistent, includes the WAL) before any change.
    dest = sqlite3.connect(os.path.join(backup_dir, "soc_lite.db"))
    with dest:
        conn.backup(dest)
    dest.close()

    # 2. Removed JSON records and the id list, for an exact restore.
    with open(os.path.join(backup_dir, "removed_records.json"), "w", encoding="utf-8") as f:
        json.dump({"ids": ids, "index": p["index"], "outbox": p["outbox"],
                   "dead_letter": p["dead_letter"]}, f, indent=2, ensure_ascii=False)

    # 3. Database rows, all in one transaction.
    marks = ",".join("?" * len(ids))
    with conn:
        for t in p["counts"]:
            conn.execute(f"DELETE FROM {t} WHERE correlation_id IN ({marks})", ids)

    # 4. JSON lists, rewritten atomically.
    idset = set(ids)
    for path, removed in ((paths.index, p["index"]), (paths.outbox, p["outbox"]),
                          (paths.dead_letter, p["dead_letter"])):
        if removed:
            write_json_atomic(path, [r for r in read_json_list(path)
                                     if r.get("correlation_id") not in idset])

    # 5. Result files: moved into the backup, not deleted.
    for path in p["files"]:
        shutil.move(path, os.path.join(backup_dir, "alerts", os.path.basename(path)))


def cmd_purge(args, paths: Paths) -> int:
    conn = connect(paths.db)
    ids = selected_ids(args, conn)
    p = plan(conn, paths, ids)
    print_plan(conn, ids, p)

    if not args.apply:
        print("\nDRY RUN: nothing was changed. Re-run with --apply --confirm-app-stopped to remove these.")
        return 0
    if not args.confirm_app_stopped:
        sys.exit("\nRefusing: stop the platform container first (the app rewrites index.json and "
                 "the outbox while running), then pass --confirm-app-stopped.")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = args.backup_dir or os.path.join(paths.data_dir, f"purge-backup-{stamp}")
    apply(conn, paths, ids, p, backup_dir)
    print(f"\nRemoved {len(ids)} alert(s). Backup: {backup_dir}")
    return 0


# ------------------------------------------------------------------ hide

def hidden_set(conn: sqlite3.Connection) -> set[str] | None:
    """Ids in hidden_alerts, or None when the platform version has no such table yet."""
    if "hidden_alerts" not in existing_tables(conn):
        return None
    return {r[0] for r in conn.execute("SELECT correlation_id FROM hidden_alerts")}


def cmd_hide(args, paths: Paths) -> int:
    """Hide (or unhide) alerts: one row each in hidden_alerts. Nothing else on the
    server changes, so the app can keep running and this is undone by `unhide`."""
    conn = connect(paths.db)
    already = hidden_set(conn)
    if already is None:
        sys.exit("This database has no hidden_alerts table: deploy the platform version with "
                 "hidden alerts first (it creates the table on start-up).")
    ids = selected_ids(args, conn)
    unhide = args.cmd == "unhide"
    todo = [i for i in ids if (i in already) == unhide]
    skipped = len(ids) - len(todo)

    by_id = {a["correlation_id"]: a for a in list_alerts(conn)}
    verb = "unhide" if unhide else "hide"
    print(f"Would {verb} {len(todo)} alert(s)" + (f" ({skipped} already {'visible' if unhide else 'hidden'})" if skipped else "") + ":")
    for cid in todo:
        a = by_id.get(cid) or {}
        print(f"  {cid}  {jst(a.get('received_at'))}  {a.get('test_evidence') or '-'}  "
              f"{a.get('payload_subject') or '-'}  {a.get('endpoint_name') or '-'}")
    if not args.apply:
        print(f"\nDRY RUN: nothing was changed. Re-run with --apply to {verb} these.")
        return 0
    with conn:
        if unhide:
            conn.executemany("DELETE FROM hidden_alerts WHERE correlation_id = ?", [(i,) for i in todo])
        else:
            now = dt.datetime.now(dt.timezone.utc).timestamp()
            conn.executemany(
                "INSERT INTO hidden_alerts (correlation_id, hidden_at, hidden_by, reason) VALUES (?,?,?,?) "
                "ON CONFLICT(correlation_id) DO NOTHING",
                [(i, now, "purge_alerts.py", args.reason) for i in todo],
            )
    print(f"\n{verb.capitalize()}d {len(todo)} alert(s). Undo with `{'hide' if unhide else 'unhide'}` and the same selection.")
    return 0


def _selection_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--id", action="append", help="correlation id; repeatable")
    p.add_argument("--ids-file", help="file with one correlation id per line (# comments allowed; a CSV from `list` works if its first column is the id)")
    p.add_argument("--known-tests", action="store_true",
                   help="select our developer test alerts (test-style ESET alert ids) and ESET PROTECT "
                        "test webhooks (audit-log events with subject TEST); see `list` for the evidence")
    p.add_argument("--endpoint", help="exact endpoint name")
    p.add_argument("--detection", help="exact detection name")
    p.add_argument("--source", help="exact source")
    p.add_argument("--received-from", help="JST, inclusive: YYYY-MM-DD or 'YYYY-MM-DD HH:MM'")
    p.add_argument("--received-to", help="JST, exclusive")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="data", help="directory holding soc_lite.db and output/ (production host: /srv/soc-data/app)")
    ap.add_argument("--db", help="database path, if not <data-dir>/soc_lite.db")
    sub = ap.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("list", help="list every alert, newest first")
    lp.add_argument("--csv", help="write the list to this CSV file (opens in Excel); - for standard output")

    hp = sub.add_parser("hide", help="hide selected alerts from every view and report, keeping all data "
                                     "(dry run unless --apply; the app can keep running)")
    _selection_args(hp)
    hp.add_argument("--reason", default="test alert", help="stored with each hidden alert")
    hp.add_argument("--apply", action="store_true", help="actually hide (default: dry run)")

    up = sub.add_parser("unhide", help="bring hidden alerts back (dry run unless --apply)")
    _selection_args(up)
    up.add_argument("--apply", action="store_true", help="actually unhide (default: dry run)")

    pp = sub.add_parser("purge", help="permanently remove selected alerts (dry run unless --apply)")
    _selection_args(pp)
    pp.add_argument("--apply", action="store_true", help="actually remove (default: dry run)")
    pp.add_argument("--confirm-app-stopped", action="store_true", help="required with --apply")
    pp.add_argument("--backup-dir", help="where the backup goes (default: <data-dir>/purge-backup-<UTC time>)")

    args = ap.parse_args(argv)
    paths = Paths(args.data_dir, args.db)
    if args.cmd == "list":
        return cmd_list(args, paths)
    if args.cmd in ("hide", "unhide"):
        return cmd_hide(args, paths)
    return cmd_purge(args, paths)


if __name__ == "__main__":
    sys.exit(main())
