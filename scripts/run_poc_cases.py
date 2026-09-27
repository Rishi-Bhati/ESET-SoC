"""
Runs the client's PoC test cases (tests/fixtures/poc_cases/*.json) through the
real pipeline with the REAL configured AI provider, and writes what came out
for review.

    # in-process, isolated temp storage, email delivery forced off:
    .venv/bin/python scripts/run_poc_cases.py
    .venv/bin/python scripts/run_poc_cases.py --out poc_report.json

    # against a running deployment (uses its own storage and notifications):
    .venv/bin/python scripts/run_poc_cases.py --url https://soc.example.com --token "$ESET_WEBHOOK_AUTH_TOKEN" \
        --dashboard-key "$DASHBOARD_ACCESS_KEY"

The in-process mode reads the same configuration as the app (.env / environment
/ Secrets Manager), so it needs AI_PROVIDER, the model name and an API key or
secret ID. Each case costs one AI generation.
"""
import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
CASES_DIR = os.path.join(ROOT, "tests", "fixtures", "poc_cases")

EXPECTED = {
    "low_handled_detection": "LOW",
    "medium_partially_handled": "MEDIUM",
    "high_malware_not_handled": "HIGH",
    "critical_ransomware_behavior": "CRITICAL",
    "critical_multiple_endpoints": "CRITICAL",
}


def load_cases() -> dict[str, dict]:
    cases = {}
    for name in EXPECTED:
        with open(os.path.join(CASES_DIR, f"{name}.json"), encoding="utf-8") as f:
            payload = json.load(f)
        payload = {k: v for k, v in payload.items() if not k.startswith("_")}
        # Unique per run so deduplication never swallows a re-run.
        payload["alert_id"] = f"{payload['alert_id']}-{uuid.uuid4().hex[:6]}"
        cases[name] = payload
    return cases


async def run_in_process(cases: dict[str, dict]) -> dict[str, dict]:
    from src.config import settings

    work = tempfile.mkdtemp(prefix="soc_poc_")
    settings.sqlite_db_path = os.path.join(work, "poc.db")
    settings.output_dir = os.path.join(work, "alerts")
    settings.email_delivery_enabled = False

    from src.storage.database import init_db
    from src.storage import job_store
    from src.pipeline.orchestrator import process_alert_pipeline
    from src.ingestion.webhook_handler import WebhookIngestionHandler

    await init_db()
    results = {}
    for name, payload in cases.items():
        cid = str(uuid.uuid4())
        # Exactly what POST /webhook/eset stores and hands to the pipeline.
        job_payload = WebhookIngestionHandler().parse(payload).model_dump()
        await job_store.create_job(cid, "WEBHOOK", job_payload)
        started = time.monotonic()
        await process_alert_pipeline(cid, job_payload, "WEBHOOK")
        with open(os.path.join(settings.output_dir, f"{cid}.json"), encoding="utf-8") as f:
            result = json.load(f)
        result["_elapsed_s"] = round(time.monotonic() - started, 1)
        results[name] = result
    print(f"(temporary storage: {work})", file=sys.stderr)
    return results


def run_remote(cases: dict[str, dict], url: str, token: str, dashboard_key: str) -> dict[str, dict]:
    import httpx

    results = {}
    with httpx.Client(base_url=url.rstrip("/"), timeout=30) as client:
        for name, payload in cases.items():
            res = client.post("/webhook/eset", json=payload, headers={"Authorization": f"Bearer {token}"})
            res.raise_for_status()
            cid = res.json()["correlation_id"]
            headers = {"X-Dashboard-Key": dashboard_key} if dashboard_key else {}
            for _ in range(180):
                body = client.get(f"/dashboard/api/jobs/{cid}", headers=headers).json()
                if body["job"]["status"] in ("SUCCESS", "PARTIAL", "FAILED") and body.get("result"):
                    results[name] = body["result"]
                    break
                time.sleep(1)
            else:
                results[name] = {"error": "timed out waiting for the pipeline"}
    return results


def summarize(results: dict[str, dict]) -> int:
    failures = 0
    for name, result in results.items():
        expected = EXPECTED[name]
        level = result.get("risk_level")
        run = result.get("ai_run") or {}
        ok = level == expected and result.get("pipeline_status") == "SUCCESS"
        failures += not ok
        print(f"\n{'PASS' if ok else 'FAIL'}  {name}: risk {level} (expected {expected}), "
              f"pipeline {result.get('pipeline_status')}, AI {run.get('status')} "
              f"model={run.get('served_model') or run.get('model')} request_id={run.get('request_id')} "
              f"attempts={run.get('attempts')} {run.get('duration_ms')}ms")
        for factor in result.get("risk_factors", []):
            if factor.get("effect") in ("base", "raised"):
                print(f"      rule: {factor['detail']}")
        if run.get("error") or run.get("validation_issues"):
            print(f"      AI problem: {run.get('error_type')} {run.get('error')} {run.get('validation_issues')}")
        ai = result.get("ai_output")
        if ai:
            print(f"      件名: {ai['email_subject_ja']}")
            print(f"      要約: {ai['alert_summary_ja']}")
            print(f"      理由: {ai['risk_reason_ja']}")
            print(f"      unknown: {ai['unknown_items']}")
    print(f"\n{len(results) - failures}/{len(results)} cases passed")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", help="Base URL of a running deployment (default: run in-process)")
    parser.add_argument("--token", default=os.environ.get("ESET_WEBHOOK_AUTH_TOKEN", ""))
    parser.add_argument("--dashboard-key", default=os.environ.get("DASHBOARD_ACCESS_KEY", ""))
    parser.add_argument("--out", help="Write the full results (normalized alert, risk, AI run, AI output) as JSON")
    args = parser.parse_args()

    cases = load_cases()
    results = (run_remote(cases, args.url, args.token, args.dashboard_key) if args.url
               else asyncio.run(run_in_process(cases)))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"Full results written to {args.out}", file=sys.stderr)
    sys.exit(1 if summarize(results) else 0)


if __name__ == "__main__":
    main()
