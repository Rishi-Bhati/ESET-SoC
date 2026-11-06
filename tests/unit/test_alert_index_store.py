import json
import os
import aiosqlite
import pytest
from datetime import datetime, timezone
from src.config import settings
from src.models.normalized_alert import NormalizedAlert
from src.models.pipeline_result import PipelineResult
from src.services import output_writer
from src.storage import alert_index_store as store, job_store
from src.utils.jst_time import jst_day_start_epoch, jst_range_epoch


def make_result(cid, risk="HIGH", status="SUCCESS", **norm) -> PipelineResult:
    return PipelineResult(
        correlation_id=cid, source="WEBHOOK",
        received_at="2026-11-02T00:00:00+00:00", processed_at="2026-11-02T00:00:05+00:00",
        pipeline_status=status,
        normalized_alert=NormalizedAlert(severity="Warning", alert_id="A-1",
                                         detection_name="Trojan.X", endpoint_name="PC-1", **norm),
        risk_level=risk, risk_rationale="r",
    )


async def all_rows():
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        async with conn.execute("SELECT correlation_id FROM alert_index") as c:
            return [r[0] async for r in c]


def write_file(result: PipelineResult, name=None):
    os.makedirs(settings.output_dir, exist_ok=True)
    with open(os.path.join(settings.output_dir, f"{name or result.correlation_id}.json"), "w", encoding="utf-8") as f:
        f.write(result.model_dump_json())


async def test_upsert_twice_leaves_one_row():
    await store.upsert_from_result(make_result("a1", risk="LOW"), 1000.0)
    await store.upsert_from_result(make_result("a1", risk="HIGH"), 1000.0)
    rows, total = await store.query()
    assert total == 1 and len(rows) == 1
    row = rows[0]
    assert row["risk_level"] == "HIGH"
    assert row["received_at"] == 1000.0
    assert row["eset_severity"] == "Warning" and row["eset_alert_id"] == "A-1"
    assert row["detection_name"] == "Trojan.X" and row["endpoint_name"] == "PC-1"
    assert row["has_ai_output"] is False
    assert row["processed_at"] == datetime(2026, 11, 2, 0, 0, 5, tzinfo=timezone.utc).timestamp()


async def test_reconcile_backfills_only_missing_and_is_idempotent():
    await job_store.create_job("r1", "WEBHOOK", {})
    job = await job_store.get_job("r1")
    write_file(make_result("r1"))
    write_file(make_result("r2"))
    await store.upsert_from_result(make_result("r2", risk="LOW"), 5.0)  # already indexed: must stay untouched

    counts = await store.reconcile()
    assert counts == {"scanned": 2, "inserted": 1, "skipped": 0}
    rows, total = await store.query(order="asc")
    assert total == 2
    by_id = {r["correlation_id"]: r for r in rows}
    assert by_id["r1"]["received_at"] == job["created_at"]  # taken from the job row
    assert by_id["r2"]["risk_level"] == "LOW" and by_id["r2"]["received_at"] == 5.0

    again = await store.reconcile()
    assert again == {"scanned": 2, "inserted": 0, "skipped": 0}


async def test_reconcile_without_job_falls_back_to_processed_at():
    write_file(make_result("nojob"))
    await store.reconcile()
    rows, _ = await store.query()
    assert rows[0]["received_at"] == datetime(2026, 11, 2, 0, 0, 5, tzinfo=timezone.utc).timestamp()


async def test_reconcile_skips_corrupt_and_ignores_index_json():
    write_file(make_result("good"))
    with open(os.path.join(settings.output_dir, "bad.json"), "w") as f:
        f.write("{not json")
    with open(os.path.join(settings.output_dir, "mismatch.json"), "w") as f:
        json.dump({"correlation_id": "other"}, f)
    with open(os.path.join(settings.output_dir, "index.json"), "w") as f:
        json.dump([{"correlation_id": "good"}], f)
    counts = await store.reconcile()
    assert counts == {"scanned": 3, "inserted": 1, "skipped": 2}
    assert await all_rows() == ["good"]


async def test_reconcile_missing_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "output_dir", str(tmp_path / "nope"))
    assert await store.reconcile() == {"scanned": 0, "inserted": 0, "skipped": 0}


async def test_jst_day_boundaries():
    start = jst_day_start_epoch("2026-11-02")
    end = jst_day_start_epoch("2026-11-03")
    assert end - start == 86400
    assert jst_range_epoch("2026-11-02", "2026-11-02") == (start, end)
    await store.upsert_from_result(make_result("before"), start - 1)
    await store.upsert_from_result(make_result("first"), start)
    await store.upsert_from_result(make_result("last"), end - 1)      # 23:59:59 JST
    await store.upsert_from_result(make_result("next"), end)          # 00:00:00 Nov 3 JST
    rows, total = await store.query(received_from=start, received_to=end, order="asc")
    assert [r["correlation_id"] for r in rows] == ["first", "last"] and total == 2
    with pytest.raises(ValueError):
        jst_day_start_epoch("2026-13-40")


async def test_risk_filter_case_insensitive_and_status_default():
    await store.upsert_from_result(make_result("c", risk="CRITICAL"), 1.0)
    await store.upsert_from_result(make_result("h", risk="HIGH"), 2.0)
    await store.upsert_from_result(make_result("p", risk="HIGH", status="PARTIAL"), 3.0)
    await store.upsert_from_result(make_result("f", risk="HIGH", status="FAILED"), 4.0)

    rows, total = await store.query(risk_levels={"high", "Critical"}, order="asc")
    assert [r["correlation_id"] for r in rows] == ["c", "h", "p"] and total == 3
    rows, _ = await store.query(risk_levels=["high"])
    assert {r["correlation_id"] for r in rows} == {"h", "p"}
    rows, total = await store.query(statuses={"FAILED"})
    assert [r["correlation_id"] for r in rows] == ["f"]
    assert await store.query(risk_levels=[]) == ([], 0)
    assert await store.query(statuses=[]) == ([], 0)


async def test_counts_by_risk_has_all_keys():
    assert await store.counts_by_risk() == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    await store.upsert_from_result(make_result("a", risk="HIGH"), 10.0)
    await store.upsert_from_result(make_result("b", risk="HIGH"), 20.0)
    await store.upsert_from_result(make_result("c", risk="LOW"), 30.0)
    await store.upsert_from_result(make_result("d", risk="LOW", status="FAILED"), 30.0)
    assert await store.counts_by_risk() == {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 1}
    assert await store.counts_by_risk(received_from=15.0, received_to=30.0) == {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}


async def test_ordering_and_paging_are_stable_with_ties():
    for cid in ("d", "b", "a", "c", "e"):
        await store.upsert_from_result(make_result(cid), 100.0)  # identical received_at
    asc, _ = await store.query(order="asc")
    assert [r["correlation_id"] for r in asc] == ["a", "b", "c", "d", "e"]
    desc, _ = await store.query(order="desc")
    assert [r["correlation_id"] for r in desc] == ["e", "d", "c", "b", "a"]
    p1, total = await store.query(limit=2, offset=0, order="asc")
    p2, _ = await store.query(limit=2, offset=2, order="asc")
    p3, _ = await store.query(limit=2, offset=4, order="asc")
    assert total == 5
    assert [r["correlation_id"] for r in p1 + p2 + p3] == ["a", "b", "c", "d", "e"]


async def test_limit_is_clamped_and_params_are_not_interpolated():
    await store.upsert_from_result(make_result("a"), 1.0)
    rows, total = await store.query(limit=0)
    assert len(rows) == 1 and total == 1
    rows, _ = await store.query(limit=10**9, offset=-5)
    assert len(rows) == 1
    # hostile filter values are bound, not executed
    rows, total = await store.query(risk_levels=["HIGH' OR '1'='1"])
    assert (rows, total) == ([], 0)


async def test_write_result_creates_index_row_from_job_time(monkeypatch):
    await job_store.create_job("w1", "WEBHOOK", {})
    job = await job_store.get_job("w1")
    await output_writer.write_result(make_result("w1"))
    rows, _ = await store.query()
    assert [r["correlation_id"] for r in rows] == ["w1"]
    assert rows[0]["received_at"] == job["created_at"]


async def test_write_result_without_job_and_index_failure_is_not_fatal(monkeypatch):
    await output_writer.write_result(make_result("w2"))
    assert await all_rows() == ["w2"]

    async def boom(*a, **k):
        raise RuntimeError("db down")
    monkeypatch.setattr(store, "upsert_from_result", boom)
    await output_writer.write_result(make_result("w3"))
    assert os.path.exists(os.path.join(settings.output_dir, "w3.json"))
    with open(os.path.join(settings.output_dir, "index.json")) as f:
        assert [r["correlation_id"] for r in json.load(f)] == ["w2", "w3"]
