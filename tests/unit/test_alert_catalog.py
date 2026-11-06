import os
import pytest
from src.config import settings
from src.models.normalized_alert import NormalizedAlert
from src.models.pipeline_result import PipelineResult
from src.services import alert_catalog as catalog
from src.services.alert_catalog import BundleQuery
from src.services import output_writer
from src.storage import job_store, recommendation_store


def make_result(cid, risk="HIGH") -> PipelineResult:
    return PipelineResult(
        correlation_id=cid, source="WEBHOOK",
        received_at="2026-11-02T00:00:00+00:00", processed_at="2026-11-02T00:00:05+00:00",
        pipeline_status="SUCCESS", normalized_alert=NormalizedAlert(detection_name="D"),
        risk_level=risk, risk_rationale="r",
    )


async def make_alert(cid, risk="HIGH"):
    await job_store.create_job(cid, "WEBHOOK", {"k": cid})
    await output_writer.write_result(make_result(cid, risk))


@pytest.mark.parametrize("bad", ["../x", "a/b", "..", ".", "", "a" * 129, "a b", "x\n", "..\\x", None, 5])
async def test_load_bundle_rejects_invalid_ids(bad):
    assert await catalog.load_bundle(bad) is None


async def test_load_bundle_does_not_read_outside_output_dir():
    outside = os.path.join(os.path.dirname(settings.output_dir), "secret.json")
    with open(outside, "w") as f:
        f.write('{"correlation_id": "secret"}')
    assert await catalog.load_bundle("../secret") is None


async def test_load_bundle_returns_job_result_and_active_recommendations():
    await make_alert("b1")
    keep = await recommendation_store.create("b1", "do this", "eng")
    gone = await recommendation_store.create("b1", "oops", "eng")
    await recommendation_store.retract(gone["id"], "eng", "wrong")
    bundle = await catalog.load_bundle("b1")
    assert bundle.job["correlation_id"] == "b1" and bundle.job["raw_payload"] == {"k": "b1"}
    assert bundle.result["risk_level"] == "HIGH"
    assert [r["id"] for r in bundle.recommendations] == [keep["id"]]


async def test_load_bundle_none_when_result_or_job_missing_or_corrupt():
    await job_store.create_job("nores", "WEBHOOK", {})
    assert await catalog.load_bundle("nores") is None
    assert await catalog.load_bundle("unknown") is None
    await make_alert("corrupt")
    with open(os.path.join(settings.output_dir, "corrupt.json"), "w") as f:
        f.write("{oops")
    assert await catalog.load_bundle("corrupt") is None


async def test_list_bundles_filters_orders_and_batches_recommendations():
    for cid, risk in (("l1", "LOW"), ("h1", "HIGH"), ("h2", "HIGH")):
        await make_alert(cid, risk)
    await recommendation_store.create("h2", "advice", "eng")
    bundles, total = await catalog.list_bundles(BundleQuery(risk_levels={"high"}, order="asc"))
    assert total == 2
    assert {b.job["correlation_id"] for b in bundles} == {"h1", "h2"}
    by_id = {b.job["correlation_id"]: b for b in bundles}
    assert len(by_id["h2"].recommendations) == 1 and by_id["h1"].recommendations == []
    bundles, total = await catalog.list_bundles(BundleQuery(limit=1))
    assert len(bundles) == 1 and total == 3


async def test_list_bundles_tolerates_missing_and_corrupt_result_files():
    for cid in ("m1", "m2", "m3"):
        await make_alert(cid)
    os.remove(os.path.join(settings.output_dir, "m1.json"))
    with open(os.path.join(settings.output_dir, "m2.json"), "w") as f:
        f.write("not json")
    bundles, total = await catalog.list_bundles(BundleQuery())
    assert total == 3  # still counted
    assert [b.job["correlation_id"] for b in bundles] == ["m3"]


async def test_list_bundles_empty():
    assert await catalog.list_bundles(BundleQuery()) == ([], 0)
