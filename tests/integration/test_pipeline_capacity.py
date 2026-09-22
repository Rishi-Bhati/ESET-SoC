"""Admission is bounded before HTTP responses start their background pipelines."""

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import BackgroundTasks, HTTPException, Request
from pydantic import ValidationError

from src import main
from src.api import dashboard, webhook
from src.config import Settings
from src.pipeline import orchestrator
from src.services import pipeline_capacity
from src.storage import deduplication, job_store


def payload(alert_id):
    return {
        "alert_id": alert_id,
        "occurred_at": "2026-09-01T00:00:00Z",
        "severity": "HIGH",
        "detection_name": "Test detection",
        "endpoint_name": "TEST-HOST",
    }


def request():
    return Request({"type": "http", "headers": []})


@pytest.fixture
def pool(monkeypatch):
    pool = pipeline_capacity.PipelineCapacity(2)
    monkeypatch.setattr(pipeline_capacity, "capacity", pool)
    monkeypatch.setattr(orchestrator, "process_alert_pipeline", AsyncMock())
    return pool


async def queue(alert_id, tasks):
    return await webhook.ingest_alert(payload(alert_id), webhook.webhook_handler, "WEBHOOK", tasks)


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["/webhook/eset", "/webhook/syslog"])
async def test_ingest_reserves_before_background_execution_and_overload_is_retryable(pool, route):
    first, second = BackgroundTasks(), BackgroundTasks()
    await queue("slot-one", first)
    await queue("slot-two", second)
    assert pool.active_count == 2
    orchestrator.process_alert_pipeline.assert_not_awaited()

    # The real route must answer 503 without creating a job or marking dedup.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test") as client:
        response = await client.post(route, json=payload("overloaded"), headers={"Authorization": "Bearer test_token"})
    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert len(await job_store.list_jobs()) == 2
    assert not await deduplication.is_duplicate("overloaded:2026-09-01T00:00:00Z")

    duplicate_tasks = BackgroundTasks()
    assert (await queue("slot-one", duplicate_tasks))["status"] == "duplicate"
    assert not duplicate_tasks.tasks
    assert pool.active_count == 2

    await first()
    assert pool.active_count == 1
    replacement = BackgroundTasks()
    assert (await queue("overloaded", replacement))["status"] == "queued"
    assert pool.active_count == 2
    await second()
    await replacement()
    assert pool.active_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["success", "failure", "cancel"])
async def test_reservation_lives_until_pipeline_finishes(pool, monkeypatch, outcome):
    started, finish = asyncio.Event(), asyncio.Event()

    async def process(*_args):
        started.set()
        await finish.wait()
        if outcome == "failure":
            raise RuntimeError("mock pipeline failure")

    monkeypatch.setattr(orchestrator, "process_alert_pipeline", process)
    tasks = BackgroundTasks()
    await queue("lifecycle", tasks)
    running = asyncio.create_task(tasks())
    await asyncio.wait_for(started.wait(), 1)
    assert pool.active_count == 1
    if outcome == "cancel":
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running
    else:
        finish.set()
        await running
    assert pool.active_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_admission_failure_releases_reservation(pool, monkeypatch, cancel):
    entered = asyncio.Event()

    async def fail_persistence(*_args):
        entered.set()
        if cancel:
            await asyncio.Event().wait()
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(deduplication, "record_seen", fail_persistence)
    tasks = BackgroundTasks()
    ingest = asyncio.create_task(queue("persist-failure", tasks))
    await asyncio.wait_for(entered.wait(), 1)
    if cancel:
        ingest.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else RuntimeError):
        await ingest
    assert pool.active_count == 0
    assert not tasks.tasks
    assert not await job_store.list_jobs()


@pytest.mark.asyncio
async def test_request_cancelled_before_background_start_releases_reservation(pool):
    queued = asyncio.Event()
    tasks = BackgroundTasks()

    async def request_lifetime():
        await queue("disconnect", tasks)
        queued.set()
        await asyncio.Event().wait()

    pending = asyncio.create_task(request_lifetime())
    await asyncio.wait_for(queued.wait(), 1)
    assert pool.active_count == 1
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    await asyncio.sleep(0)  # Run the owner's completion callback.
    assert pool.active_count == 0
    await tasks()  # A released reservation must never launch later.
    orchestrator.process_alert_pipeline.assert_not_awaited()


@pytest.mark.asyncio
async def test_retry_uses_same_capacity_and_preserves_status_on_overload(pool):
    first, second = BackgroundTasks(), BackgroundTasks()
    await queue("ingest-one", first)
    await queue("ingest-two", second)
    await job_store.create_job("failed-job", "WEBHOOK", payload("retry"))
    await job_store.update_job_status("failed-job", "FAILED")
    retry_tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as error:
        await dashboard.retry_job(request(), "failed-job", retry_tasks)
    assert error.value.status_code == 503
    assert error.value.headers == {"Retry-After": "1"}
    assert (await job_store.get_job("failed-job"))["status"] == "FAILED"
    assert not retry_tasks.tasks
    await first()
    result = await dashboard.retry_job(request(), "failed-job", retry_tasks)
    assert result["status"] == "retrying"
    assert pool.active_count == 2
    await second()
    await retry_tasks()
    assert pool.active_count == 0


@pytest.mark.asyncio
async def test_simultaneous_retries_cannot_start_same_job_twice(pool, monkeypatch):
    await job_store.create_job("race-job", "WEBHOOK", payload("retry-race"))
    await job_store.update_job_status("race-job", "FAILED")
    entered, finish = asyncio.Event(), asyncio.Event()
    real_update = job_store.update_job_status

    async def delayed_update(*args):
        entered.set()
        await finish.wait()
        await real_update(*args)

    monkeypatch.setattr(job_store, "update_job_status", delayed_update)
    first_tasks, other_tasks = BackgroundTasks(), BackgroundTasks()
    async def first_request():
        result = await dashboard.retry_job(request(), "race-job", first_tasks)
        await first_tasks()
        return result

    first = asyncio.create_task(first_request())
    await asyncio.wait_for(entered.wait(), 1)
    try:
        with pytest.raises(HTTPException) as error:
            await dashboard.retry_job(request(), "race-job", other_tasks)
        assert error.value.status_code == 409
        assert pool.active_count == 1
        assert not other_tasks.tasks
    finally:
        finish.set()
        await first
    orchestrator.process_alert_pipeline.assert_awaited_once()
    assert pool.active_count == 0


@pytest.mark.asyncio
async def test_recovery_shares_capacity_and_never_starts_backlog_concurrently(pool, monkeypatch):
    pool.limit = 1
    held = pool.reserve("live-request")
    for i in range(12):
        await job_store.create_job(f"unfinished-{i}", "WEBHOOK", payload(f"recover-{i}"))
    started, finish = asyncio.Event(), asyncio.Event()
    calls = []

    async def process(correlation_id, *_args):
        calls.append(correlation_id)
        started.set()
        await finish.wait()
        await job_store.update_job_status(correlation_id, "SUCCESS")

    monkeypatch.setattr(orchestrator, "process_alert_pipeline", process)
    recovery = asyncio.create_task(main.recover_unfinished_jobs())
    try:
        await asyncio.sleep(0.15)
        assert not calls
        assert pool.active_count == 1
        held.release()
        await asyncio.wait_for(started.wait(), 1)
        await asyncio.sleep(0.05)
        assert len(calls) == 1
        assert pool.active_count == 1
        finish.set()
        await asyncio.wait_for(recovery, 5)
        assert len(calls) == 12
        assert pool.active_count == 0
    finally:
        held.release()
        recovery.cancel()
        await asyncio.gather(recovery, return_exceptions=True)


@pytest.mark.asyncio
async def test_lifespan_tracks_and_cancels_recovery_pipeline(pool, monkeypatch):
    await job_store.create_job("shutdown-job", "WEBHOOK", payload("shutdown"))
    started = asyncio.Event()

    async def pipeline(*_args):
        started.set()
        await asyncio.Event().wait()

    async def idle(*_args):
        await asyncio.Event().wait()

    monkeypatch.setattr(orchestrator, "process_alert_pipeline", pipeline)
    monkeypatch.setattr(main, "setup_logging", lambda *_args, **_kw: None)
    monkeypatch.setattr(main.syslog_runtime, "start", AsyncMock(return_value=None))
    monkeypatch.setattr(main.syslog_runtime, "stop", AsyncMock())
    monkeypatch.setattr(main.email_dispatcher, "run_dispatch_loop", idle)
    monkeypatch.setattr(main.deduplication, "run_cleanup_loop", idle)
    async with main.lifespan(main.app):
        await asyncio.wait_for(started.wait(), 1)
        assert pool.active_count == 1
        assert not main.app.state.recovery_task.done()
    assert main.app.state.recovery_task.cancelled()
    assert pool.active_count == 0
    main.syslog_runtime.stop.assert_awaited_once()


@pytest.mark.parametrize("invalid", [0, -1])
def test_pipeline_limit_must_be_positive(invalid):
    with pytest.raises(ValidationError):
        Settings(MAX_CONCURRENT_PIPELINES=invalid)
