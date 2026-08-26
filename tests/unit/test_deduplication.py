import asyncio
import pytest
from src.storage import deduplication
from src.storage.deduplication import is_duplicate, record_seen, cleanup_expired

@pytest.mark.asyncio
async def test_deduplication_flow():
    key = "test_alert_id_1:2026-08-10T12:00:00Z"
    
    # 1. New key is not duplicate
    assert not await is_duplicate(key)
    
    # 2. Record it with 1s TTL
    await record_seen(key, ttl_seconds=1)
    
    # 3. Now it is a duplicate
    assert await is_duplicate(key)
    
    # 4. Wait for it to expire (extra margin beyond the 1s TTL to avoid flakiness
    # under system load — see docs/SOC_LITE_AUDIT.md's Implementation Update)
    await asyncio.sleep(1.5)
    
    # 5. Still in DB but expired (is_duplicate checks expires_at)
    assert not await is_duplicate(key)
    
    # 6. Cleanup deletes it
    deleted = await cleanup_expired()
    assert deleted == 1


async def test_run_cleanup_loop_calls_cleanup_expired_periodically(monkeypatch):
    """
    cleanup_expired() previously existed but was never invoked anywhere in the
    running app (docs/SOC_LITE_AUDIT.md §5/§17). run_cleanup_loop() is the fix —
    verify it actually calls cleanup_expired() on its interval, and that
    cancellation (as done in src/main.py's shutdown path) stops it cleanly.
    """
    calls = []

    async def fake_cleanup_expired():
        calls.append(1)
        return 0

    monkeypatch.setattr(deduplication, "cleanup_expired", fake_cleanup_expired)

    task = asyncio.create_task(deduplication.run_cleanup_loop(interval_seconds=0))
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert len(calls) > 0
