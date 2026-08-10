import asyncio
import pytest
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
    
    # 4. Wait for it to expire
    await asyncio.sleep(1.1)
    
    # 5. Still in DB but expired (is_duplicate checks expires_at)
    assert not await is_duplicate(key)
    
    # 6. Cleanup deletes it
    deleted = await cleanup_expired()
    assert deleted == 1
