"""Process-wide admission for queued and executing alert pipelines.

A semaphore inside a background task is too late: Starlette sends the HTTP
response before running it. Reserve synchronously before persisting a new job,
and carry that reservation through the actual background execution instead.
"""

import asyncio
from collections.abc import Awaitable, Callable
from threading import Lock
from typing import Any

from fastapi import HTTPException

from src.config import settings


class CapacityExhausted(Exception):
    pass


class PipelineAlreadyActive(Exception):
    pass


def overloaded() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Pipeline capacity is full; retry later",
        headers={"Retry-After": "1"},
    )


class Reservation:
    def __init__(self, pool: "PipelineCapacity", correlation_id: str, dedup_key: str | None):
        self.pool = pool
        self.correlation_id = correlation_id
        self.dedup_key = dedup_key
        self.released = False
        self.started = False
        self.owner = asyncio.current_task()
        if self.owner is not None:
            # Also release if a disconnected/cancelled HTTP request never gets
            # as far as executing its response's BackgroundTasks.
            self.owner.add_done_callback(self._owner_done)

    def _owner_done(self, _task: asyncio.Task) -> None:
        if not self.started:
            self.release()

    def release(self) -> None:
        with self.pool._lock:
            if self.released:
                return
            self.released = True
            self.pool._active.pop(self.correlation_id, None)
            if self.dedup_key is not None:
                self.pool._dedup.discard(self.dedup_key)
        if self.owner is not None:
            self.owner.remove_done_callback(self._owner_done)

    async def run(self, task: Callable[..., Awaitable[None]], *args: Any) -> None:
        if self.released:
            return
        self.started = True
        try:
            await task(*args)
        finally:
            # CancelledError is a BaseException, so this must be a finally.
            self.release()


class PipelineCapacity:
    def __init__(self, limit: int):
        if limit < 1:
            raise ValueError("Pipeline capacity must be positive")
        self.limit = limit
        self._lock = Lock()
        self._active: dict[str, Reservation] = {}
        self._dedup: set[str] = set()

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    def reserve(self, correlation_id: str, dedup_key: str | None = None) -> Reservation:
        # No await between checking and claiming. The lock also covers multiple
        # event loops/threads in one process; each server process has its own cap.
        with self._lock:
            if correlation_id in self._active or (dedup_key is not None and dedup_key in self._dedup):
                raise PipelineAlreadyActive
            if len(self._active) >= self.limit:
                raise CapacityExhausted
            reservation = Reservation(self, correlation_id, dedup_key)
            self._active[correlation_id] = reservation
            if dedup_key is not None:
                self._dedup.add(dedup_key)
            return reservation


capacity = PipelineCapacity(settings.max_concurrent_pipelines)
