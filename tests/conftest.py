import os
import shutil
import tempfile
from typing import AsyncGenerator, Generator
import pytest
import pytest_asyncio
import aiosqlite
from fastapi.testclient import TestClient
from src.config import settings

# Redirect ALL persistent state to temp locations before importing any component
# that captures these paths at import time. Without this the suite writes real
# alert files into output/alerts/ and real emails into output/emails/outbox.json,
# polluting the runtime directories an operator is looking at.
test_db_fd, test_db_path = tempfile.mkstemp(suffix="_test.db")
test_output_dir = tempfile.mkdtemp(prefix="soc_lite_test_output_")

settings.sqlite_db_path = test_db_path
settings.eset_webhook_auth_token = "test_token"
settings.output_dir = os.path.join(test_output_dir, "alerts")
settings.dashboard_access_key = ""

from src.storage.database import init_db
from src.services import email_outbox
from src.main import app
from ai_fakes import FakeProvider, default_responder

# email_outbox resolves its paths at import time, so point them at the temp tree too
email_outbox.OUTBOX_DIR = os.path.join(test_output_dir, "emails")
email_outbox.OUTBOX_PATH = os.path.join(email_outbox.OUTBOX_DIR, "outbox.json")

@pytest.fixture(scope="session", autouse=True)
def setup_test_env() -> Generator[None, None, None]:
    """Creates the temp output tree and tears everything down afterwards."""
    os.makedirs("logs", exist_ok=True)
    os.makedirs(settings.output_dir, exist_ok=True)
    os.makedirs(email_outbox.OUTBOX_DIR, exist_ok=True)
    yield
    try:
        os.close(test_db_fd)
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
    except Exception:
        pass
    shutil.rmtree(test_output_dir, ignore_errors=True)

@pytest.fixture(autouse=True)
def clean_output_dirs() -> Generator[None, None, None]:
    """Isolates each test: no alert files or queued emails leak between tests."""
    for directory in (settings.output_dir, email_outbox.OUTBOX_DIR):
        shutil.rmtree(directory, ignore_errors=True)
        os.makedirs(directory, exist_ok=True)
    yield

@pytest_asyncio.fixture(autouse=True)
async def clean_database() -> AsyncGenerator[None, None]:
    """Initializes and wipes tables between test runs to ensure isolation."""
    await init_db()
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("DELETE FROM jobs")
        await conn.execute("DELETE FROM dedup_log")
        await conn.execute("DELETE FROM app_settings")
        await conn.execute("DELETE FROM alert_observations")
        await conn.commit()
    yield

@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def prevent_live_side_effects(monkeypatch):
    """Tests never inherit live delivery/intel flags from a developer's .env."""
    monkeypatch.setattr(settings, "email_delivery_enabled", False)
    monkeypatch.setattr(settings, "use_mock_threat_intel", True)

@pytest.fixture(autouse=True)
def mock_ai_provider(monkeypatch):
    """
    Every test gets FakeProvider (tests/ai_fakes.py) as the configured AI
    provider: no real API call, no cost, but the whole BaseAIProvider.generate()
    path — masking, pinned schema, parsing, tracing — still runs. Retries wait 0s.
    """
    from tenacity import wait_none
    from src.services.ai import base as ai_base, factory as ai_factory

    monkeypatch.setattr(ai_factory, "get_ai_provider", lambda: FakeProvider())
    monkeypatch.setattr(ai_base, "RETRY_WAIT", wait_none())
    monkeypatch.setattr(FakeProvider, "responder", staticmethod(default_responder))
    FakeProvider.requests = []
    yield FakeProvider


@pytest.fixture
def ai_responder(monkeypatch):
    """Replace what the fake model returns: ai_responder(fn) where fn(request)
    returns a ProviderResponse or an exception instance to raise."""
    def set_responder(fn):
        monkeypatch.setattr(FakeProvider, "responder", staticmethod(fn))
    return set_responder


@pytest.fixture(autouse=True)
def reset_auth_limiter() -> Generator[None, None, None]:
    """Auth-failure throttling is per client address, and every TestClient
    request comes from the same one — without a reset, wrong-credential tests
    would lock out the tests that run after them."""
    from src.middleware.security import auth_limiter
    auth_limiter.reset()
    yield
    auth_limiter.reset()
