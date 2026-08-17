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
from src.models.ai_output import AIOutput, ClientNotificationJa, CThreeNotificationJa, InternalNotificationJa, EngineerNotificationEn

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
        await conn.commit()
    yield

@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)

@pytest.fixture(autouse=True)
def mock_gemini(monkeypatch) -> None:
    """
    Monkeypatches GeminiAIService.generate to return deterministic mock AIOutputs.
    Avoids actual Gemini API calls and cost during unit/integration tests.
    """
    from src.services.ai.gemini_service import GeminiAIService
    
    async def mock_generate(self, alert, risk_level, threat_intel):
        return AIOutput(
            risk_level=risk_level,
            client_notification_ja=ClientNotificationJa(
                summary=f"[MOCK] {alert.detection_name} が検知されました。",
                current_status="隔離および確認中。",
                required_confirmation="管理者に状況を確認してください。"
            ),
            cthree_notification_ja=CThreeNotificationJa(
                summary=f"[MOCK] 連携用通知: {alert.detection_name}",
                assessment=f"リスクレベルは {risk_level} です。",
                front_office_notes="クライアントへの連絡準備をお願いします。",
                draft_client_response="担当者様、セキュリティアラートを確認しました。"
            ),
            internal_notification_ja=InternalNotificationJa(
                summary=f"[MOCK] 内部通知: {alert.detection_name}",
                assessment="内部詳細調査を進めます。",
                recommended_actions=["ログの確認", "端末隔離状態の再確認"],
                draft_client_response="内部連絡用下書きです。"
            ),
            engineer_notification_en=EngineerNotificationEn(
                alert_summary=f"[MOCK] Technical alert summary for {alert.detection_name}",
                assessment=f"Calculated risk level is {risk_level}.",
                confirmed_information=["Endpoint name: " + alert.endpoint_name],
                unknown_information=["Full network activity log is missing"],
                investigation_items=["Check registry run keys", "Verify process tree"],
                recommended_actions=["Scan host with ESET", "Isolate network card if suspicious"],
                draft_client_response="Security operations are actively triaging the alert."
            )
        )
        
    monkeypatch.setattr(GeminiAIService, "generate", mock_generate)
