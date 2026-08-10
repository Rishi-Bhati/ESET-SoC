import os
import tempfile
from typing import AsyncGenerator, Generator
import pytest
import pytest_asyncio
import aiosqlite
from fastapi.testclient import TestClient
from src.config import settings

# Force using a test SQLite database path before importing any components
test_db_fd, test_db_path = tempfile.mkstemp(suffix="_test.db")
settings.sqlite_db_path = test_db_path
settings.eset_webhook_auth_token = "test_token"

from src.storage.database import init_db
from src.main import app
from src.models.ai_output import AIOutput, ClientNotificationJa, CThreeNotificationJa, InternalNotificationJa, EngineerNotificationEn

@pytest.fixture(scope="session", autouse=True)
def setup_test_env() -> Generator[None, None, None]:
    """Sets up the test environment variables."""
    # Ensure logs/ output directories exist for tests
    os.makedirs("logs", exist_ok=True)
    os.makedirs(settings.output_dir, exist_ok=True)
    yield
    # Cleanup temp database file
    try:
        os.close(test_db_fd)
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
    except Exception:
        pass

@pytest_asyncio.fixture(autouse=True)
async def clean_database() -> AsyncGenerator[None, None]:
    """Initializes and wipes tables between test runs to ensure isolation."""
    await init_db()
    async with aiosqlite.connect(settings.sqlite_db_path) as conn:
        await conn.execute("DELETE FROM jobs")
        await conn.execute("DELETE FROM dedup_log")
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
