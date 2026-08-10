import os
import json
import pytest
from src.pipeline.orchestrator import process_alert_pipeline
from src.storage import job_store
from src.config import settings

@pytest.mark.asyncio
async def test_full_pipeline_success():
    correlation_id = "test-pipeline-run-uuid"
    raw_payload = {
        "alert_id": "alert-p-100",
        "occurred_at": "2026-08-10T12:00:00Z",
        "severity": "HIGH",
        "detection_name": "Win32/Conficker",
        "endpoint_name": "DC-01",
        "threat_handled": False,
        "file_hash": "hash12345"
    }
    
    # 1. Setup DB record in PENDING
    await job_store.create_job(correlation_id, "WEBHOOK", raw_payload)
    
    # 2. Run the orchestrator
    await process_alert_pipeline(correlation_id, raw_payload, "WEBHOOK")
    
    # 3. Verify SQLite DB updated to SUCCESS status
    job = await job_store.get_job(correlation_id)
    assert job is not None
    assert job["status"] == "SUCCESS"
    
    # 4. Verify output file exists
    output_file = os.path.join(settings.output_dir, f"{correlation_id}.json")
    assert os.path.exists(output_file)
    
    # 5. Read output file and verify payload schema mapping
    with open(output_file, "r") as f:
        result = json.load(f)
        
    assert result["correlation_id"] == correlation_id
    assert result["pipeline_status"] == "SUCCESS"
    assert result["risk_level"] == "HIGH"
    assert result["normalized_alert"]["detection_name"] == "Win32/Conficker"
    
    # Verify AI mock output populated
    assert result["ai_output"] is not None
    assert result["ai_output"]["risk_level"] == "HIGH"
    assert "Conficker" in result["ai_output"]["client_notification_ja"]["summary"]
    
    # 6. Verify index.json exists and contains record
    index_file = os.path.join(settings.output_dir, "index.json")
    assert os.path.exists(index_file)
    with open(index_file, "r") as f:
        index_data = json.load(f)
        
    # Find our record
    record = next((r for r in index_data if r["correlation_id"] == correlation_id), None)
    assert record is not None
    assert record["status"] == "SUCCESS"
    assert record["risk_level"] == "HIGH"
