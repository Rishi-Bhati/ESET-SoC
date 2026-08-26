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
    with open(output_file, "r", encoding="utf-8") as f:
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
    with open(index_file, "r", encoding="utf-8") as f:
        index_data = json.load(f)
        
    # Find our record
    record = next((r for r in index_data if r["correlation_id"] == correlation_id), None)
    assert record is not None
    assert record["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_full_pipeline_critical_multi_endpoint_event():
    """
    PoC Test Matrix #4 (docs/SOC_LITE_AUDIT.md §13): a CRITICAL, ransomware-like event
    reported as spreading across multiple endpoints.

    NormalizedAlert (src/models/normalized_alert.py) is single-endpoint-per-alert by
    design, matching the requirements document's schema — ESET reports one detection
    per endpoint, not a correlated multi-endpoint object. This fixture represents the
    scenario the way the pipeline actually receives it: one primary alert whose
    raw_content names the other affected endpoints, rather than a structured list of
    endpoints. That is a real, currently-accepted schema limitation (see the audit's
    Recommended Order, item 6), not something this test papers over.
    """
    fixture_path = os.path.join(
        os.path.dirname(__file__), "..", "fixtures", "sample_critical_multi_endpoint.json"
    )
    with open(fixture_path, encoding="utf-8") as f:
        raw_payload = json.load(f)

    correlation_id = "test-pipeline-critical-multi-endpoint"
    await job_store.create_job(correlation_id, "WEBHOOK", raw_payload)
    await process_alert_pipeline(correlation_id, raw_payload, "WEBHOOK")

    job = await job_store.get_job(correlation_id)
    assert job["status"] == "SUCCESS"

    output_file = os.path.join(settings.output_dir, f"{correlation_id}.json")
    with open(output_file, "r", encoding="utf-8") as f:
        result = json.load(f)

    assert result["risk_level"] == "CRITICAL"
    assert result["normalized_alert"]["endpoint_name"] == "DOMAIN-CONTROLLER-01"
    # The additional endpoints are only visible via raw_content until the schema
    # supports a real multi-endpoint structure — assert they at least survive intact
    # into the persisted, normalized record for an analyst to read.
    for other_endpoint in ("FINANCE-PC-09", "FINANCE-PC-11", "HR-WORKSTATION-04"):
        assert other_endpoint in result["normalized_alert"]["raw_content"]
    assert result["ai_output"] is not None
