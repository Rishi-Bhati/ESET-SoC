from fastapi.testclient import TestClient

def test_syslog_webhook_endpoint(client: TestClient):
    headers = {"Authorization": "Bearer test_token"}
    # Payload matching the raw syslog JSON export keys
    payload = {
        "event": "Threat Detection",
        "id": "syslog-alert-88888",
        "uuid": "syslog-detect-uuid-xyz",
        "computer_uuid": "syslog-target-uuid-xyz",
        "time": "2026-08-10T12:20:00Z",
        "severity": "HIGH",
        "threat_name": "Win32/Trojan.Agent.ABC",
        "computer_name": "SEC-PC-01",
        "username": "admin",
        "os": "Windows Server 2022",
        "action": "Blocked",
        "handled": False,
        "hash": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "ip": "203.0.113.5",
        "subject": "Syslog detection on SEC-PC-01",
        "content": "Threat detected and blocked via Syslog export"
    }
    
    response = client.post("/webhook/syslog", headers=headers, json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "queued"
    assert data["correlation_id"] is not None
