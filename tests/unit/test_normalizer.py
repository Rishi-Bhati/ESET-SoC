from src.models.raw_payload import EsetRawPayload
from src.services.normalizer import normalize

def test_normalize_basic_conversion():
    raw = EsetRawPayload(
        alert_id="123",
        severity="high",
        threat_handled=True,
        isolation_status=False,
        file_hash="abcde"
    )
    alert = normalize(raw, "WEBHOOK")
    
    assert alert.source == "WEBHOOK"
    assert alert.alert_id == "123"
    assert alert.severity == "high"
    assert alert.threat_handled == "true"
    assert alert.isolation_status == "false"
    assert alert.file_hash == "abcde"
    assert alert.endpoint_name == "UNKNOWN"

def test_normalize_missing_threat_handled():
    raw = EsetRawPayload(alert_id="456")
    alert = normalize(raw, "SYSLOG")
    
    assert alert.source == "SYSLOG"
    assert alert.threat_handled == "UNKNOWN"
    assert alert.isolation_status == "UNKNOWN"
