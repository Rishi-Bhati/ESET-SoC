from src.models.raw_payload import EsetRawPayload
from src.models.normalized_alert import NormalizedAlert

def test_raw_payload_lenient_defaults():
    """Ensure raw payload instantiates with None defaults and extra fields."""
    raw = EsetRawPayload(
        severity="HIGH",
        extra_unmapped_field="should_be_ignored_but_allowed"
    )
    assert raw.severity == "HIGH"
    assert raw.alert_id is None
    # Verify extra fields are preserved in model_extra
    assert raw.model_extra is not None
    assert raw.model_extra["extra_unmapped_field"] == "should_be_ignored_but_allowed"

def test_normalized_alert_defaults():
    """Ensure normalized alert standardizes missing fields to 'UNKNOWN'."""
    alert = NormalizedAlert()
    assert alert.severity == "UNKNOWN"
    assert alert.threat_handled == "UNKNOWN"
    assert alert.isolation_status == "UNKNOWN"
    assert alert.raw_payload == {}
