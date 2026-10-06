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
    """Fields the alert did not carry stay absent — never a placeholder."""
    alert = NormalizedAlert()
    assert alert.severity is None
    assert alert.threat_handled is None
    assert alert.isolation_status is None
    assert alert.raw_payload == {}
    assert alert.present_fields() == {}


def test_normalized_alert_serializes_only_present_fields():
    alert = NormalizedAlert(source="WEBHOOK", severity="HIGH", threat_handled="false",
                            raw_payload={"severity": "HIGH", "note": None})
    assert alert.model_dump() == {
        "source": "WEBHOOK", "severity": "HIGH", "threat_handled": "false",
        # The raw request itself is kept verbatim, nulls included.
        "raw_payload": {"severity": "HIGH", "note": None},
    }
    assert "UNKNOWN" not in alert.model_dump_json() and "null" not in alert.model_dump_json(exclude={"raw_payload"})
    assert alert.present_fields() == {"source": "WEBHOOK", "severity": "HIGH", "threat_handled": "false"}
