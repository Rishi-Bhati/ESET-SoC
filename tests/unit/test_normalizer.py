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


# --------------------------- arbitrary/non-ESET-shaped JSON ---------------------------
# The webhook route accepts any JSON object (src/api/webhook.py has no required
# fields, EsetRawPayload has extra="allow") — a sender is not required to match
# ESET's own field names. These cover the alias-resolution fallback in normalize()
# that reads the ORIGINAL submitted JSON for common alternate key names before
# giving up and marking a field "UNKNOWN".

def test_normalize_resolves_common_aliases_from_raw_payload():
    # raw_payload is set explicitly here to match what the ingestion handlers
    # actually do (src/ingestion/webhook_handler.py always sets it to the full
    # original dict) — constructing EsetRawPayload directly with only the
    # keyword args, as the other tests in this file do, leaves it as {} and the
    # alias lookup (which reads raw.raw_payload) would have nothing to search.
    submitted = {
        # None of these are EsetRawPayload's own field names.
        "sev": "high",
        "threat_name": "Custom.Malware.X",
        "host": "GENERIC-HOST-01",
        "user": "j.doe",
        "sha256": "deadbeef" * 8,
        "ip": "203.0.113.9",
        "handled": True,
    }
    raw = EsetRawPayload(raw_payload=submitted, **submitted)
    alert = normalize(raw, "WEBHOOK")

    assert alert.severity == "high"
    assert alert.detection_name == "Custom.Malware.X"
    assert alert.endpoint_name == "GENERIC-HOST-01"
    assert alert.user_name == "j.doe"
    assert alert.file_hash == "deadbeef" * 8
    assert alert.ip_address == "203.0.113.9"
    assert alert.threat_handled == "true"


def test_normalize_exact_field_wins_over_alias():
    # A payload that happens to carry BOTH ESET's own key and a synonym must not
    # let the alias override the value already correctly mapped.
    submitted = {"detection_name": "Real.Detection", "threat_name": "Should.Not.Win"}
    raw = EsetRawPayload(raw_payload=submitted, **submitted)
    alert = normalize(raw, "WEBHOOK")
    assert alert.detection_name == "Real.Detection"


def test_normalize_unrecognized_shape_falls_back_to_unknown():
    # A payload with no recognizable field name at all — the deterministic risk
    # engine's MEDIUM safety default (src/services/risk_engine.py) is what carries
    # this case, not normalize() inventing a guess.
    submitted = {"nonsense_key": "nonsense_value"}
    raw = EsetRawPayload(raw_payload=submitted, **submitted)
    alert = normalize(raw, "WEBHOOK")
    assert alert.severity == "UNKNOWN"
    assert alert.detection_name == "UNKNOWN"
    assert alert.raw_payload == {"nonsense_key": "nonsense_value"}
