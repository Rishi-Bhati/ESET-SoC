from src.models.normalized_alert import NormalizedAlert
from src.services.risk_engine import compute_risk

def test_risk_critical():
    alert = NormalizedAlert(severity="CRITICAL")
    risk, rationale = compute_risk(alert)
    assert risk == "CRITICAL"
    assert "Immediate escalation" in rationale

def test_risk_high_unhandled():
    alert = NormalizedAlert(severity="HIGH", threat_handled="false")
    risk, rationale = compute_risk(alert)
    assert risk == "HIGH"

def test_risk_high_handled_not_isolated():
    alert = NormalizedAlert(severity="HIGH", threat_handled="true", isolation_status="false")
    risk, rationale = compute_risk(alert)
    assert risk == "MEDIUM"

def test_risk_high_handled_isolated():
    alert = NormalizedAlert(severity="HIGH", threat_handled="true", isolation_status="true")
    risk, rationale = compute_risk(alert)
    assert risk == "LOW"

def test_risk_medium_unhandled():
    alert = NormalizedAlert(severity="MEDIUM", threat_handled="false")
    risk, rationale = compute_risk(alert)
    assert risk == "MEDIUM"

def test_risk_medium_handled():
    alert = NormalizedAlert(severity="MEDIUM", threat_handled="true")
    risk, rationale = compute_risk(alert)
    assert risk == "LOW"

def test_risk_low_handled():
    alert = NormalizedAlert(severity="LOW", threat_handled="true")
    risk, rationale = compute_risk(alert)
    assert risk == "LOW"


def test_risk_low_with_unknown_handling_needs_confirmation():
    # "MEDIUM: unclear or partially handled" — a LOW detection is only LOW once handled.
    risk, rationale = compute_risk(NormalizedAlert(severity="LOW"))
    assert risk == "MEDIUM"
    assert "needs confirmation" in rationale

def test_risk_unknown_fallback():
    alert = NormalizedAlert(severity="SOMETHING_ELSE")
    risk, rationale = compute_risk(alert)
    assert risk == "MEDIUM"
    assert "Falling back to MEDIUM" in rationale


# --------------------------- factors beyond severity × handling ---------------------------

import pytest
from src.config import settings
from src.models.threat_intel import AbuseIPDBResult, ThreatIntelResult, VirusTotalResult
from src.services.risk_engine import assess_risk, reported_endpoint_count


def _intel(vt="UNKNOWN", abuse="UNKNOWN"):
    return ThreatIntelResult(virustotal=VirusTotalResult(status=vt), abuseipdb=AbuseIPDBResult(status=abuse))


def _rules(assessment):
    return [f.rule for f in assessment.factors if f.effect in ("base", "raised")]


def test_malicious_intel_raises_an_unhandled_medium_to_high():
    a = assess_risk(NormalizedAlert(severity="MEDIUM", threat_handled="false"), _intel(vt="MALICIOUS"))
    assert a.level == "HIGH"
    assert "threat_intel_malicious" in _rules(a)
    assert "VirusTotal" in a.rationale


def test_malicious_intel_on_a_handled_threat_only_needs_confirmation():
    a = assess_risk(NormalizedAlert(severity="LOW", threat_handled="true"), _intel(abuse="MALICIOUS"))
    assert a.level == "MEDIUM"


def test_suspicious_intel_does_not_raise_a_handled_threat():
    a = assess_risk(NormalizedAlert(severity="LOW", threat_handled="true"), _intel(vt="SUSPICIOUS"))
    assert a.level == "LOW"


def test_important_endpoint_raises_one_level_but_never_to_critical_alone():
    server = NormalizedAlert(severity="MEDIUM", threat_handled="false", endpoint_type="Server")
    assert assess_risk(server).level == "HIGH"
    high_server = NormalizedAlert(severity="HIGH", threat_handled="false", endpoint_type="Domain Controller")
    assert assess_risk(high_server).level == "HIGH"


def test_important_endpoint_patterns_are_configurable(monkeypatch):
    monkeypatch.setattr(settings, "important_endpoint_patterns", "MAC-FS-*, *-SQL*")
    a = assess_risk(NormalizedAlert(severity="MEDIUM", threat_handled="false",
                                    endpoint_type="Workstation", endpoint_name="MAC-FS-01"))
    assert a.level == "HIGH"
    assert "MAC-FS-*" in a.rationale


def test_handled_threat_on_important_endpoint_is_not_raised():
    a = assess_risk(NormalizedAlert(severity="MEDIUM", threat_handled="true", endpoint_type="Server"))
    assert a.level == "LOW"


@pytest.mark.parametrize("field, value", [
    ("detection_name", "Win32/Filecoder.WannaCryptor.D"),
    ("raw_content", "vssadmin delete shadows /all was executed"),
    ("raw_subject", "Ransomware Shield blocked a process"),
])
def test_ransomware_indicators_are_critical_when_not_handled(field, value):
    a = assess_risk(NormalizedAlert(severity="MEDIUM", threat_handled="false", **{field: value}))
    assert a.level == "CRITICAL"
    assert "ransomware_indicator" in _rules(a)


def test_handled_ransomware_detection_stays_at_least_high():
    a = assess_risk(NormalizedAlert(severity="HIGH", threat_handled="true", isolation_status="true",
                                    detection_name="Win32/Filecoder.LockBit.C"))
    assert a.base_level == "LOW"
    assert a.level == "HIGH"


def test_outbreak_events_are_critical():
    a = assess_risk(NormalizedAlert(severity="LOW", threat_handled="true", event_type="Outbreak detected"))
    assert a.level == "CRITICAL"


def test_multiple_endpoints_reported_in_the_payload_are_critical():
    alert = NormalizedAlert(severity="HIGH", threat_handled="false", endpoint_name="PC-1",
                            raw_payload={"affected_endpoints": ["PC-1", "PC-2", {"name": "PC-3"}]})
    assert reported_endpoint_count(alert) == 3
    assert assess_risk(alert).level == "CRITICAL"


def test_reported_count_field_is_understood():
    alert = NormalizedAlert(severity="MEDIUM", raw_payload={"endpoint_count": "5"})
    assert reported_endpoint_count(alert) == 5


def test_multiple_endpoints_observed_by_the_platform_are_critical():
    alert = NormalizedAlert(severity="MEDIUM", threat_handled="false", detection_name="Win32/Qbot.AX")
    assert assess_risk(alert, observed_endpoint_count=2).level == "MEDIUM"
    a = assess_risk(alert, observed_endpoint_count=3)
    assert a.level == "CRITICAL"
    assert "multiple_endpoints_observed" in _rules(a)


def test_rules_never_lower_the_base_level():
    a = assess_risk(NormalizedAlert(severity="CRITICAL", threat_handled="true"), _intel(vt="CLEAN"))
    assert a.level == "CRITICAL"


def test_every_decision_is_explained():
    a = assess_risk(NormalizedAlert(severity="MEDIUM", threat_handled="false", endpoint_type="Server",
                                    detection_name="Win32/Filecoder.X"), _intel(vt="MALICIOUS"))
    assert a.level == "CRITICAL"
    assert [f.effect for f in a.factors][0] == "base"
    assert all(f.detail for f in a.factors)
    assert "Raised from" in a.rationale


def test_severity_aliases():
    assert compute_risk(NormalizedAlert(severity="Warning", threat_handled="true"))[0] == "LOW"
    assert compute_risk(NormalizedAlert(severity="information", threat_handled="true"))[0] == "LOW"


# --------------------------- fields the alert did not report ---------------------------

def test_missing_threat_handled_is_neutral_not_false():
    # The level matches the unhandled case (nothing says it was handled), but the
    # rationale must not claim the threat was reported as unhandled...
    level, rationale = compute_risk(NormalizedAlert(severity="HIGH"))
    assert level == "HIGH"
    assert "not handled." not in rationale
    # ...and must never surface as an "unknown" field in the text the AI and the
    # emails are built from.
    assert "unknown" not in rationale.lower()


def test_missing_severity_uses_the_safety_default_without_inventing_a_value():
    level, rationale = compute_risk(NormalizedAlert())
    assert level == "MEDIUM"
    assert "None" not in rationale and "unknown" not in rationale.lower()
    assert "does not report a severity" in rationale


def test_assess_risk_handles_an_alert_with_no_fields_at_all():
    assessment = assess_risk(NormalizedAlert(), _intel())
    assert assessment.level == "MEDIUM"
    assert [f.rule for f in assessment.factors] == ["severity_unknown"]
