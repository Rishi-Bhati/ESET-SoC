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

def test_risk_low():
    alert = NormalizedAlert(severity="LOW")
    risk, rationale = compute_risk(alert)
    assert risk == "LOW"

def test_risk_unknown_fallback():
    alert = NormalizedAlert(severity="SOMETHING_ELSE")
    risk, rationale = compute_risk(alert)
    assert risk == "MEDIUM"
    assert "Falling back to MEDIUM" in rationale
