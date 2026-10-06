"""Every sentence the rule engine can produce has a Japanese version
(src/services/risk_text_ja.py), so the Japanese emails never fall back to English."""
import itertools
import re

import pytest
from src.config import settings
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import AbuseIPDBResult, ThreatIntelResult, VirusTotalResult
from src.services.risk_engine import assess_risk
from src.services.risk_text_ja import to_japanese

_ENGLISH_WORDS = re.compile(r"[A-Za-z]{3,} [A-Za-z]{3,}")


def _alerts():
    for severity, handled, isolated in itertools.product(
            (None, "CRITICAL", "HIGH", "MEDIUM", "LOW", "weird"), (None, "true", "false"), (None, "true")):
        yield NormalizedAlert(severity=severity, threat_handled=handled, isolation_status=isolated)
    yield NormalizedAlert(severity="LOW", detection_name="Win32/Filecoder.A")
    yield NormalizedAlert(severity="LOW", threat_handled="true", detection_name="Win32/Filecoder.A")
    yield NormalizedAlert(severity="LOW", raw_subject="Outbreak detected")
    yield NormalizedAlert(severity="LOW", endpoint_type="Server")
    yield NormalizedAlert(severity="LOW", raw_payload={"affected_endpoints": ["a", "b", "c", "d", "e"]})


@pytest.mark.parametrize("vt,abuse", [("UNKNOWN", "UNKNOWN"), ("MALICIOUS", "UNKNOWN"), ("UNKNOWN", "SUSPICIOUS")])
def test_every_rule_sentence_has_a_japanese_version(vt, abuse, monkeypatch):
    monkeypatch.setattr(settings, "outbreak_endpoint_threshold", 3)
    intel = ThreatIntelResult(virustotal=VirusTotalResult(status=vt), abuseipdb=AbuseIPDBResult(status=abuse))
    for alert in _alerts():
        for factor in assess_risk(alert, intel, observed_endpoint_count=4).factors:
            ja = to_japanese(factor.detail)
            assert not _ENGLISH_WORDS.search(ja), factor.detail


def test_unknown_sentences_are_returned_unchanged():
    assert to_japanese("Some future rule fired.") == "Some future rule fired."
