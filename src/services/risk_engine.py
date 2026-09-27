"""
Rule-based risk assessment. The ONLY place a risk level is decided.

The AI provider is handed the result of this module and asked to explain it;
it is never asked for, and never allowed to change, the level itself (see
src/services/ai/output_validator.py). Every rule below is deterministic, so the
same alert and context always produce the same level and the same rationale.

Inputs, in the order they are applied:

  1. ESET alert information + handling status — the base level from the
     reported severity, whether the threat was handled, and whether the
     endpoint was isolated.
  2. External threat intelligence — a MALICIOUS/SUSPICIOUS verdict on an
     indicator raises the floor.
  3. Endpoint importance — an unhandled detection on an important endpoint
     (server, domain controller, or a name matching IMPORTANT_ENDPOINT_PATTERNS)
     is raised one level, never above HIGH by this rule alone.
  4. Event pattern — ransomware-like detections, ESET outbreak events, and the
     same detection on several endpoints are CRITICAL.

Rules only ever raise the level after step 1; nothing after the handling-status
check can make an alert look safer than its base.

The rule table is an engineering proposal pending client sign-off. Thresholds
and endpoint lists are configurable (src/config.py) without a code change.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from src.config import settings
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult

logger = structlog.get_logger(__name__)

LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_RANK = {level: i for i, level in enumerate(LEVELS)}

# Reported severities outside the four canonical names that still carry an
# unambiguous meaning. Anything else is "unknown severity".
_SEVERITY_ALIASES = {
    "INFO": "LOW", "INFORMATION": "LOW", "INFORMATIONAL": "LOW",
    "WARN": "MEDIUM", "WARNING": "MEDIUM",
}

# Ransomware-like indicators. "Filecoder" is ESET's own family name for
# file-encrypting ransomware (e.g. Win32/Filecoder.WannaCryptor.D).
_RANSOMWARE_RE = re.compile(
    r"ransom|filecoder|file[\s_-]?coder|cryptolocker|wannacry|lockbit|ryuk|blackcat|alphv|"
    r"akira|conti\b|revil|sodinokibi|shadow\s?cop(?:y|ies)\s+(?:delet|remov)|vssadmin\s+delete|"
    r"files?\s+(?:are\s+)?(?:actively\s+)?being\s+encrypted|mass\s+(?:file\s+)?encryption|ランサム",
    re.IGNORECASE,
)
_OUTBREAK_RE = re.compile(r"outbreak|アウトブレイク", re.IGNORECASE)

# Payload keys a sender may use to report how many / which endpoints are affected.
_AFFECTED_LIST_KEYS = ("affected_endpoints", "affected_computers", "affected_hosts", "endpoints", "computers", "hosts")
_AFFECTED_COUNT_KEYS = ("affected_endpoint_count", "affected_endpoints_count", "endpoint_count",
                        "computer_count", "computers_count", "affected_count", "host_count")


@dataclass
class RiskFactor:
    rule: str          # stable identifier, e.g. "threat_intel_malicious"
    effect: str        # "base" | "raised" | "no_change"
    detail: str        # human-readable, English (the AI explains it in Japanese)

    def as_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "effect": self.effect, "detail": self.detail}


@dataclass
class RiskAssessment:
    level: str
    base_level: str
    factors: list[RiskFactor] = field(default_factory=list)

    @property
    def rationale(self) -> str:
        return " ".join(f.detail for f in self.factors if f.effect in ("base", "raised"))

    def factor_dicts(self) -> list[dict[str, str]]:
        return [f.as_dict() for f in self.factors]


def _raise_to(current: str, floor: str) -> str:
    return floor if _RANK[floor] > _RANK[current] else current


def _handled(alert: NormalizedAlert) -> str:
    """'true' | 'false' | 'unknown'"""
    value = alert.threat_handled.strip().lower()
    return value if value in ("true", "false") else "unknown"


def _base_level(alert: NormalizedAlert) -> tuple[str, RiskFactor]:
    reported = alert.severity.strip().upper()
    severity = _SEVERITY_ALIASES.get(reported, reported)
    handled = _handled(alert)
    isolated = alert.isolation_status.strip().lower() == "true"

    if severity == "CRITICAL":
        return "CRITICAL", RiskFactor("severity_critical", "base",
            "Alert severity is CRITICAL. Immediate escalation required regardless of mitigation status.")

    if severity == "HIGH":
        if handled == "true" and isolated:
            return "LOW", RiskFactor("severity_high_handled_isolated", "base",
                "Alert severity is HIGH, but the threat is marked as handled and the endpoint is reported as isolated.")
        if handled == "true":
            return "MEDIUM", RiskFactor("severity_high_handled", "base",
                "Alert severity is HIGH and the threat is marked as handled, but the endpoint has not been isolated.")
        return "HIGH", RiskFactor("severity_high_unhandled", "base",
            "Alert severity is HIGH and the threat is not handled."
            if handled == "false" else
            "Alert severity is HIGH and whether the threat was handled is unknown.")

    if severity == "MEDIUM":
        if handled == "true":
            return "LOW", RiskFactor("severity_medium_handled", "base",
                "Alert severity is MEDIUM and the threat is marked as handled.")
        return "MEDIUM", RiskFactor("severity_medium_unhandled", "base",
            "Alert severity is MEDIUM and the threat has not been handled."
            if handled == "false" else
            "Alert severity is MEDIUM and whether the threat was handled is unknown.")

    if severity == "LOW":
        if handled == "true":
            return "LOW", RiskFactor("severity_low_handled", "base",
                "Alert severity is LOW and the threat is marked as handled.")
        return "MEDIUM", RiskFactor("severity_low_not_confirmed_handled", "base",
            "Alert severity is LOW, but the threat is not handled."
            if handled == "false" else
            "Alert severity is LOW, but whether the threat was handled is unknown, so it needs confirmation.")

    logger.warning("risk_engine_unknown_severity", severity=alert.severity)
    return "MEDIUM", RiskFactor("severity_unknown", "base",
        f"Unknown alert severity '{alert.severity}'. Falling back to MEDIUM risk safety default.")


def _text_fields(alert: NormalizedAlert) -> str:
    return " ".join(v for v in (alert.detection_name, alert.event_type, alert.raw_subject, alert.raw_content)
                    if v and v != "UNKNOWN")


def reported_endpoint_count(alert: NormalizedAlert) -> int:
    """Distinct affected endpoints the payload itself reports (top-level keys
    only), counting the alert's own endpoint. 1 when nothing is reported."""
    payload: Any = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
    lower = {str(k).lower(): v for k, v in payload.items()}
    names: set[str] = set()
    if alert.endpoint_name and alert.endpoint_name != "UNKNOWN":
        names.add(alert.endpoint_name.strip().lower())
    for key in _AFFECTED_LIST_KEYS:
        value = lower.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    item = item.get("name") or item.get("endpoint_name") or item.get("computer_name") or item.get("hostname")
                if isinstance(item, str) and item.strip():
                    names.add(item.strip().lower())
    count = len(names)
    for key in _AFFECTED_COUNT_KEYS:
        value = lower.get(key)
        try:
            count = max(count, int(value))
        except (TypeError, ValueError):
            continue
    return max(count, 1)


def is_important_endpoint(alert: NormalizedAlert) -> str | None:
    """Why the endpoint counts as important, or None."""
    endpoint_type = alert.endpoint_type.strip().lower()
    if endpoint_type and endpoint_type != "unknown":
        for word in (w.strip().lower() for w in settings.important_endpoint_types.split(",")):
            if word and word in endpoint_type:
                return f"endpoint type '{alert.endpoint_type}'"
    name = alert.endpoint_name.strip()
    if name and name != "UNKNOWN":
        for pattern in (p.strip() for p in settings.important_endpoint_patterns.split(",")):
            if pattern and fnmatch.fnmatch(name.lower(), pattern.lower()):
                return f"endpoint name '{name}' matches important-asset pattern '{pattern}'"
    return None


def assess_risk(
    alert: NormalizedAlert,
    threat_intel: ThreatIntelResult | None = None,
    *,
    observed_endpoint_count: int = 1,
) -> RiskAssessment:
    """
    Deterministic risk level for one alert.

    `observed_endpoint_count` is how many distinct endpoints this platform has
    seen the same detection on within OUTBREAK_WINDOW_SECONDS (see
    src/storage/observation_store.py); the caller supplies it so this function
    stays pure.
    """
    level, base = _base_level(alert)
    assessment = RiskAssessment(level=level, base_level=level, factors=[base])
    handled = _handled(alert)

    def apply(floor: str, rule: str, detail: str) -> None:
        new_level = _raise_to(assessment.level, floor)
        if new_level != assessment.level:
            assessment.factors.append(RiskFactor(rule, "raised", f"{detail} Raised from {assessment.level} to {new_level}."))
            assessment.level = new_level
        else:
            assessment.factors.append(RiskFactor(rule, "no_change", f"{detail} Level already {assessment.level}."))

    # 2. External threat intelligence
    if threat_intel is not None:
        verdicts = {
            "VirusTotal": threat_intel.virustotal.status,
            "AbuseIPDB": threat_intel.abuseipdb.status,
        }
        malicious = [name for name, status in verdicts.items() if status == "MALICIOUS"]
        suspicious = [name for name, status in verdicts.items() if status == "SUSPICIOUS"]
        if malicious:
            apply("HIGH" if handled != "true" else "MEDIUM", "threat_intel_malicious",
                  f"External threat intelligence ({', '.join(malicious)}) reports an indicator as MALICIOUS"
                  f"{' and the threat is not confirmed handled' if handled != 'true' else ''}.")
        elif suspicious and handled != "true":
            apply("MEDIUM", "threat_intel_suspicious",
                  f"External threat intelligence ({', '.join(suspicious)}) reports an indicator as SUSPICIOUS.")

    # 3. Endpoint importance
    important = is_important_endpoint(alert)
    if important and handled != "true":
        one_up = LEVELS[min(_RANK[assessment.level] + 1, _RANK["HIGH"])]
        apply(one_up, "important_endpoint",
              f"The detection is on an important endpoint ({important}) and is not confirmed handled.")

    # 4. Event pattern
    text = _text_fields(alert)
    match = _RANSOMWARE_RE.search(text)
    if match:
        if handled == "true":
            apply("HIGH", "ransomware_indicator_handled",
                  f"Ransomware-like indicator '{match.group(0)}' is present, although the threat is marked as handled.")
        else:
            apply("CRITICAL", "ransomware_indicator",
                  f"Ransomware-like indicator '{match.group(0)}' is present and the threat is not confirmed handled.")

    if _OUTBREAK_RE.search(text):
        apply("CRITICAL", "outbreak_event", "The alert is reported as an outbreak.")

    threshold = settings.outbreak_endpoint_threshold
    reported = reported_endpoint_count(alert)
    if reported >= threshold:
        apply("CRITICAL", "multiple_endpoints_reported",
              f"The alert reports {reported} affected endpoints (threshold {threshold}).")
    elif observed_endpoint_count >= threshold:
        window_min = settings.outbreak_window_seconds // 60
        apply("CRITICAL", "multiple_endpoints_observed",
              f"The same detection has been seen on {observed_endpoint_count} distinct endpoints "
              f"within {window_min} minutes (threshold {threshold}).")

    logger.info("risk_assessed", level=assessment.level, base_level=assessment.base_level,
                rules=[f.rule for f in assessment.factors])
    return assessment


def compute_risk(alert: NormalizedAlert) -> tuple[str, str]:
    """(level, rationale) from alert fields alone — no intel, no history."""
    assessment = assess_risk(alert)
    return assessment.level, assessment.rationale
