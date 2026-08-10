import structlog
from src.models.normalized_alert import NormalizedAlert

logger = structlog.get_logger(__name__)

def compute_risk(alert: NormalizedAlert) -> tuple[str, str]:
    """
    Determines the risk level (LOW, MEDIUM, HIGH, CRITICAL) and the rationale
    based on a strict, rule-based logic. Does NOT use AI for decision making.
    """
    severity = alert.severity.strip().upper()
    handled = alert.threat_handled.strip().lower()
    isolated = alert.isolation_status.strip().lower()
    
    # 1. Critical cases
    if severity == "CRITICAL":
        return (
            "CRITICAL",
            "Alert severity is CRITICAL. Immediate escalation required regardless of mitigation status."
        )
        
    # 2. High severity cases
    if severity == "HIGH":
        if handled == "true":
            if isolated == "true":
                return (
                    "LOW",
                    "Alert severity is HIGH, but the threat is marked as handled and the endpoint has been successfully isolated."
                )
            else:
                return (
                    "MEDIUM",
                    "Alert severity is HIGH and the threat is marked as handled, but the endpoint has not been isolated."
                )
        else:
            return (
                "HIGH",
                "Alert severity is HIGH and the threat is not handled."
            )
            
    # 3. Medium severity cases
    if severity == "MEDIUM":
        if handled == "true":
            return (
                "LOW",
                "Alert severity is MEDIUM and the threat is marked as handled."
            )
        else:
            return (
                "MEDIUM",
                "Alert severity is MEDIUM and the threat has not been handled."
            )
            
    # 4. Low severity cases
    if severity == "LOW":
        return (
            "LOW",
            "Alert severity is LOW."
        )
        
    # 5. Default/Fallback cases
    logger.warning("risk_engine_unknown_severity", severity=alert.severity)
    return (
        "MEDIUM",
        f"Unknown alert severity '{alert.severity}'. Falling back to MEDIUM risk safety default."
    )
