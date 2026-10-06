from pydantic import BaseModel, Field

# The `query` a provider records when the alert carried no indicator for it to
# look up (no hash/URL/IP for VirusTotal, no IP for AbuseIPDB).
NO_INDICATOR_QUERY = "NONE"

class VirusTotalResult(BaseModel):
    status: str = Field(default="UNKNOWN")  # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    positives: int = Field(default=0)
    total: int = Field(default=0)
    permalink: str = Field(default="UNKNOWN")
    query: str = Field(default="UNKNOWN")
    error: str | None = Field(default=None)

class AbuseIPDBResult(BaseModel):
    status: str = Field(default="UNKNOWN")  # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    abuse_confidence_score: int = Field(default=0)
    total_reports: int = Field(default=0)
    country_code: str = Field(default="UNKNOWN")
    query: str = Field(default="UNKNOWN")
    error: str | None = Field(default=None)

class ThreatIntelResult(BaseModel):
    virustotal: VirusTotalResult = Field(default_factory=VirusTotalResult)
    abuseipdb: AbuseIPDBResult = Field(default_factory=AbuseIPDBResult)

    def looked_up_providers(self) -> list[str]:
        """The providers that had an indicator from the alert to look up. One
        with nothing to query has no verdict to report, not an UNKNOWN one."""
        return [name for name in ("virustotal", "abuseipdb")
                if getattr(self, name).query != NO_INDICATOR_QUERY]
