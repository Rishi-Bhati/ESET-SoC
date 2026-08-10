from pydantic import BaseModel, Field

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
