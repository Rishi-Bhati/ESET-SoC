import ipaddress
import os
import httpx
import structlog
from src.services.threat_intel.base import BaseThreatIntelProvider
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import AbuseIPDBResult, NO_INDICATOR_QUERY
from src.config import settings

logger = structlog.get_logger(__name__)

class AbuseIPDBProvider(BaseThreatIntelProvider):
    """
    AbuseIPDB Threat Intelligence Provider.
    Queries AbuseIPDB for suspicious/malicious IP addresses.
    Supports a mock mode for local prototype usage without API keys.
    """
    
    async def query(self, alert: NormalizedAlert) -> AbuseIPDBResult:
        ip = alert.ip_address
        if not ip or ip == "UNKNOWN":
            logger.debug("abuseipdb_no_ip_found")
            return AbuseIPDBResult(status="UNKNOWN", query=NO_INDICATOR_QUERY)
            
        if settings.use_mock_threat_intel:
            return self._query_mock(ip)
            
        return await self._query_real(ip)
        
    def _query_mock(self, ip: str) -> AbuseIPDBResult:
        """
        Simulates AbuseIPDB API check response.
        """
        logger.info("abuseipdb_query_mock", ip=ip)
        
        # Simple heuristics for testing
        if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
            return AbuseIPDBResult(
                status="CLEAN",
                abuse_confidence_score=0,
                total_reports=0,
                country_code="PRIVATE",
                query=ip
            )
        elif "100" in ip:  # Arbitrary test condition
            return AbuseIPDBResult(
                status="MALICIOUS",
                abuse_confidence_score=100,
                total_reports=1420,
                country_code="CN",
                query=ip
            )
        elif "50" in ip:
            return AbuseIPDBResult(
                status="SUSPICIOUS",
                abuse_confidence_score=45,
                total_reports=12,
                country_code="RU",
                query=ip
            )
        else:
            # Default clean mock for public IPs
            return AbuseIPDBResult(
                status="CLEAN",
                abuse_confidence_score=2,
                total_reports=1,
                country_code="US",
                query=ip
            )
            
    async def _query_real(self, ip: str) -> AbuseIPDBResult:
        """
        Executes a real async HTTP call to the AbuseIPDB check API endpoint.
        """
        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not api_key:
            logger.error("abuseipdb_real_query_missing_api_key")
            return AbuseIPDBResult(status="UNKNOWN", query=ip, error="Missing ABUSEIPDB_API_KEY")
            
        # httpx encodes query parameters, so a malformed value cannot escape the
        # URL here the way it can in a path segment — but the value still comes
        # from an attacker-influenced alert field, and sending it to a third
        # party at all is worth refusing when it is not even an IP address.
        try:
            if "%" in ip:
                raise ValueError("Scoped IP addresses are not public indicators")
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("abuseipdb_indicator_rejected", ip=str(ip)[:80])
            return AbuseIPDBResult(status="UNKNOWN", query=ip, error="Not a valid IP address")

        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": ""
        }
        url = "https://api.abuseipdb.com/api/v2/check"
        
        try:
            async with httpx.AsyncClient() as client:
                logger.info("abuseipdb_query_real_start", url=url, ip=ip)
                response = await client.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=settings.threat_intel_timeout_seconds
                )
                
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    country = data.get("countryCode", "UNKNOWN")
                    
                    status = "CLEAN"
                    if score >= 50:
                        status = "MALICIOUS"
                    elif score > 10 or reports > 5:
                        status = "SUSPICIOUS"
                        
                    return AbuseIPDBResult(
                        status=status,
                        abuse_confidence_score=score,
                        total_reports=reports,
                        country_code=country,
                        query=ip
                    )
                else:
                    logger.error("abuseipdb_query_http_error", status_code=response.status_code, body=response.text)
                    return AbuseIPDBResult(
                        status="UNKNOWN",
                        query=ip,
                        error=f"HTTP {response.status_code}: {response.text[:200]}"
                    )
        except Exception as e:
            logger.error("abuseipdb_query_exception", error=str(e))
            return AbuseIPDBResult(status="UNKNOWN", query=ip, error=str(e))
