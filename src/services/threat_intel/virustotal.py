import os
import httpx
import structlog
from src.services.threat_intel.base import BaseThreatIntelProvider
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import VirusTotalResult
from src.config import settings

logger = structlog.get_logger(__name__)

class VirusTotalProvider(BaseThreatIntelProvider):
    """
    VirusTotal API Provider.
    Queries VT for file hashes, IPs, or URLs found in the alert.
    Supports a mock mode for local prototype usage without API keys.
    """
    
    async def query(self, alert: NormalizedAlert) -> VirusTotalResult:
        # Determine query indicator
        indicator = "UNKNOWN"
        indicator_type = None
        
        if alert.file_hash and alert.file_hash != "UNKNOWN":
            indicator = alert.file_hash
            indicator_type = "file"
        elif alert.url and alert.url != "UNKNOWN":
            indicator = alert.url
            indicator_type = "url"
        elif alert.ip_address and alert.ip_address != "UNKNOWN":
            indicator = alert.ip_address
            indicator_type = "ip"
            
        if indicator_type is None:
            logger.debug("vt_no_indicator_found")
            return VirusTotalResult(status="UNKNOWN", query="NONE")
            
        if settings.use_mock_threat_intel:
            return self._query_mock(indicator, indicator_type)
            
        return await self._query_real(indicator, indicator_type)
        
    def _query_mock(self, indicator: str, indicator_type: str) -> VirusTotalResult:
        """
        Simulates VirusTotal API lookup.
        """
        logger.info("vt_query_mock", indicator=indicator, type=indicator_type)
        
        # Simple heuristic mock
        indicator_lower = indicator.lower()
        if "malicious" in indicator_lower or "ransom" in indicator_lower or "virus" in indicator_lower:
            return VirusTotalResult(
                status="MALICIOUS",
                positives=48,
                total=72,
                permalink=f"https://www.virustotal.com/gui/mock/{indicator}",
                query=indicator
            )
        elif "suspicious" in indicator_lower or "warn" in indicator_lower:
            return VirusTotalResult(
                status="SUSPICIOUS",
                positives=5,
                total=72,
                permalink=f"https://www.virustotal.com/gui/mock/{indicator}",
                query=indicator
            )
        elif indicator == "UNKNOWN" or not indicator:
            return VirusTotalResult(status="UNKNOWN", query=indicator)
        else:
            return VirusTotalResult(
                status="CLEAN",
                positives=0,
                total=72,
                permalink=f"https://www.virustotal.com/gui/mock/{indicator}",
                query=indicator
            )
            
    async def _query_real(self, indicator: str, indicator_type: str) -> VirusTotalResult:
        """
        Executes a real async HTTP call to the VirusTotal v3 API.
        """
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            logger.error("vt_real_query_missing_api_key")
            return VirusTotalResult(status="UNKNOWN", query=indicator, error="Missing VIRUSTOTAL_API_KEY")
            
        headers = {"x-apikey": api_key}
        
        # Build API endpoint
        if indicator_type == "file":
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        elif indicator_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        elif indicator_type == "url":
            # VT requires URLs to be base64-encoded without padding
            import base64
            encoded_url = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("utf-8").strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        else:
            return VirusTotalResult(status="UNKNOWN", query=indicator)
            
        try:
            async with httpx.AsyncClient() as client:
                logger.info("vt_query_real_start", url=url)
                response = await client.get(
                    url, 
                    headers=headers, 
                    timeout=settings.threat_intel_timeout_seconds
                )
                
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    stats = data.get("attributes", {}).get("last_analysis_stats", {})
                    positives = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    permalink = data.get("links", {}).get("self", "UNKNOWN")
                    
                    status = "CLEAN"
                    if positives > 5:
                        status = "MALICIOUS"
                    elif positives > 0 or suspicious > 0:
                        status = "SUSPICIOUS"
                        
                    return VirusTotalResult(
                        status=status,
                        positives=positives,
                        total=total,
                        permalink=permalink,
                        query=indicator
                    )
                elif response.status_code == 404:
                    logger.info("vt_query_not_found", indicator=indicator)
                    return VirusTotalResult(status="UNKNOWN", query=indicator, error="Indicator not found in VirusTotal")
                else:
                    logger.error("vt_query_http_error", status_code=response.status_code, body=response.text)
                    return VirusTotalResult(
                        status="UNKNOWN", 
                        query=indicator, 
                        error=f"HTTP {response.status_code}: {response.text[:200]}"
                    )
        except Exception as e:
            logger.error("vt_query_exception", error=str(e))
            return VirusTotalResult(status="UNKNOWN", query=indicator, error=str(e))
