import asyncio
import structlog
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult, VirusTotalResult, AbuseIPDBResult
from src.services.threat_intel.virustotal import VirusTotalProvider
from src.services.threat_intel.abuseipdb import AbuseIPDBProvider
from src.config import settings

logger = structlog.get_logger(__name__)

async def gather_threat_intel(alert: NormalizedAlert) -> ThreatIntelResult:
    """
    Gathers threat intelligence verdicts from all configured providers in parallel.
    Uses asyncio.wait_for to apply hard timeout protection.
    If a provider times out or fails, returns an UNKNOWN result so the pipeline continues.
    """
    logger.info("threat_intel_gather_start")
    
    vt_provider = VirusTotalProvider()
    abuse_provider = AbuseIPDBProvider()
    
    timeout_sec = settings.threat_intel_timeout_seconds
    
    async def run_vt() -> VirusTotalResult:
        try:
            return await asyncio.wait_for(vt_provider.query(alert), timeout=timeout_sec)
        except asyncio.TimeoutError:
            logger.warning("vt_query_timeout", timeout=timeout_sec)
            return VirusTotalResult(status="UNKNOWN", query="TIMEOUT", error="VirusTotal query timed out")
        except Exception as e:
            logger.error("vt_query_failed_uncaught", error=str(e))
            return VirusTotalResult(status="UNKNOWN", query="ERROR", error=str(e))
            
    async def run_abuse() -> AbuseIPDBResult:
        try:
            return await asyncio.wait_for(abuse_provider.query(alert), timeout=timeout_sec)
        except asyncio.TimeoutError:
            logger.warning("abuseipdb_query_timeout", timeout=timeout_sec)
            return AbuseIPDBResult(status="UNKNOWN", query="TIMEOUT", error="AbuseIPDB query timed out")
        except Exception as e:
            logger.error("abuseipdb_query_failed_uncaught", error=str(e))
            return AbuseIPDBResult(status="UNKNOWN", query="ERROR", error=str(e))
            
    # Concurrently execute both queries
    vt_result, abuse_result = await asyncio.gather(run_vt(), run_abuse())
    
    logger.info(
        "threat_intel_gather_complete",
        vt_status=vt_result.status,
        abuse_status=abuse_result.status
    )
    
    return ThreatIntelResult(
        virustotal=vt_result,
        abuseipdb=abuse_result
    )
