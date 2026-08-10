from abc import ABC, abstractmethod
from typing import Any
from src.models.normalized_alert import NormalizedAlert

class BaseThreatIntelProvider(ABC):
    """
    Abstract interface for Threat Intelligence providers (e.g. VirusTotal, AbuseIPDB).
    Each provider implements its own parsing/lookup logic.
    """
    
    @abstractmethod
    async def query(self, alert: NormalizedAlert) -> Any:
        """
        Queries the threat intelligence source using indicators from the normalized alert.
        """
        pass
