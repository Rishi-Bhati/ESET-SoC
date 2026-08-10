from abc import ABC, abstractmethod
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult
from src.models.ai_output import AIOutput

class BaseAIProvider(ABC):
    """
    Abstract interface for AI analysis providers.
    """
    
    @abstractmethod
    async def generate(
        self,
        alert: NormalizedAlert,
        risk_level: str,
        threat_intel: ThreatIntelResult
    ) -> AIOutput:
        """
        Queries the AI model using structured input data and generates the bilingually structured AIOutput.
        """
        pass
