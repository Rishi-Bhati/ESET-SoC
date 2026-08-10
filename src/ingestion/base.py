from abc import ABC, abstractmethod
from typing import Any
from src.models.raw_payload import EsetRawPayload

class BaseIngestionHandler(ABC):
    """
    Abstract base class for ingestion handlers.
    Each ingestion source (Webhook, Syslog) must implement this.
    """
    
    @abstractmethod
    def parse(self, raw_data: Any) -> EsetRawPayload:
        """
        Parses raw input data into standard EsetRawPayload.
        """
        pass
