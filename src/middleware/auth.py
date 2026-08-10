import hmac
from fastapi import Request, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
import structlog
from src.config import settings

logger = structlog.get_logger(__name__)

# Webhooks from ESET may send credentials in the Authorization header.
# We configure APIKeyHeader to retrieve this header.
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def validate_eset_token(
    request: Request,
    api_key: str | None = Security(api_key_header),
) -> None:
    """
    Validates ESET webhook authorization token using a timing-attack safe comparison.
    If unauthorized, logs client details and raises 401 with no response body detail.
    """
    client_ip = request.client.host if request.client else "unknown"
    
    if not api_key:
        logger.warning("auth_failed_missing_header", client_ip=client_ip)
        raise HTTPException(status_code=401)
        
    # Standardize header token: check if it's 'Bearer <token>' or just '<token>'
    token = api_key
    if api_key.lower().startswith("bearer "):
        token = api_key[7:].strip()
        
    expected_token = settings.eset_webhook_auth_token
    
    # Timing-safe comparison to prevent side-channel analysis
    if not hmac.compare_digest(token, expected_token):
        logger.warning("auth_failed_token_mismatch", client_ip=client_ip)
        raise HTTPException(status_code=401)
        
    logger.debug("auth_success", client_ip=client_ip)
