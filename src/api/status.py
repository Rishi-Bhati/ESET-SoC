import os
import json
from typing import Any
from fastapi import APIRouter, HTTPException
import structlog
from src.storage import job_store
from src.config import settings

router = APIRouter(prefix="/status", tags=["Status"])
logger = structlog.get_logger(__name__)

@router.get("/{correlation_id}")
async def get_job_status(correlation_id: str) -> dict[str, Any]:
    """
    Checks the status of a pipeline job by correlation_id.
    If successfully processed, returns references to the written file.
    """
    job = await job_store.get_job(correlation_id)
    if not job:
        logger.warning("status_query_not_found", correlation_id=correlation_id)
        raise HTTPException(status_code=404, detail="Job not found")
        
    response = {
        "correlation_id": job["correlation_id"],
        "source": job["source"],
        "status": job["status"],
        "created_at": job["created_at"],
        "updated_at": job["updated_at"],
        "error": job["error"],
        "output_file": None
    }
    
    # If completed, check if the output file exists
    if job["status"] in ("SUCCESS", "PARTIAL"):
        output_file_name = f"{correlation_id}.json"
        output_file_path = os.path.join(settings.output_dir, output_file_name)
        if os.path.exists(output_file_path):
            response["output_file"] = output_file_path
            
    return response
