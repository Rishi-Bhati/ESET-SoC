import os
import tempfile
import json
import asyncio
import structlog
from src.config import settings
from src.models.pipeline_result import PipelineResult

logger = structlog.get_logger(__name__)

# Lock to synchronize concurrent writes to index.json
_index_lock = asyncio.Lock()

async def write_result(result: PipelineResult) -> None:
    """
    Writes the PipelineResult object as a JSON file atomically using a temp file.
    Also appends the execution metadata to index.json.
    """
    # Ensure target directory exists
    os.makedirs(settings.output_dir, exist_ok=True)
    
    file_name = f"{result.correlation_id}.json"
    target_path = os.path.join(settings.output_dir, file_name)
    
    logger.info("output_write_start", path=target_path)
    
    # 1. Write the main result file atomically
    json_data = result.model_dump_json(indent=2)
    
    # Create a temp file in the same directory to guarantee atomic rename (on same mount point)
    temp_fd, temp_path = tempfile.mkstemp(dir=settings.output_dir, prefix=f"{result.correlation_id}_", suffix=".tmp")
    try:
        with os.fdopen(temp_fd, "w") as f:
            f.write(json_data)
        # Atomic file rename (overwrites if target exists)
        os.replace(temp_path, target_path)
        logger.info("output_write_success", path=target_path)
    except Exception as e:
        logger.error("output_write_failed", error=str(e))
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e
        
    # 2. Append metadata to index.json in a thread-safe manner
    async with _index_lock:
        index_path = os.path.join(settings.output_dir, "index.json")
        records = []
        
        # Load existing index records if index.json is present
        if os.path.exists(index_path):
            try:
                with open(index_path, "r") as f:
                    records = json.load(f)
            except Exception as e:
                logger.warning("index_read_failed_reinitializing", error=str(e))
                records = []
                
        # Append new metadata record
        records.append({
            "correlation_id": result.correlation_id,
            "source": result.source,
            "processed_at": result.processed_at,
            "risk_level": result.risk_level,
            "status": result.pipeline_status
        })
        
        # Write index.json atomically
        temp_idx_fd, temp_idx_path = tempfile.mkstemp(dir=settings.output_dir, prefix="index_", suffix=".tmp")
        try:
            with os.fdopen(temp_idx_fd, "w") as f:
                json.dump(records, f, indent=2)
            os.replace(temp_idx_path, index_path)
            logger.info("index_write_success")
        except Exception as e:
            logger.error("index_write_failed", error=str(e))
            if os.path.exists(temp_idx_path):
                os.remove(temp_idx_path)
            # We don't raise here; index failures shouldn't block alert pipelines
