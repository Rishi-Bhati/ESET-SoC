"""
Single-command entrypoint for the whole platform: the ingestion API,
the live dashboard, and the syslog UDP/TCP listeners all run together
in one process (see src/main.py's lifespan for the syslog wiring).

Usage:
    .venv/bin/python run.py
"""
import uvicorn
from src.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host=settings.app_host,
        port=settings.app_port,
        log_config=None,  # structlog (configured in src.utils.logging) owns log formatting
    )
