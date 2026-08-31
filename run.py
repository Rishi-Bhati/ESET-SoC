"""
Single-command entrypoint for the whole platform: the ingestion API,
the live dashboard, and the syslog UDP/TCP listeners all run together
in one process (see src/main.py's lifespan for the syslog wiring).

Usage:
    .venv/bin/python run.py
"""
import os
import uvicorn
from src.config import settings

if __name__ == "__main__":
    # Railway (and any Heroku-style host) assigns the port at runtime and
    # publishes it as $PORT; binding APP_PORT instead means nothing is listening
    # where the platform's health check looks. $PORT wins when present, so local
    # runs still honour APP_PORT.
    port = int(os.environ.get("PORT") or settings.app_port)

    uvicorn.run(
        "src.main:app",
        host=settings.app_host,
        port=port,
        log_config=None,  # structlog (configured in src.utils.logging) owns log formatting
    )
