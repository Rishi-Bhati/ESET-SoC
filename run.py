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
    # The syslog forwarder (src/services/syslog_runtime.py) posts to
    # 127.0.0.1:{settings.app_port}; keep it pointed at the port actually bound.
    settings.app_port = port

    uvicorn.run(
        "src.main:app",
        host=settings.app_host,
        port=port,
        log_config=None,  # structlog (configured in src.utils.logging) owns log formatting
        # Real client address and scheme from a trusted reverse proxy — needed
        # for per-client auth throttling and for HSTS behind TLS termination.
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
        server_header=False,
    )
