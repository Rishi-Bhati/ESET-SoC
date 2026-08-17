import asyncio
import structlog
from src.config import settings
from src.utils.logging import setup_logging
from src.services import syslog_runtime

logger = structlog.get_logger(__name__)


async def main() -> None:
    """
    Standalone entrypoint for running the syslog listeners as their own process.
    Kept for backward compatibility — the primary path now embeds these listeners
    directly in the FastAPI process via src.services.syslog_runtime (see src/main.py).
    """
    setup_logging(settings.log_level, log_file="logs/syslog_server.log")
    logger.info("syslog_server_starting")

    handles = await syslog_runtime.start()

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("syslog_server_cancelled")
    finally:
        await syslog_runtime.stop(handles)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
