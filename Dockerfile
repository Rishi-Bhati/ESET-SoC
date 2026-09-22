# ESET SOC Lite — single container: ingest API, dashboard and syslog listeners.
#
#   docker build -t eset-soc-lite .
#   docker run --env-file .env -p 8000:8000 -v soc-data:/data eset-soc-lite
#
# Everything the platform writes (SQLite DB, alert results, email outbox, logs)
# lives under /data — mount a volume there or it is lost on every redeploy.

FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Unprivileged runtime user; owns only /data.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin soc \
 && mkdir -p /data \
 && chown soc:soc /data

COPY --chown=root:root src ./src
COPY --chown=root:root static ./static
COPY --chown=root:root run.py ./

ENV APP_ENV=production \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    SQLITE_DB_PATH=/data/soc_lite.db \
    OUTPUT_DIR=/data/output/alerts \
    LOG_FILE=/data/logs/app.log \
    # A non-root process cannot bind ports below 1024. Map 514/601 on the host
    # to these (see docker-compose.yml).
    SYSLOG_UDP_PORT=5514 \
    SYSLOG_TCP_PORT=5601

USER soc
VOLUME ["/data"]
EXPOSE 8000 5514/udp 5601/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT') or os.environ.get('APP_PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=4).status == 200 else 1)"

CMD ["python", "run.py"]
