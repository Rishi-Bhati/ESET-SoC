import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    # --- AI ---
    gemini_api_key: str = Field(..., validation_alias="GEMINI_API_KEY")

    # --- Webhook Auth ---
    eset_webhook_auth_token: str = Field(..., validation_alias="ESET_WEBHOOK_AUTH_TOKEN")

    # --- App ---
    # "production" turns configuration mistakes that are merely risky in
    # development (blank dashboard key, placeholder webhook token, API docs on)
    # into a refusal to start — see src/main.py: check_production_config().
    app_env: str = Field("development", validation_alias="APP_ENV")
    app_host: str = Field("0.0.0.0", validation_alias="APP_HOST")
    app_port: int = Field(8000, validation_alias="APP_PORT")
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")
    output_dir: str = Field("output/alerts", validation_alias="OUTPUT_DIR")
    log_file: str = Field("logs/app.log", validation_alias="LOG_FILE")
    # Rotation for LOG_FILE: size of one file and how many rotated files to keep.
    log_max_bytes: int = Field(20_000_000, validation_alias="LOG_MAX_BYTES")
    log_backup_count: int = Field(5, validation_alias="LOG_BACKUP_COUNT")
    # The dashboard polls several endpoints every few seconds and each poll is an
    # access-log line; left in, they are most of the log. Successful GETs of the
    # dashboard's own API, static files and /health are dropped unless this is on.
    # Webhook/syslog requests and every non-2xx/3xx response are always logged.
    log_dashboard_access: bool = Field(False, validation_alias="LOG_DASHBOARD_ACCESS")
    # Addresses of reverse proxies trusted to set X-Forwarded-For/-Proto
    # (uvicorn's forwarded_allow_ips). Without it every client behind a proxy
    # looks like the proxy — which breaks per-client auth throttling. "*" is
    # right on a PaaS (Railway, Render, Fly) where only the platform's edge can
    # reach the app; keep the default on a host with a directly exposed port.
    forwarded_allow_ips: str = Field("127.0.0.1", validation_alias="FORWARDED_ALLOW_IPS")

    # --- Auth throttling ---
    # Wrong webhook tokens / dashboard keys allowed per client address within the
    # window before that address gets 429s. 0 disables throttling.
    auth_max_failures: int = Field(20, validation_alias="AUTH_MAX_FAILURES")
    auth_failure_window_seconds: int = Field(600, validation_alias="AUTH_FAILURE_WINDOW_SECONDS")

    # --- Syslog Server ---
    syslog_host: str = Field("0.0.0.0", validation_alias="SYSLOG_HOST")
    syslog_udp_port: int = Field(514, validation_alias="SYSLOG_UDP_PORT")
    syslog_tcp_port: int = Field(601, validation_alias="SYSLOG_TCP_PORT")
    # Comma-separated source IPs allowed to feed the syslog listeners. The
    # listeners are unauthenticated by protocol, and forward_to_api() attaches the
    # real webhook token on their behalf — so without an allowlist anyone who can
    # reach the port can inject an authenticated alert, and each injected alert
    # costs a Gemini generation and an outbound notification. Blank = accept from
    # anywhere, which is only safe when the port is already behind a network
    # boundary. Set it to the ESET PROTECT exporter's address(es) in production.
    syslog_allowed_sources: str = Field("", validation_alias="SYSLOG_ALLOWED_SOURCES")
    # Bounds on what one sender can make the listeners do. Frames are handed to a
    # fixed worker pool through a bounded queue rather than an unbounded
    # create_task() per datagram, so a flood is dropped at the door instead of
    # growing the event loop until the API process (which hosts these listeners)
    # falls over with it.
    syslog_queue_size: int = Field(500, validation_alias="SYSLOG_QUEUE_SIZE")
    syslog_workers: int = Field(4, validation_alias="SYSLOG_WORKERS")
    syslog_max_tcp_connections: int = Field(50, validation_alias="SYSLOG_MAX_TCP_CONNECTIONS")
    # A TCP peer that connects and never writes holds a file descriptor forever
    # otherwise; FD exhaustion here takes the HTTP API down with it.
    syslog_tcp_idle_timeout_seconds: int = Field(60, validation_alias="SYSLOG_TCP_IDLE_TIMEOUT_SECONDS")
    # Longest single syslog frame accepted, in bytes. Caps the per-connection read
    # buffer so one peer cannot stream an unterminated line into memory.
    syslog_max_frame_bytes: int = Field(64 * 1024, validation_alias="SYSLOG_MAX_FRAME_BYTES")

    # --- Database ---
    sqlite_db_path: str = Field("data/soc_lite.db", validation_alias="SQLITE_DB_PATH")

    # --- Deduplication ---
    dedup_ttl_seconds: int = Field(3600, validation_alias="DEDUP_TTL_SECONDS")

    # --- Pipeline Limits ---
    # Includes pipelines queued in HTTP BackgroundTasks, not only running AI calls.
    max_concurrent_pipelines: int = Field(4, gt=0, validation_alias="MAX_CONCURRENT_PIPELINES")
    threat_intel_timeout_seconds: int = Field(5, validation_alias="THREAT_INTEL_TIMEOUT_SECONDS")
    ai_timeout_seconds: int = Field(30, validation_alias="AI_TIMEOUT_SECONDS")
    max_retries: int = Field(3, validation_alias="MAX_RETRIES")

    # --- Feature Flags for Testing ---
    use_mock_threat_intel: bool = True  # Defaults to True for prototype

    # --- AI Data Minimization ---
    # Masks fields the audit (docs/SOC_LITE_AUDIT.md §9) judged unnecessary for AI
    # reasoning (e.g. user_name) before they are sent to Gemini. Engineering default
    # is ON; the exact field policy still needs client sign-off before production.
    ai_masking_enabled: bool = Field(True, validation_alias="AI_MASKING_ENABLED")

    # --- Ingest Limits ---
    # Defense-in-depth cap on inbound webhook body size (bytes). A Content-Length
    # header above this is rejected with 413 before the body is parsed.
    max_ingest_body_bytes: int = Field(1_048_576, validation_alias="MAX_INGEST_BODY_BYTES")

    # --- Email Outbox Recipients (comma-separated addresses, blank = skip that type) ---
    client_notification_emails: str = Field("", validation_alias="CLIENT_NOTIFICATION_EMAILS")
    cthree_notification_emails: str = Field("", validation_alias="CTHREE_NOTIFICATION_EMAILS")
    internal_notification_emails: str = Field("", validation_alias="INTERNAL_NOTIFICATION_EMAILS")
    engineer_notification_emails: str = Field("", validation_alias="ENGINEER_NOTIFICATION_EMAILS")

    # --- Dashboard ---
    dashboard_access_key: str = Field("", validation_alias="DASHBOARD_ACCESS_KEY")

    # --- API Documentation ---
    # FastAPI's /docs, /redoc and /openapi.json cannot be gated by
    # DASHBOARD_ACCESS_KEY (they are served by FastAPI itself, not our routers)
    # and enumerate every route, including the ingest endpoints. Off by default;
    # turn on for local development only.
    enable_api_docs: bool = Field(False, validation_alias="ENABLE_API_DOCS")

    # --- Email Delivery (ESET Mail worker; see src/services/email_delivery/) ---
    email_delivery_enabled: bool = Field(False, validation_alias="EMAIL_DELIVERY_ENABLED")
    email_provider: str = Field("eset_mail", validation_alias="EMAIL_PROVIDER")
    email_api_url: str = Field("", validation_alias="EMAIL_API_URL")
    email_api_key: str = Field("", validation_alias="EMAIL_API_KEY")
    email_api_secret: str = Field("", validation_alias="EMAIL_API_SECRET")
    # full | signed | api-key-only — must match the worker's SECURITY_MODE
    email_security_mode: str = Field("full", validation_alias="EMAIL_SECURITY_MODE")
    # Default is intentionally higher than the previous 15s window so a slow worker
    # cold-start / SMTP handoff is less likely to trigger an ambiguous retry.
    email_timeout_seconds: int = Field(60, validation_alias="EMAIL_TIMEOUT_SECONDS")
    email_max_attempts: int = Field(3, validation_alias="EMAIL_MAX_ATTEMPTS")
    email_dispatch_interval_seconds: int = Field(60, validation_alias="EMAIL_DISPATCH_INTERVAL_SECONDS")

    # --- Email Sender Routing (mail service multi-provider support) ---
    # The mail service can hold several configured senders (SMTP/Resend/SendGrid/
    # Mailgun/Postmark) and picks one per email. Left blank, it applies its own
    # default/priority order — which is the right choice unless this platform must
    # send from a specific verified address.
    #
    # A sender named here must exist and be active on the mail service, otherwise
    # it answers 400 "Unauthorized Sender/Provider".
    email_sender_email: str = Field("", validation_alias="EMAIL_SENDER_EMAIL")
    email_sender_name: str = Field("", validation_alias="EMAIL_SENDER_NAME")
    email_provider_id: str = Field("", validation_alias="EMAIL_PROVIDER_ID")
    # How the sender choice travels to the mail service:
    #   false (default) - in the signed JSON body (from_email / from_name / provider_id)
    #   true            - as X-Sender-Email / X-Provider-Id headers, which the mail
    #                     service binds into the HMAC canonical string
    # Both are tamper-proof; the body form is the simpler contract.
    email_routing_via_headers: bool = Field(False, validation_alias="EMAIL_ROUTING_VIA_HEADERS")

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
