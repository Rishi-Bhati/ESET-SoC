import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    # --- AI ---
    gemini_api_key: str = Field(..., validation_alias="GEMINI_API_KEY")

    # --- Webhook Auth ---
    eset_webhook_auth_token: str = Field(..., validation_alias="ESET_WEBHOOK_AUTH_TOKEN")

    # --- App ---
    app_host: str = Field("0.0.0.0", validation_alias="APP_HOST")
    app_port: int = Field(8000, validation_alias="APP_PORT")
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")
    output_dir: str = Field("output/alerts", validation_alias="OUTPUT_DIR")

    # --- Syslog Server ---
    syslog_host: str = Field("0.0.0.0", validation_alias="SYSLOG_HOST")
    syslog_udp_port: int = Field(514, validation_alias="SYSLOG_UDP_PORT")
    syslog_tcp_port: int = Field(601, validation_alias="SYSLOG_TCP_PORT")

    # --- Database ---
    sqlite_db_path: str = Field("data/soc_lite.db", validation_alias="SQLITE_DB_PATH")

    # --- Deduplication ---
    dedup_ttl_seconds: int = Field(3600, validation_alias="DEDUP_TTL_SECONDS")

    # --- Pipeline Limits ---
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
