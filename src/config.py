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

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
