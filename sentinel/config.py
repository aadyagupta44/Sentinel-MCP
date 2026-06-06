from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Server ────────────────────────────────────────────────────────────────
    mcp_transport: Literal["stdio", "http"] = "stdio"
    http_host: str = "0.0.0.0"
    http_port: int = 8000
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    environment: Literal["development", "production", "test"] = "development"
    version: str = "1.0.0"

    # ── Analyst identity (stdio transport — trusted local process) ────────────
    analyst_id: str = "analyst@acmecorp.com"
    analyst_role: Literal["analyst", "senior_analyst", "admin"] = "analyst"

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── OPA ───────────────────────────────────────────────────────────────────
    opa_url: str = "http://localhost:8181"
    policy_enforcement: bool = True

    # ── Auth / Keycloak (HTTP transport only) ─────────────────────────────────
    keycloak_url: str = "http://localhost:8080"
    keycloak_realm: str = "sentinel"
    oauth_client_id: str = "claude-desktop"

    # ── OpenSearch ────────────────────────────────────────────────────────────
    opensearch_url: str = "http://localhost:9200"
    opensearch_verify_ssl: bool = False
    opensearch_index_alerts: str = "sentinel-alerts"
    opensearch_index_logs: str = "sentinel-logs-*"

    # ── Wazuh (optional) ──────────────────────────────────────────────────────
    wazuh_enabled: bool = False
    wazuh_url: str = "https://localhost:55000"
    wazuh_api_key: str = ""
    wazuh_verify_ssl: bool = False

    # ── Threat intel — all optional, degrade gracefully if absent ─────────────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    alienvault_otx_api_key: str = ""
    urlscan_api_key: str = ""

    # ── Anthropic (optional narrative generation) ─────────────────────────────
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"
    report_narrative_enabled: bool = False

    # ── OpenCTI (optional) ────────────────────────────────────────────────────
    opencti_enabled: bool = False
    opencti_url: str = "http://localhost:8082"
    opencti_token: str = ""

    # ── Observability ─────────────────────────────────────────────────────────
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "sentinel-mcp"
    otel_enabled: bool = True

    # ── Mock mode ─────────────────────────────────────────────────────────────
    mock_adapters: bool = True

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_enabled: bool = True

    # ── Write-tool confirmation ───────────────────────────────────────────────
    pending_action_ttl_seconds: int = 600

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    mitre_attack_url: str = (
        "https://github.com/mitre-attack/attack-stix-data/raw/master"
        "/enterprise-attack/enterprise-attack.json"
    )
    mitre_refresh_interval_hours: int = 168

    # ── abuse.ch feeds ────────────────────────────────────────────────────────
    abuse_ch_refresh_interval_minutes: int = 60

    # ── Derived properties ────────────────────────────────────────────────────
    @property
    def is_development(self) -> bool:
        return self.environment in ("development", "test")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def has_virustotal(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def has_abuseipdb(self) -> bool:
        return bool(self.abuseipdb_api_key)

    @property
    def has_otx(self) -> bool:
        return bool(self.alienvault_otx_api_key)

    @property
    def has_urlscan(self) -> bool:
        return bool(self.urlscan_api_key)

    @property
    def has_anthropic(self) -> bool:
        return bool(self.anthropic_api_key) and self.report_narrative_enabled


@lru_cache
def get_settings() -> Settings:
    return Settings()
