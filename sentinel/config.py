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
    # Public origin the server is reachable at (e.g. https://user-space.hf.space).
    # Behind a reverse proxy the incoming Host is rewritten (Caddy forces the /mcp
    # Host to localhost), so absolute discovery URLs must come from here, not the
    # request. Exported as PUBLIC_URL by the demo's entrypoint. Empty → derive a
    # best-effort local URL from http_host/http_port.
    public_url: str = ""
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
    oauth_client_secret: str = ""  # empty for public PKCE clients
    oauth_redirect_uri: str = "http://localhost:8000/auth/callback"
    oauth_audience: str = ""  # if set, JWT `aud` is verified against it
    oauth_default_scopes: str = "openid profile soc:read soc:write"

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

    # ── Perimeter firewall (optional) ─────────────────────────────────────────
    # When disabled, block_ip still persists to the durable Postgres block list
    # but performs no external push. When enabled, blocks are additionally
    # pushed to the firewall's REST API.
    firewall_enabled: bool = False
    firewall_url: str = "https://localhost:8443"
    firewall_api_key: str = ""
    firewall_verify_ssl: bool = True

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

    # ── Demo mode ─────────────────────────────────────────────────────────────
    # A production-hardened public showcase: auth, roles, policy, rate limiting
    # and the audit chain all run for real, but adapters return simulated data
    # (MOCK_ADAPTERS=true) so no real credentials or security telemetry are
    # exposed. This is the ONLY circumstance under which production tolerates
    # mock adapters — see validate_runtime().
    demo_mode: bool = False

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

    # ── Public origin / resource discovery (RFC 9728) ─────────────────────────
    @property
    def public_base_url(self) -> str:
        """The externally reachable origin, without a trailing slash."""
        if self.public_url:
            return self.public_url.rstrip("/")
        host = "localhost" if self.http_host in ("0.0.0.0", "127.0.0.1") else self.http_host
        return f"http://{host}:{self.http_port}"

    @property
    def mcp_resource_url(self) -> str:
        """The OAuth-protected resource identifier — the MCP endpoint itself."""
        return f"{self.public_base_url}/mcp"

    @property
    def protected_resource_metadata_url(self) -> str:
        """RFC 9728 metadata URL advertised in the WWW-Authenticate challenge."""
        return f"{self.public_base_url}/.well-known/oauth-protected-resource/mcp"

    # ── OIDC / Keycloak endpoints ─────────────────────────────────────────────
    @property
    def keycloak_realm_url(self) -> str:
        return f"{self.keycloak_url.rstrip('/')}/realms/{self.keycloak_realm}"

    @property
    def oidc_issuer(self) -> str:
        return self.keycloak_realm_url

    @property
    def oidc_authorize_endpoint(self) -> str:
        return f"{self.keycloak_realm_url}/protocol/openid-connect/auth"

    @property
    def oidc_token_endpoint(self) -> str:
        return f"{self.keycloak_realm_url}/protocol/openid-connect/token"

    @property
    def oidc_jwks_uri(self) -> str:
        return f"{self.keycloak_realm_url}/protocol/openid-connect/certs"

    @property
    def oidc_registration_endpoint(self) -> str:
        """Keycloak's OIDC Dynamic Client Registration endpoint (RFC 7591).

        MCP clients like Claude that don't have a pre-provisioned client_id use
        this to register themselves on the fly. Anonymous registration is enabled
        on the demo realm (see keycloak/realm-export.json Trusted Hosts policy).
        """
        return f"{self.keycloak_realm_url}/clients-registrations/openid-connect"

    # ── Startup validation ────────────────────────────────────────────────────
    def validate_runtime(self) -> list[str]:
        """Return fatal misconfigurations for the current environment.

        Production must not run with authorization disabled, mock adapters on, or
        placeholder secrets — surfacing these at boot instead of at first use.
        """
        problems: list[str] = []
        if self.is_production:
            if not self.policy_enforcement:
                problems.append("POLICY_ENFORCEMENT must be true in production")
            # Real production must never be mock. The sole exception is the
            # public demo, which opts in explicitly via DEMO_MODE=true and keeps
            # every other production guarantee (auth, policy, audit) intact.
            if self.mock_adapters and not self.demo_mode:
                problems.append("MOCK_ADAPTERS must be false in production")
            # The single-container demo legitimately co-locates Postgres/Keycloak
            # on localhost; real production must point at managed services, so
            # these two checks are relaxed only under the explicit demo opt-in.
            if "localhost" in self.database_url and not self.demo_mode:
                problems.append("DATABASE_URL still points at localhost in production")
            if (
                self.mcp_transport == "http"
                and "localhost" in self.keycloak_url
                and not self.demo_mode
            ):
                problems.append("KEYCLOAK_URL still points at localhost in production HTTP mode")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
