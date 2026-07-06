#!/usr/bin/env bash
# One-time init, then hand off to supervisord which runs every service.
set -euo pipefail

PGBIN="$(ls -d /usr/lib/postgresql/*/bin | head -n1)"
export PGDATA="${PGDATA:-/var/lib/postgresql/data}"

# Hugging Face injects SPACE_HOST (e.g. user-space.hf.space). Fall back to
# localhost for local `docker run` testing.
export SPACE_HOST="${SPACE_HOST:-localhost:7860}"
export PUBLIC_URL="https://${SPACE_HOST}"
echo "[entrypoint] public url: ${PUBLIC_URL}"

# ── Initialise the Postgres cluster once ─────────────────────────────────────
if [ ! -s "${PGDATA}/PG_VERSION" ]; then
  echo "[entrypoint] initialising postgres cluster"
  chown -R postgres:postgres "${PGDATA}"
  su postgres -c "${PGBIN}/initdb -D ${PGDATA} --auth-local=trust --auth-host=md5"

  # start briefly to create the role + databases
  su postgres -c "${PGBIN}/pg_ctl -D ${PGDATA} -o '-c listen_addresses=127.0.0.1 -p 5432' -w start"
  su postgres -c "psql -v ON_ERROR_STOP=1 --username postgres <<'SQL'
CREATE USER sentinel WITH PASSWORD 'sentinel' SUPERUSER;
CREATE DATABASE sentinel OWNER sentinel;
SQL"
  su postgres -c "${PGBIN}/pg_ctl -D ${PGDATA} -w stop"
fi

# Make the discovered PG binary path available to supervisord's postgres program.
export PGBIN
echo "[entrypoint] postgres binaries: ${PGBIN}"

# ── Environment for the supervised services (children inherit this) ──────────
# Keycloak — self-hosted OAuth 2.1 provider, issuer pinned to the public URL.
export KC_BOOTSTRAP_ADMIN_USERNAME="${KC_ADMIN_USER:-admin}"
export KC_BOOTSTRAP_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-admin}"
export KC_HOSTNAME="${PUBLIC_URL}"
export KC_HOSTNAME_STRICT="false"
export KC_HTTP_ENABLED="true"
export KC_PROXY_HEADERS="xforwarded"

# Sentinel app — production-hardened demo (auth/roles/policy/audit real, data mocked)
export MCP_TRANSPORT="http"
export HTTP_HOST="127.0.0.1"
export HTTP_PORT="8000"
# Behind Caddy — the public Host/Origin isn't localhost; trust the proxy.
export MCP_TRUST_PROXY="true"
export ENVIRONMENT="production"
export DEMO_MODE="true"
export MOCK_ADAPTERS="true"
export POLICY_ENFORCEMENT="true"
export RATE_LIMIT_ENABLED="true"
export DATABASE_URL="postgresql+asyncpg://sentinel:sentinel@127.0.0.1:5432/sentinel"
export REDIS_URL="redis://127.0.0.1:6379/0"
export OPA_URL="http://127.0.0.1:8181"
export KEYCLOAK_URL="${PUBLIC_URL}"
export KEYCLOAK_REALM="sentinel"
export OAUTH_CLIENT_ID="claude-desktop"
export OAUTH_REDIRECT_URI="${PUBLIC_URL}/auth/callback"
# The demo IdP only issues standard OIDC scopes — advertise just those so the
# client never requests custom scopes Keycloak doesn't have. Authorization is
# by role (see authz.py demo_mode branch).
export OAUTH_DEFAULT_SCOPES="openid profile"
export OTEL_ENABLED="false"
export LOG_LEVEL="INFO"

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/sentinel.conf
