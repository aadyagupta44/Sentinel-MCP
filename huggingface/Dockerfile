# ─────────────────────────────────────────────────────────────────────────────
# Single-container build of the FULL Sentinel stack for Hugging Face Spaces.
#
# Hugging Face runs one container, so the whole Setup-1 stack lives inside it,
# supervised together:
#   postgres · redis · opa · keycloak · sentinel(app) · caddy
#
# Caddy fronts everything on the one port Spaces exposes (7860). Keycloak is
# self-hosted (real OAuth 2.1 + PKCE), data is ephemeral (resets on restart —
# the realm re-imports each boot). Runs in DEMO_MODE: production-hardened
# (auth/roles/policy/audit all real) with simulated tool data.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-21-jre-headless \
        postgresql postgresql-contrib \
        redis-server \
        supervisor \
        curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv (fast Python dependency install)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# OPA (static policy engine binary)
RUN curl -fsSL -o /usr/local/bin/opa \
        https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static \
    && chmod +x /usr/local/bin/opa

# Caddy (reverse proxy / static server)
RUN curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64" -o /usr/local/bin/caddy \
    && chmod +x /usr/local/bin/caddy

# Keycloak (OAuth / OIDC identity provider)
ENV KC_VERSION=26.0.7
RUN curl -fsSL -o /tmp/kc.tar.gz \
        https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.tar.gz \
    && tar -xzf /tmp/kc.tar.gz -C /opt \
    && mv /opt/keycloak-${KC_VERSION} /opt/keycloak \
    && rm /tmp/kc.tar.gz

# ── Application: cloned from GitHub and built into a venv ─────────────────────
# Override with --build-arg REPO_URL=... / REPO_REF=... if your repo differs.
ARG REPO_URL=https://github.com/aadyagupta44/Sentinel-SOC.git
ARG REPO_REF=main
# Bust the layer cache whenever the repo's HEAD moves, so rebuilds re-clone the
# latest code (otherwise Docker reuses a stale cached clone).
ADD https://api.github.com/repos/aadyagupta44/Sentinel-SOC/commits/main /tmp/repo-head.json
RUN git clone --depth 1 --branch ${REPO_REF} ${REPO_URL} /app
WORKDIR /app
RUN (uv sync --frozen --no-dev --no-editable 2>/dev/null || uv sync --no-dev)
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH="/app" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Keycloak realm (users analyst/senior/admin + roles) imported on every boot
RUN mkdir -p /opt/keycloak/data/import \
    && cp /app/keycloak/realm-export.json /opt/keycloak/data/import/realm-export.json

# Landing page served at /
RUN mkdir -p /srv && cp /app/landing/index.html /srv/index.html

# Container glue (from this huggingface/ directory)
COPY Caddyfile /etc/caddy/Caddyfile
COPY supervisord.conf /etc/supervisor/conf.d/sentinel.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Writable dirs for the postgres data cluster (initialised at runtime)
ENV PGDATA=/var/lib/postgresql/data
RUN mkdir -p ${PGDATA} /var/run/postgresql \
    && chown -R postgres:postgres ${PGDATA} /var/run/postgresql

# Hugging Face Spaces expose port 7860
EXPOSE 7860
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
