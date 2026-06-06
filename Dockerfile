# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy dependency files first (layer cache)
COPY pyproject.toml ./
COPY sentinel/__init__.py ./sentinel/

# Install production dependencies only
RUN uv sync --frozen --no-dev --no-editable 2>/dev/null || uv sync --no-dev

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.13-slim AS runtime

WORKDIR /app

# Non-root user for security
RUN groupadd --system sentinel && useradd --system --gid sentinel sentinel

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application source
COPY sentinel/ ./sentinel/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY policies/ ./policies/

# Bundled MITRE ATT&CK snapshot (downloaded separately, see data/README.md)
COPY data/ ./data/

# Runtime environment
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["python", "-m", "sentinel.main"]
