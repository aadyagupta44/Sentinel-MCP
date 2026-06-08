# Contributing to Sentinel-mcp

Welcome! Sentinel-mcp is an open-source SOC MCP Server. We welcome contributions from the security community.

## Before You Start

1. **Read the threat model** in [SECURITY.md](SECURITY.md) to understand what's production-ready vs. what's hardening
2. **Check the roadmap** in [docs/phases/](docs/phases/) to see what phases are active
3. **Review [CLAUDE.md](CLAUDE.md)** for architecture overview and tech stack

## How to Contribute

### Report a Bug
1. Search existing [GitHub Issues](https://github.com/aadyagupta44/Sentinel-SOC/issues) — don't duplicate
2. If not reported, open a new issue with:
   - Title: brief summary (e.g., "enrich_ioc fails on IPv6 addresses")
   - Description: what happened, what should happen, steps to reproduce
   - Environment: Python version, OS, uv version
   - Logs: any error messages (sanitize API keys)

### Request a Feature
1. Check the roadmap (Phase 8+ in docs/phases/)
2. Open a GitHub Issue with:
   - Title: feature name (e.g., "Add Splunk adapter")
   - Description: what problem it solves, how you'd use it, why it matters for SOC ops
   - Acceptance criteria: how you'd know it's done

### Submit Code
1. **Fork** the repo and create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Set up development environment:**
   ```bash
   # Clone your fork
   git clone https://github.com/YOUR_USERNAME/Sentinel-SOC.git
   cd Sentinel-SOC

   # Install dependencies
   python -m uv sync --group dev

   # Verify tests pass
   pytest tests/ -v --cov=sentinel
   ```

3. **Make your changes:**
   - Follow the [code style](#code-style) below
   - Add tests for new code (target 80%+ coverage)
   - Update docs if needed (README, CLAUDE.md, SECURITY.md)

4. **Test your changes:**
   ```bash
   # Unit tests
   pytest tests/unit/ -xvs

   # Integration tests (optional, requires Docker)
   docker-compose up -d
   pytest tests/integration/ -xvs

   # Code quality
   ruff check sentinel/
   mypy sentinel/ --ignore-missing-imports
   black --check sentinel/
   ```

5. **Commit and push:**
   ```bash
   git add -A
   git commit -m "feat: add support for X

   - Implement new adapter for X service
   - Add 12 unit tests (coverage: 95%)
   - Update README with example

   Fixes #123"
   
   git push origin feature/my-feature
   ```

6. **Open a Pull Request:**
   - Title: same as commit message
   - Description: explain the change, reference any issues, mention testing
   - Link to any related discussions

7. **Address review feedback** — maintainers will request changes if needed

---

## Code Style

### Python
- **Format:** Use `black` (auto-format on save)
- **Lint:** Use `ruff check` (fix: `ruff check --fix`)
- **Types:** Use type hints on all function signatures
  ```python
  # Good
  async def get_alert(alert_id: str) -> dict[str, Any] | None:
      ...

  # Bad
  async def get_alert(alert_id):
      ...
  ```

- **Logging:** Use `structlog`, not print statements
  ```python
  # Good
  logger.info("alert_retrieved", alert_id=alert_id, severity=alert["severity"])

  # Bad
  print(f"Alert {alert_id} retrieved")
  ```

- **Naming:** Follow PEP 8
  - Functions/variables: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_SNAKE_CASE`
  - Private: prefix with `_`

- **Imports:** Sort with isort (auto-fixed by ruff)
  ```python
  # stdlib
  import json
  from datetime import UTC, datetime

  # third-party
  import structlog
  from sqlalchemy import select

  # local
  from sentinel.config import get_settings
  from sentinel.db.models import AuditLog
  ```

### Tests
- **Framework:** pytest
- **Mocking:** respx for HTTP, unittest.mock for config
- **Coverage:** Aim for 80%+ on any new code
  ```python
  # Good: test happy path, errors, edge cases
  async def test_get_alert_success(respx_mock):
      respx_mock.get("https://opensearch/...").mock(return_value=Response(200, json={...}))
      result = await get_alert("ALT-001")
      assert result["id"] == "ALT-001"

  async def test_get_alert_not_found(respx_mock):
      respx_mock.get("https://opensearch/...").mock(return_value=Response(404))
      result = await get_alert("NONEXISTENT")
      assert result is None

  async def test_get_alert_timeout(respx_mock):
      respx_mock.get("https://opensearch/...").mock(side_effect=TimeoutError)
      with pytest.raises(CircuitOpenError):
          await get_alert("ALT-001")
  ```

### Documentation
- **READMEs:** Markdown, clear sections, code examples
- **Docstrings:** One-line for simple functions, multi-line for complex logic
  ```python
  # Good: explains WHY not WHAT
  async def create_proposal(...) -> dict:
      """Create a write-tool confirmation proposal with 10-min TTL token."""

  # Bad: just restates the code
  def create_proposal(...) -> dict:
      """Create a proposal and return a dict."""
  ```

---

## Adding a New Adapter

If you're adding a new external adapter (e.g., for Splunk, Datadog, etc.):

1. **Create the adapter** at `sentinel/adapters/my_adapter.py`:
   ```python
   from sentinel.adapters.base import BaseAdapter, CircuitOpenError
   from sentinel.config import get_settings

   class MyAdapter(BaseAdapter):
       adapter_name = "my_adapter"

       async def lookup(self, indicator: str) -> dict[str, Any]:
           if self.is_mock:
               return {"result": "mock"}
           if self._breaker.is_open():
               raise CircuitOpenError(self.adapter_name)
           
           try:
               resp = await self._call("GET", f"https://api.example.com/lookup/{indicator}")
               resp.raise_for_status()
               return resp.json()
           except CircuitOpenError:
               raise
           except Exception as exc:
               await self._breaker.record_failure()
               self._log.warning("lookup_failed", error=str(exc))
               return {}

   _adapter: MyAdapter | None = None

   def get_my_adapter() -> MyAdapter:
       global _adapter
       if _adapter is None:
           _adapter = MyAdapter()
       return _adapter
   ```

2. **Add config in config.py:**
   ```python
   MY_ADAPTER_ENABLED: bool = Field(default=False, alias="MY_ADAPTER_ENABLED")
   MY_ADAPTER_API_KEY: str = Field(default="", alias="MY_ADAPTER_API_KEY")
   ```

3. **Write unit tests** in `tests/unit/test_adapters/test_my_adapter.py`:
   - Happy path (successful lookup)
   - Error handling (404, 500, timeout)
   - Circuit breaker (mock mode, failure state)
   - Input validation

4. **Update README.md:**
   - Add to adapter list
   - Document required config
   - Link to adapter docs

5. **Update CLAUDE.md** if it's a major feature

---

## Adding a New Tool

If you're adding a new MCP tool (e.g., "threat_hunt_advanced"):

1. **Add to appropriate tool module** (`sentinel/tools/alerts.py`, etc.):
   ```python
   @mcp.tool()
   async def threat_hunt_advanced(pattern: str, time_window_days: int = 7) -> list[dict]:
       """Search for patterns across endpoint and network logs.
       
       Args:
           pattern: regex pattern to search for
           time_window_days: lookback window in days
       """
       # Implementation
       return results
   ```

2. **Add input validation** in `sentinel/mcp/schemas.py`:
   ```python
   class ThreatHuntAdvancedInput(BaseModel):
       pattern: str = Field(..., min_length=1, max_length=500)
       time_window_days: int = Field(default=7, ge=1, le=365)
   ```

3. **Write tests** in `tests/unit/test_tools/`:
   - Valid inputs (returns results)
   - Invalid inputs (raises validation error)
   - Edge cases (empty results, timeout, policy denial)

4. **Document in CLAUDE.md** and README

---

## Review Process

1. **Automated checks:**
   - GitHub Actions runs: ruff, mypy, pytest, coverage
   - Must pass before human review

2. **Human review:**
   - Security reviewer: checks for injection, auth, data leakage
   - Architecture reviewer: checks design, integration, breaking changes
   - Code reviewer: checks style, tests, docs

3. **Approval & merge:**
   - At least 2 approvals required
   - Approved PRs are merged to main
   - Release notes auto-generated from commits

---

## Development Workflow

### Branches
- `main` — stable release branch (v1.0.0+)
- `develop` — integration branch for Phase 9+ work
- `feature/*` — individual features (fork from develop)
- `bugfix/*` — bug fixes (fork from main, cherry-picked to develop)
- `release/*` — release candidates (v1.x.0)

### CI/CD Pipeline
```
Push to feature/X
  ↓
GitHub Actions (ruff, mypy, pytest, coverage)
  ↓
Open PR to develop
  ↓
Automated checks pass
  ↓
Request 2 human reviews
  ↓
Approve & merge to develop
  ↓
Phase complete → merge to main
  ↓
Tag v1.x.0 → PyPI, Docker Hub, Marketplace
```

---

## Common Tasks

### Run full test suite
```bash
pytest tests/ -v --cov=sentinel --cov-report=html
```

### Format and lint
```bash
black sentinel/ tests/
ruff check sentinel/ --fix
mypy sentinel/
```

### Build Docker image for testing
```bash
docker build -t sentinel-mcp:dev .
docker run --rm -it sentinel-mcp:dev
```

### Start local services
```bash
docker-compose up -d
# Postgres: localhost:5432
# Redis: localhost:6379
# OpenSearch: localhost:9200
# Keycloak: localhost:8080
```

### Clean up
```bash
docker-compose down -v
rm -rf htmlcov .pytest_cache __pycache__
```

---

## Getting Help

- **Questions about architecture?** → [CLAUDE.md](CLAUDE.md)
- **Questions about security?** → [SECURITY.md](SECURITY.md)
- **Questions about phases?** → [docs/phases/](docs/phases/)
- **Need to discuss before coding?** → Open a GitHub Discussion

---

## Code of Conduct

We are committed to providing a welcoming and inspiring community. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

All contributions are licensed under the MIT License. By submitting a PR, you agree to license your work under this license.

---

**Thank you for contributing to Sentinel-mcp!** 🙏
