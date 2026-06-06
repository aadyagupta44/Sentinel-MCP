"""OpenCTI adapter — structured threat intelligence platform.

Self-hosted, open source (Apache 2.0). Optional — feature-flagged.
Active only if OPENCTI_ENABLED=true and OPENCTI_URL + OPENCTI_TOKEN are set.

Uses OpenCTI's GraphQL API via httpx (avoiding the pycti dependency
which has frequent version conflicts).

Provides: IOC lookup, threat actor profiles, campaign attribution.
"""

from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings

_INDICATOR_QUERY = """
query SearchIndicator($value: String!) {
  indicators(filters: {key: value, values: [$value]}) {
    edges {
      node {
        id
        name
        description
        pattern
        valid_from
        valid_until
        x_opencti_score
        createdBy { name }
        objectLabel { edges { node { value } } }
      }
    }
  }
}
"""


class OpenCTIAdapter(BaseAdapter):
    adapter_name = "opencti"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._url = settings.opencti_url.rstrip("/")
        self._token = settings.opencti_token
        self._enabled = settings.opencti_enabled and bool(self._token)
        self._graphql_url = f"{self._url}/graphql"

    async def search_indicator(self, value: str) -> dict[str, Any]:
        if self.is_mock:
            return {"indicators": [], "source": "opencti_mock"}
        if not self._enabled:
            return {}

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "POST",
                self._graphql_url,
                span_name="search_indicator",
                json={"query": _INDICATOR_QUERY, "variables": {"value": value}},
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            edges = data.get("data", {}).get("indicators", {}).get("edges", [])
            return {
                "indicators": [e["node"] for e in edges],
                "total": len(edges),
            }
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("opencti_search_failed", error=str(exc), value=value[:30])
            return {}


_adapter: OpenCTIAdapter | None = None


def get_opencti_adapter() -> OpenCTIAdapter:
    global _adapter
    if _adapter is None:
        _adapter = OpenCTIAdapter()
    return _adapter
