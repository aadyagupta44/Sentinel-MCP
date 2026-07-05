"""CIRCL Hash Lookup adapter — hash reputation from CIRCL (Luxembourg CERT).

Endpoint: https://hashlookup.circl.lu/lookup/{algo}/{hash}
No API key, no authentication required.
Aggregates: NSRL (benign software), MalwareBazaar, VirusTotal, etc.
Returns: KnownMalicious, KnownBenign, or unknown.

Operated by CIRCL (Computer Incident Response Center Luxembourg).
"""

from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError

_BASE_URL = "https://hashlookup.circl.lu"

_MOCK_DATA: dict[str, dict[str, Any]] = {
    "44d88612fea8a8f36de82e1278abb02f": {
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "KnownMalicious": 1,
        "source": "MalwareBazaar",
        "tags": ["emotet"],
    },
    "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f": {
        "sha256": "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f",
        "KnownMalicious": 1,
        "source": "MalwareBazaar",
    },
}


class CIRCLAdapter(BaseAdapter):
    adapter_name = "circl"

    async def lookup(self, hash_value: str) -> dict[str, Any]:
        if self.is_mock:
            return _MOCK_DATA.get(hash_value.lower(), {"KnownMalicious": 0, "KnownBenign": 0})

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        algo = self._detect_algo(hash_value)
        if not algo:
            return {"error": "unsupported hash length", "hash": hash_value}

        url = f"{_BASE_URL}/lookup/{algo}/{hash_value.lower()}"
        try:
            resp = await self._call("GET", url, span_name="lookup")
            if resp.status_code == 404:
                return {"KnownMalicious": 0, "KnownBenign": 0, "hash": hash_value}
            resp.raise_for_status()
            payload: dict[str, Any] = resp.json()
            return payload
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("circl_lookup_failed", error=str(exc), hash=hash_value[:16])
            return {}

    @staticmethod
    def _detect_algo(hash_value: str) -> str | None:
        length = len(hash_value)
        if length == 32:
            return "md5"
        if length == 40:
            return "sha1"
        if length == 64:
            return "sha256"
        return None


_adapter: CIRCLAdapter | None = None


def get_circl_adapter() -> CIRCLAdapter:
    global _adapter
    if _adapter is None:
        _adapter = CIRCLAdapter()
    return _adapter
