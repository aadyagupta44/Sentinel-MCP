"""MITRE ATT&CK adapter — local STIX 2.1 Enterprise ATT&CK JSON.

Downloads the STIX bundle from MITRE's GitHub on startup and parses
all technique objects into an in-memory dict keyed by technique ID.
Falls back to a bundled minimal dataset if the download fails.

No API call at lookup time — purely in-memory.
Refreshes weekly via a background task (Phase 7).
"""

import asyncio
import json
from pathlib import Path
from typing import Any

from sentinel.adapters.base import BaseAdapter
from sentinel.config import get_settings

_BUNDLED_PATH = Path(__file__).parent.parent.parent / "data" / "mitre-minimal.json"

# Minimal bundled dataset — enough for tests and quickstart
_MINIMAL_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1059.001": {
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "detection": "Monitor for PowerShell with: -EncodedCommand, -WindowStyle Hidden, -ExecutionPolicy Bypass.",
        "mitigation": "Constrained Language Mode, AMSI, Script Block Logging.",
        "data_sources": ["Command: Command Execution", "Process: Process Creation"],
        "platforms": ["Windows"],
    },
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "detection": "Monitor for impossible travel, new geographies, off-hours access.",
        "mitigation": "MFA, conditional access policies, privileged access workstations.",
        "data_sources": ["Authentication: Authentication Log", "Logon Session: Logon Session Creation"],
        "platforms": ["Windows", "macOS", "Linux", "Cloud"],
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may use repeated login attempts with common passwords.",
        "detection": "Monitor for high-volume failed authentications from a single IP.",
        "mitigation": "Account lockout policy, MFA, login rate limiting.",
        "data_sources": ["Authentication: Authentication Log"],
        "platforms": ["Windows", "macOS", "Linux", "Cloud"],
    },
    "T1003.001": {
        "technique_id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may access credential material stored in LSASS process memory.",
        "detection": "Monitor LSASS access, tools like Mimikatz or ProcDump targeting LSASS.",
        "mitigation": "Credential Guard, LSA Protection, restrict debugging privileges.",
        "data_sources": ["Process: OS API Execution", "Process: Process Access"],
        "platforms": ["Windows"],
    },
    "T1566.001": {
        "technique_id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with malicious attachments.",
        "detection": "Monitor for suspicious email attachments, macro-enabled documents.",
        "mitigation": "Email filtering, user training, disable macros.",
        "data_sources": ["Network Traffic: Network Traffic Content", "File: File Creation"],
        "platforms": ["macOS", "Windows", "Linux"],
    },
    "T1055": {
        "technique_id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade defenses.",
        "detection": "Monitor for unusual process relationships and memory writes.",
        "mitigation": "Privileged account management, endpoint protection.",
        "data_sources": ["Process: OS API Execution", "Process: Process Modification"],
        "platforms": ["Linux", "macOS", "Windows"],
    },
}


class MitreAdapter(BaseAdapter):
    adapter_name = "mitre"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._url = settings.mitre_attack_url
        self._techniques: dict[str, dict[str, Any]] = dict(_MINIMAL_TECHNIQUES)
        self._loaded_full = False
        self._load_lock = asyncio.Lock()

    async def ensure_loaded(self) -> None:
        """Download and parse full ATT&CK bundle on first use."""
        if self._loaded_full:
            return
        async with self._load_lock:
            if not self._loaded_full:
                await self._load_attack_data()

    async def _load_attack_data(self) -> None:
        if self.is_mock:
            self._loaded_full = True
            return

        # Try live download first
        try:
            self._log.info("mitre_downloading", url=self._url)
            resp = await self._retry_request("GET", self._url)
            resp.raise_for_status()
            bundle = resp.json()
            count = self._parse_bundle(bundle)
            self._log.info("mitre_loaded", technique_count=count)
            self._loaded_full = True
            return
        except Exception as exc:
            self._log.warning("mitre_download_failed", error=str(exc))

        # Try bundled file
        if _BUNDLED_PATH.exists():
            try:
                bundle = json.loads(_BUNDLED_PATH.read_text(encoding="utf-8"))
                count = self._parse_bundle(bundle)
                self._log.info("mitre_loaded_from_bundle", technique_count=count)
                self._loaded_full = True
                return
            except Exception as exc:
                self._log.warning("mitre_bundle_parse_failed", error=str(exc))

        # Fall back to minimal hardcoded set
        self._log.warning("mitre_using_minimal_fallback")
        self._loaded_full = True

    def _parse_bundle(self, bundle: dict[str, Any]) -> int:
        """Parse STIX 2.1 bundle, extract attack-pattern objects."""
        count = 0
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            tid = self._extract_technique_id(obj)
            if not tid:
                continue
            self._techniques[tid] = {
                "technique_id": tid,
                "name": obj.get("name", ""),
                "tactic": self._extract_tactics(obj),
                "description": obj.get("description", "")[:2000],
                "detection": self._extract_x_mitre(obj, "detection"),
                "mitigation": "",
                "data_sources": obj.get("x_mitre_data_sources", []),
                "platforms": obj.get("x_mitre_platforms", []),
            }
            count += 1
        return count

    @staticmethod
    def _extract_technique_id(obj: dict[str, Any]) -> str | None:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id", "")
        return None

    @staticmethod
    def _extract_tactics(obj: dict[str, Any]) -> str:
        phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
        return ", ".join(p.replace("-", " ").title() for p in phases)

    @staticmethod
    def _extract_x_mitre(obj: dict[str, Any], field: str) -> str:
        return obj.get(f"x_mitre_{field}", "")

    # ── Lookup ────────────────────────────────────────────────────────────────

    async def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        await self.ensure_loaded()
        tid = technique_id.upper().strip()
        return self._techniques.get(tid)

    def list_technique_ids(self) -> list[str]:
        return sorted(self._techniques.keys())


_adapter: MitreAdapter | None = None


def get_mitre_adapter() -> MitreAdapter:
    global _adapter
    if _adapter is None:
        _adapter = MitreAdapter()
    return _adapter
