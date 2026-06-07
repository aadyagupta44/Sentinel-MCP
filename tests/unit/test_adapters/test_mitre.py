"""MITRE ATT&CK adapter tests — respx-mocked, no real network.

The adapter is in-memory: lookups never hit the network, only the one-shot
``_load_attack_data`` does. Covers mock-mode early returns, live STIX download +
full ``_parse_bundle`` exercise, bundled-file fallback, invalid-bundle fallback,
and the no-bundle minimal fallback.
"""

import json

from httpx import ConnectError, Response

from sentinel.adapters.mitre import MitreAdapter, get_mitre_adapter

STIX_URL = (
    "https://github.com/mitre-attack/attack-stix-data/raw/master"
    "/enterprise-attack/enterprise-attack.json"
)


def _bundle(extra_objects=None):
    """A STIX bundle exercising every _parse_bundle branch."""
    objects = [
        # type != attack-pattern → skipped
        {"type": "x-mitre-tactic", "name": "ignore me"},
        # attack-pattern WITHOUT mitre-attack reference → _extract_technique_id None → skipped
        {
            "type": "attack-pattern",
            "name": "No ref",
            "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"}],
        },
        # valid attack-pattern → fully parsed
        {
            "type": "attack-pattern",
            "name": "Drive-by Compromise",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}],
            "kill_chain_phases": [{"phase_name": "initial-access"}],
            "x_mitre_detection": "Monitor browser activity.",
            "x_mitre_data_sources": ["Network Traffic: Network Traffic Content"],
            "x_mitre_platforms": ["Windows", "Linux"],
            "description": "x" * 3000,  # long → truncated to 2000
        },
    ]
    if extra_objects:
        objects.extend(extra_objects)
    return {"type": "bundle", "objects": objects}


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestMitreMockMode:
    async def test_get_technique_returns_minimal(self):
        adapter = MitreAdapter()
        result = await adapter.get_technique("T1059.001")
        assert result is not None
        assert result["technique_id"] == "T1059.001"
        assert result["tactic"] == "Execution"
        await adapter.close()

    async def test_get_technique_normalizes_input(self):
        adapter = MitreAdapter()
        result = await adapter.get_technique("  t1059.001  ")
        assert result is not None
        assert result["technique_id"] == "T1059.001"
        await adapter.close()

    async def test_get_technique_unknown_returns_none(self):
        adapter = MitreAdapter()
        assert await adapter.get_technique("T9999") is None
        await adapter.close()

    async def test_list_technique_ids_sorted(self):
        adapter = MitreAdapter()
        ids = adapter.list_technique_ids()
        assert ids == sorted(ids)
        assert "T1078" in ids
        assert "T1059.001" in ids
        await adapter.close()

    async def test_ensure_loaded_idempotent(self):
        adapter = MitreAdapter()
        await adapter.ensure_loaded()
        assert adapter._loaded_full is True
        # Second call hits the early-return path.
        await adapter.ensure_loaded()
        assert adapter._loaded_full is True
        await adapter.close()


# ── Live HTTP path: download success → full _parse_bundle ─────────────────────


class TestMitreLiveDownload:
    async def test_download_success_parses_bundle(self, respx_mock, live_mode):
        respx_mock.get(STIX_URL).mock(return_value=Response(200, json=_bundle()))
        adapter = MitreAdapter()
        result = await adapter.get_technique("T1234")
        assert result is not None
        assert result["name"] == "Drive-by Compromise"
        assert result["tactic"] == "Initial Access"
        assert result["detection"] == "Monitor browser activity."
        assert result["data_sources"] == ["Network Traffic: Network Traffic Content"]
        assert result["platforms"] == ["Windows", "Linux"]
        assert len(result["description"]) == 2000  # truncated
        # the un-referenced attack-pattern was skipped
        assert await adapter.get_technique("CAPEC-1") is None
        await adapter.close()


# ── Live HTTP path: download fails → bundled file used ────────────────────────


class TestMitreBundledFallback:
    async def test_bundled_file_used_when_download_fails(
        self, respx_mock, live_mode, monkeypatch, tmp_path
    ):
        bundled = tmp_path / "mitre-minimal.json"
        bundled.write_text(json.dumps(_bundle()), encoding="utf-8")
        monkeypatch.setattr("sentinel.adapters.mitre._BUNDLED_PATH", bundled)

        respx_mock.get(STIX_URL).mock(side_effect=ConnectError("boom"))
        adapter = MitreAdapter()
        result = await adapter.get_technique("T1234")
        assert result is not None
        assert result["name"] == "Drive-by Compromise"
        assert adapter._loaded_full is True
        await adapter.close()

    async def test_invalid_bundle_falls_through_to_minimal(
        self, respx_mock, live_mode, monkeypatch, tmp_path
    ):
        bad = tmp_path / "mitre-minimal.json"
        bad.write_text("not json{", encoding="utf-8")
        monkeypatch.setattr("sentinel.adapters.mitre._BUNDLED_PATH", bad)

        respx_mock.get(STIX_URL).mock(side_effect=ConnectError("boom"))
        adapter = MitreAdapter()
        # bundled parse raises → minimal fallback; T1234 absent, minimal still present
        assert await adapter.get_technique("T1234") is None
        assert await adapter.get_technique("T1078") is not None
        assert adapter._loaded_full is True
        await adapter.close()

    async def test_no_bundle_file_falls_through_to_minimal(
        self, respx_mock, live_mode, monkeypatch, tmp_path
    ):
        missing = tmp_path / "does-not-exist.json"
        monkeypatch.setattr("sentinel.adapters.mitre._BUNDLED_PATH", missing)

        respx_mock.get(STIX_URL).mock(side_effect=ConnectError("boom"))
        adapter = MitreAdapter()
        assert await adapter.get_technique("T1234") is None
        assert await adapter.get_technique("T1078") is not None
        assert adapter._loaded_full is True
        await adapter.close()


# ── Singleton accessor ────────────────────────────────────────────────────────


def test_get_mitre_adapter_is_singleton():
    assert get_mitre_adapter() is get_mitre_adapter()
