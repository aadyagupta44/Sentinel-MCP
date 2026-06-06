"""Anthropic narrative adapter tests — SDK client mocked, no real API calls.

AnthropicAdapter is not a BaseAdapter (uses the Anthropic SDK, not httpx), so
there is no circuit breaker. Contract: (1) disabled returns a clear notice,
(2) enabled parses JSON output, (3) bad/failed responses degrade gracefully.
"""

import types

import anthropic

from sentinel.adapters.anthropic_adapter import AnthropicAdapter, get_anthropic_adapter


def _fake_client(text=None, exc=None):
    """Build a fake anthropic.AsyncAnthropic returning `text` or raising `exc`."""

    class _Messages:
        async def create(self, **_kwargs):
            if exc is not None:
                raise exc
            return types.SimpleNamespace(content=[types.SimpleNamespace(text=text)])

    class _Client:
        def __init__(self, *_a, **_k):
            self.messages = _Messages()

    return _Client


def _enable(adapter):
    adapter._enabled = True
    adapter._api_key = "test-key"
    adapter._model = "claude-sonnet-4-6"


# ── Disabled (default) ────────────────────────────────────────────────────────


class TestAnthropicDisabled:
    async def test_incident_narrative_disabled(self):
        adapter = AnthropicAdapter()
        result = await adapter.generate_incident_narrative({"alert": "x"})
        assert result["narrative_enabled"] is False

    async def test_weekly_narrative_disabled(self):
        adapter = AnthropicAdapter()
        result = await adapter.generate_weekly_narrative({"total": 1})
        assert result["narrative_enabled"] is False


# ── Enabled (SDK mocked) ──────────────────────────────────────────────────────


class TestAnthropicEnabled:
    async def test_incident_narrative_success(self, monkeypatch):
        payload = (
            '{"executive_summary": "s", "attack_narrative": "n", '
            '"recommended_actions": ["a"], "confidence": "high"}'
        )
        monkeypatch.setattr(anthropic, "AsyncAnthropic", _fake_client(text=payload))
        adapter = AnthropicAdapter()
        _enable(adapter)
        result = await adapter.generate_incident_narrative({"alert": "x"})
        assert result["confidence"] == "high"
        assert result["recommended_actions"] == ["a"]

    async def test_weekly_narrative_success_strips_code_fence(self, monkeypatch):
        payload = (
            '```json\n{"headline": "h", "key_findings": ["k"], '
            '"trend": "stable", "recommended_focus": "f"}\n```'
        )
        monkeypatch.setattr(anthropic, "AsyncAnthropic", _fake_client(text=payload))
        adapter = AnthropicAdapter()
        _enable(adapter)
        result = await adapter.generate_weekly_narrative({"total": 2})
        assert result["trend"] == "stable"

    async def test_bare_code_fence_without_json_label(self, monkeypatch):
        payload = (
            '```\n{"headline": "h", "key_findings": [], '
            '"trend": "improving", "recommended_focus": "f"}\n```'
        )
        monkeypatch.setattr(anthropic, "AsyncAnthropic", _fake_client(text=payload))
        adapter = AnthropicAdapter()
        _enable(adapter)
        result = await adapter.generate_weekly_narrative({"total": 2})
        assert result["trend"] == "improving"

    async def test_non_json_returns_parse_error(self, monkeypatch):
        monkeypatch.setattr(anthropic, "AsyncAnthropic", _fake_client(text="not json at all"))
        adapter = AnthropicAdapter()
        _enable(adapter)
        result = await adapter.generate_incident_narrative({"alert": "x"})
        assert result["code"] == "PARSE_ERROR"

    async def test_sdk_exception_returns_error(self, monkeypatch):
        monkeypatch.setattr(anthropic, "AsyncAnthropic", _fake_client(exc=RuntimeError("api down")))
        adapter = AnthropicAdapter()
        _enable(adapter)
        result = await adapter.generate_incident_narrative({"alert": "x"})
        assert result["code"] == "ANTHROPIC_ERROR"


def test_get_anthropic_adapter_is_singleton():
    assert get_anthropic_adapter() is get_anthropic_adapter()
