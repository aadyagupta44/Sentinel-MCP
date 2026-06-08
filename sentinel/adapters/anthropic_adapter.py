"""Anthropic API adapter — narrative generation for reports.

Optional — only active if ANTHROPIC_API_KEY is set AND
REPORT_NARRATIVE_ENABLED=true.

Used by generate_incident_report and weekly_summary to produce written
narratives from structured data. When disabled, those tools return
structured data only and Claude synthesizes the narrative naturally.

System prompt instructs the model to return strict JSON output.
"""

import json
from typing import Any

import structlog
from pydantic import BaseModel, Field, field_validator

from sentinel.config import get_settings

logger = structlog.get_logger("sentinel.adapters.anthropic")


class IncidentData(BaseModel):
    """Schema for incident narrative generation (lenient for partial data)."""

    alert_id: str | None = Field(default=None, max_length=100)
    severity: str = Field(default="medium", pattern="^(critical|high|medium|low)$")
    rule_name: str | None = Field(default=None, max_length=200)
    description: str = Field(default="", max_length=5000)
    affected_user: str = Field(default="", max_length=200)
    affected_host: str = Field(default="", max_length=200)
    technique_ids: list[str] = Field(default_factory=list, max_items=10)
    confidence: str = Field(default="medium", pattern="^(high|medium|low)$")

    @field_validator("technique_ids")
    @classmethod
    def validate_technique_ids(cls, v: list[str]) -> list[str]:
        for tid in v:
            if not tid or len(tid) > 50:
                raise ValueError(f"Invalid technique ID: {tid}")
        return v


class SummaryData(BaseModel):
    """Schema for weekly summary narrative generation (lenient for partial data)."""

    week_starting: str | None = Field(default=None, description="ISO date, e.g. 2026-06-01")
    total_alerts: int = Field(default=0, ge=0, le=100000)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    unique_users: int = Field(default=0, ge=0, le=10000)
    unique_hosts: int = Field(default=0, ge=0, le=10000)
    top_rules: list[str] = Field(default_factory=list, max_items=10)
    trend: str = Field(default="stable", pattern="^(improving|stable|worsening)$")
    notes: str = Field(default="", max_length=2000)

_REPORT_SYSTEM_PROMPT = """You are a senior SOC analyst writing a professional incident report.
You will receive structured security data as JSON.
Return ONLY a valid JSON object with exactly these keys:
- "executive_summary": string (2-3 sentences for management)
- "attack_narrative": string (detailed technical narrative)
- "recommended_actions": array of strings (prioritised action items)
- "confidence": "high" | "medium" | "low"
Do not include any text outside the JSON object."""

_SUMMARY_SYSTEM_PROMPT = """You are a SOC manager writing a weekly security briefing.
You will receive structured alert statistics as JSON.
Return ONLY a valid JSON object with exactly these keys:
- "headline": string (one-line summary for management)
- "key_findings": array of strings (top 3-5 findings)
- "trend": "improving" | "stable" | "worsening"
- "recommended_focus": string (what the team should prioritise this week)
Do not include any text outside the JSON object."""


class AnthropicAdapter:
    """Not a BaseAdapter — uses the Anthropic SDK, not httpx."""

    def __init__(self) -> None:
        settings = get_settings()
        self._api_key = settings.anthropic_api_key
        self._model = settings.anthropic_model
        self._enabled = settings.has_anthropic
        self._log = logger

    async def generate_incident_narrative(self, incident_data: dict[str, Any]) -> dict[str, Any]:
        if not self._enabled:
            return {
                "narrative_enabled": False,
                "note": "Set REPORT_NARRATIVE_ENABLED=true and ANTHROPIC_API_KEY to enable.",
            }

        # Validate input schema
        try:
            validated = IncidentData(**incident_data)
        except ValueError as e:
            return {
                "error": f"Invalid incident data: {str(e)}",
                "code": "SCHEMA_VALIDATION_ERROR",
            }

        prompt = (
            "Generate an incident report narrative for the following security incident data:\n\n"
            + json.dumps(validated.model_dump(), indent=2, default=str)
        )
        return await self._call(prompt, _REPORT_SYSTEM_PROMPT)

    async def generate_weekly_narrative(self, summary_data: dict[str, Any]) -> dict[str, Any]:
        if not self._enabled:
            return {
                "narrative_enabled": False,
                "note": "Set REPORT_NARRATIVE_ENABLED=true and ANTHROPIC_API_KEY to enable.",
            }

        # Validate input schema
        try:
            validated = SummaryData(**summary_data)
        except ValueError as e:
            return {
                "error": f"Invalid summary data: {str(e)}",
                "code": "SCHEMA_VALIDATION_ERROR",
            }

        prompt = (
            "Generate a weekly security briefing for the following alert statistics:\n\n"
            + json.dumps(validated.model_dump(), indent=2, default=str)
        )
        return await self._call(prompt, _SUMMARY_SYSTEM_PROMPT)

    async def _call(self, prompt: str, system_prompt: str) -> dict[str, Any]:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self._api_key)
        try:
            self._log.info("anthropic_generating", model=self._model)
            message = await client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = message.content[0].text.strip()
            # Parse the JSON response
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            self._log.warning("anthropic_json_parse_failed", error=str(exc))
            return {"error": "Model returned non-JSON response", "code": "PARSE_ERROR"}
        except Exception as exc:
            self._log.warning("anthropic_call_failed", error=str(exc))
            return {"error": str(exc), "code": "ANTHROPIC_ERROR"}


_adapter: AnthropicAdapter | None = None


def get_anthropic_adapter() -> AnthropicAdapter:
    global _adapter
    if _adapter is None:
        _adapter = AnthropicAdapter()
    return _adapter
