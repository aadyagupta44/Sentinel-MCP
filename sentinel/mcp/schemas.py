"""Shared Pydantic models for tool inputs and outputs.

These are used both for MCP schema generation and for internal validation.
Every tool's input and output is typed — no raw dicts cross the tool boundary.
"""

from typing import Any, Literal
from pydantic import BaseModel, Field


# ── Error models ──────────────────────────────────────────────────────────────

class ToolError(BaseModel):
    error: str
    code: str
    details: dict[str, Any] = Field(default_factory=dict)


class PolicyDenied(BaseModel):
    error: str = "Access denied by policy"
    code: str = "POLICY_DENIED"
    tool: str
    reason: str


class RateLimitExceeded(BaseModel):
    error: str = "Rate limit exceeded"
    code: str = "RATE_LIMIT_EXCEEDED"
    tool: str
    retry_after_seconds: int = 60


class CircuitOpen(BaseModel):
    error: str = "Service temporarily unavailable"
    code: str = "CIRCUIT_OPEN"
    service: str


# ── Write-tool confirmation models ────────────────────────────────────────────

class ProposedAction(BaseModel):
    """Returned by write tools when confirmed=False (first call).

    The analyst reviews this proposal, then calls the tool again with
    confirmed=True and the confirmation_token to execute.
    """

    action_type: str = Field(description="Type of action (isolate_device, disable_user, etc.)")
    description: str = Field(description="Human-readable description of what will happen")
    target: str = Field(description="The resource that will be affected")
    parameters: dict[str, Any] = Field(description="Parameters that will be used for execution")
    warning: str = Field(description="Important warnings the analyst should read before confirming")
    confirmation_token: str = Field(description="Token required for the confirmation call")
    expires_at: str = Field(description="ISO-8601 timestamp when this token expires")
    instructions: str = Field(
        default=(
            "Review the proposed action above. "
            "Call this tool again with confirmed=True and the confirmation_token to execute. "
            "The token expires in 10 minutes."
        )
    )


class ConfirmedAction(BaseModel):
    """Returned after a write tool is successfully executed."""

    action_type: str
    target: str
    executed_at: str
    analyst_id: str
    trace_id: str
    result: dict[str, Any]


# ── Enrichment verdict ────────────────────────────────────────────────────────

class EnrichmentVerdict(BaseModel):
    verdict: Literal["malicious", "suspicious", "clean", "unknown"]
    confidence: float = Field(ge=0.0, le=1.0)
    sources_checked: list[str]
    sources_hit: list[str]


# ── Common output models ──────────────────────────────────────────────────────

class AlertSummary(BaseModel):
    alert_id: str
    severity: str
    rule_name: str
    affected_host: str | None
    affected_user: str | None
    timestamp: str
    status: str
    raw_log_references: list[str] = Field(default_factory=list)


class LoginEvent(BaseModel):
    timestamp: str
    ip_address: str
    country: str
    device: str
    success: bool
    mfa_method: str | None
