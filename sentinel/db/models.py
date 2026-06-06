import hashlib
import json
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class AuditLog(Base):
    """Hash-chained audit log. Every row's hash covers the previous row's hash,
    making the log tamper-evident: altering any row breaks all subsequent hashes."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    row_hash: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str] = mapped_column(Text, nullable=False)
    trace_id: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    analyst_id: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    input_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    policy_result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    response_code: Mapped[str] = mapped_column(Text, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    metadata_: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", JSONB, nullable=True
    )

    __table_args__ = (
        Index("ix_audit_log_timestamp", "timestamp"),
        Index("ix_audit_log_analyst_id", "analyst_id"),
        Index("ix_audit_log_tool_name", "tool_name"),
        Index("ix_audit_log_trace_id", "trace_id"),
    )

    @staticmethod
    def build_hash_payload(prev_hash: str, data: dict[str, Any]) -> str:
        return prev_hash + json.dumps(data, sort_keys=True, default=str)

    @staticmethod
    def compute_hash(prev_hash: str, data: dict[str, Any]) -> str:
        payload = AuditLog.build_hash_payload(prev_hash, data)
        return hashlib.sha256(payload.encode()).hexdigest()


class PendingAction(Base):
    """Stores write-tool proposals awaiting analyst confirmation.

    First call to a write tool inserts a row here and returns the token.
    Second call must supply the token; server validates it before executing.
    Rows expire after PENDING_ACTION_TTL_SECONDS (default 10 min).
    """

    __tablename__ = "pending_actions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    analyst_id: Mapped[str] = mapped_column(Text, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    proposal: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    executed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("ix_pending_actions_token", "token", unique=True),
        Index("ix_pending_actions_expires_at", "expires_at"),
    )


class ThreatIntelCache(Base):
    """Caches expensive threat intel API responses.

    Keyed on (indicator, source). TTL varies by source — Shodan InternetDB
    results cached 7 days; ip-api results cached 24 hours.
    """

    __tablename__ = "threat_intel_cache"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    indicator: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index(
            "ix_threat_intel_cache_indicator_source",
            "indicator",
            "source",
            unique=True,
        ),
        Index("ix_threat_intel_cache_expires_at", "expires_at"),
    )
