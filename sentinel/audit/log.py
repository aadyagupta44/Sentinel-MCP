"""Hash-chained audit log writer.

Every tool call — allowed or denied — is appended to the audit_log table.
Each row's SHA-256 hash covers the previous row's hash, making the log
tamper-evident: changing any historical row breaks the chain from that
point forward.

Concurrency: a Postgres advisory lock serialises all audit writes across
Gunicorn workers so the chain never forks.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.db.models import AuditLog
from sentinel.db.session import get_session_factory

logger = structlog.get_logger(__name__)

GENESIS_HASH = "0" * 64

# Stable integer key for the Postgres advisory lock.
# Any arbitrary constant — just must be consistent across all processes.
_ADVISORY_LOCK_KEY = 7_391_827


@dataclass
class AuditEntry:
    analyst_id: str
    tool_name: str
    input_summary: dict[str, Any]
    policy_result: dict[str, Any]
    response_code: str
    duration_ms: int
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


async def write_audit_log(entry: AuditEntry) -> None:
    """Append one entry to the audit log inside a serialised transaction."""
    factory = get_session_factory()
    async with factory() as session:
        async with session.begin():
            # Serialise across all workers — released automatically on commit/rollback
            await session.execute(
                text(f"SELECT pg_advisory_xact_lock({_ADVISORY_LOCK_KEY})")
            )

            prev_hash = await _get_last_hash(session)

            data_for_hash = _build_hash_payload(entry, prev_hash)
            row_hash = hashlib.sha256(
                json.dumps(data_for_hash, sort_keys=True, default=str).encode()
            ).hexdigest()

            session.add(
                AuditLog(
                    row_hash=row_hash,
                    prev_hash=prev_hash,
                    trace_id=entry.trace_id,
                    timestamp=entry.timestamp,
                    analyst_id=entry.analyst_id,
                    tool_name=entry.tool_name,
                    input_summary=entry.input_summary,
                    policy_result=entry.policy_result,
                    response_code=entry.response_code,
                    duration_ms=entry.duration_ms,
                    metadata_=entry.metadata,
                )
            )

    logger.info(
        "audit_written",
        tool=entry.tool_name,
        analyst=entry.analyst_id,
        response=entry.response_code,
        duration_ms=entry.duration_ms,
        trace_id=entry.trace_id,
    )


async def verify_chain_integrity(
    session: AsyncSession,
) -> tuple[bool, int, str | None]:
    """Walk the entire audit log and verify the hash chain.

    Returns:
        (is_valid, rows_checked, error_message_or_None)
    """
    result = await session.execute(
        text(
            "SELECT id, row_hash, prev_hash, timestamp, analyst_id, tool_name, "
            "input_summary, policy_result, response_code, duration_ms, trace_id "
            "FROM audit_log ORDER BY id ASC"
        )
    )
    rows = result.fetchall()

    if not rows:
        return True, 0, None

    prev_hash = GENESIS_HASH
    for row in rows:
        ts = row.timestamp
        ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)

        data_for_hash = {
            "prev_hash": prev_hash,
            "timestamp": ts_str,
            "analyst_id": row.analyst_id,
            "tool_name": row.tool_name,
            "input_summary": row.input_summary,
            "policy_result": row.policy_result,
            "response_code": row.response_code,
            "duration_ms": row.duration_ms,
            "trace_id": row.trace_id,
        }
        expected = hashlib.sha256(
            json.dumps(data_for_hash, sort_keys=True, default=str).encode()
        ).hexdigest()

        if expected != row.row_hash:
            return (
                False,
                row.id,
                f"Hash mismatch at row id={row.id}: expected {expected}, got {row.row_hash}",
            )

        prev_hash = row.row_hash

    return True, len(rows), None


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_last_hash(session: AsyncSession) -> str:
    result = await session.execute(
        text("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE")
    )
    row = result.fetchone()
    return row[0] if row else GENESIS_HASH


def _build_hash_payload(entry: AuditEntry, prev_hash: str) -> dict[str, Any]:
    return {
        "prev_hash": prev_hash,
        "timestamp": entry.timestamp.isoformat(),
        "analyst_id": entry.analyst_id,
        "tool_name": entry.tool_name,
        "input_summary": entry.input_summary,
        "policy_result": entry.policy_result,
        "response_code": entry.response_code,
        "duration_ms": entry.duration_ms,
        "trace_id": entry.trace_id,
    }
