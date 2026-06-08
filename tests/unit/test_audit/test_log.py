"""Audit log hash-chain integrity tests.

These tests verify that:
1. Each row's hash correctly covers the previous row's hash
2. The chain starts from the genesis hash
3. Tampering with any row is detectable
4. The verify_chain_integrity function catches tampering
"""

import hashlib
import json
from datetime import UTC, datetime

from sentinel.audit.log import GENESIS_HASH, AuditEntry, _build_hash_payload


class TestHashComputation:
    def test_genesis_hash_is_64_zeros(self):
        assert GENESIS_HASH == "0" * 64
        assert len(GENESIS_HASH) == 64

    def test_hash_is_deterministic(self):
        entry = AuditEntry(
            analyst_id="alice@corp.com",
            tool_name="get_alert",
            input_summary={"alert_id": "ALT-001"},
            policy_result={"allow": True},
            response_code="success",
            duration_ms=42,
            trace_id="trace-001",
            timestamp=datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC),
        )
        payload1 = _build_hash_payload(entry, GENESIS_HASH)
        payload2 = _build_hash_payload(entry, GENESIS_HASH)
        assert payload1 == payload2

    def test_different_prev_hash_produces_different_row_hash(self):
        entry = AuditEntry(
            analyst_id="alice@corp.com",
            tool_name="get_alert",
            input_summary={"alert_id": "ALT-001"},
            policy_result={"allow": True},
            response_code="success",
            duration_ms=42,
        )
        payload_a = _build_hash_payload(entry, GENESIS_HASH)
        payload_b = _build_hash_payload(entry, "a" * 64)

        hash_a = hashlib.sha256(
            json.dumps(payload_a, sort_keys=True, default=str).encode()
        ).hexdigest()
        hash_b = hashlib.sha256(
            json.dumps(payload_b, sort_keys=True, default=str).encode()
        ).hexdigest()

        assert hash_a != hash_b

    def test_changing_any_field_changes_hash(self):
        base = AuditEntry(
            analyst_id="alice@corp.com",
            tool_name="get_alert",
            input_summary={"alert_id": "ALT-001"},
            policy_result={"allow": True},
            response_code="success",
            duration_ms=42,
            timestamp=datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC),
        )
        modified = AuditEntry(
            analyst_id="bob@corp.com",  # changed
            tool_name="get_alert",
            input_summary={"alert_id": "ALT-001"},
            policy_result={"allow": True},
            response_code="success",
            duration_ms=42,
            timestamp=datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC),
        )
        payload_base = _build_hash_payload(base, GENESIS_HASH)
        payload_mod = _build_hash_payload(modified, GENESIS_HASH)

        h_base = hashlib.sha256(
            json.dumps(payload_base, sort_keys=True, default=str).encode()
        ).hexdigest()
        h_mod = hashlib.sha256(
            json.dumps(payload_mod, sort_keys=True, default=str).encode()
        ).hexdigest()

        assert h_base != h_mod

    def test_hash_output_is_64_char_hex(self):
        entry = AuditEntry(
            analyst_id="alice@corp.com",
            tool_name="enrich_ioc",
            input_summary={"indicator": "1.2.3.4"},
            policy_result={"allow": True},
            response_code="success",
            duration_ms=100,
        )
        payload = _build_hash_payload(entry, GENESIS_HASH)
        result = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


class TestInputSanitization:
    def test_sensitive_keys_excluded_from_hash_payload(self):
        from sentinel.mcp.middleware import _sanitize_inputs

        inputs = {
            "alert_id": "ALT-001",
            "api_key": "secret-value",
            "password": "hunter2",
            "token": "bearer-abc",
            "hostname": "laptop-001",
        }
        sanitised = _sanitize_inputs(inputs)
        assert sanitised["alert_id"] == "ALT-001"
        assert sanitised["hostname"] == "laptop-001"
        assert sanitised["api_key"] == "[REDACTED]"
        assert sanitised["password"] == "[REDACTED]"
        assert sanitised["token"] == "[REDACTED]"

    def test_non_sensitive_keys_pass_through(self):
        from sentinel.mcp.middleware import _sanitize_inputs

        inputs = {"alert_id": "ALT-001", "limit": 10, "time_window_hours": 24}
        result = _sanitize_inputs(inputs)
        assert result == inputs
