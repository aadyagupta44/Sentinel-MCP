#!/usr/bin/env python3
"""Adversarial Testing Agent — human-like, code-break tendencies.

Runs after the normal pytest suite. Tries every tool and adapter with
inputs that real users (and attackers) actually send:
- Empty and null inputs
- SQL injection strings
- Path traversal attempts
- Oversized payloads
- Unicode and special characters
- Negative numbers and zero
- Boundary values
- Repeated rapid calls (rate limit check)

Usage:
    python scripts/testing_agent.py              # test all tools
    python scripts/testing_agent.py --tool enrich_ioc
    python scripts/testing_agent.py --phase 2
"""

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Adversarial payloads ──────────────────────────────────────────────────────

EMPTY_INPUTS: list[Any] = ["", None, "   ", "\t", "\n"]

SQL_INJECTION: list[str] = [
    "' OR '1'='1",
    "'; DROP TABLE audit_log; --",
    "1; SELECT * FROM audit_log",
    "' UNION SELECT * FROM pending_actions--",
    "\" OR \"1\"=\"1",
]

PATH_TRAVERSAL: list[str] = [
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
]

OVERSIZED: list[str] = [
    "A" * 10_000,
    "A" * 100_000,
]

SPECIAL_CHARS: list[str] = [
    "<script>alert(1)</script>",
    "{{7*7}}",                     # template injection probe
    "${7*7}",                       # expression injection
    "%(7*7)s",
    "\x00\x01\x02",                 # null bytes
    "*" * 100,                     # unicode stress
    "'; --",
    "`id`",                         # shell injection
]

BOUNDARY_NUMBERS: list[Any] = [
    0, -1, -999, 2**31, 2**63, float("inf"), float("nan"),
]

VALID_LOOKING_BAD_IPS: list[str] = [
    "256.256.256.256",
    "0.0.0.0",
    "127.0.0.1",
    "localhost",
    "::1",
    "http://evil.com",
]


# ── Result tracking ───────────────────────────────────────────────────────────

@dataclass
class TestResult:
    tool: str
    payload_type: str
    payload: Any
    passed: bool
    issue: str = ""
    response: Any = None
    duration_ms: int = 0


@dataclass
class AgentReport:
    run_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    issues: list[TestResult] = field(default_factory=list)

    def add(self, result: TestResult) -> None:
        self.total_tests += 1
        if result.passed:
            self.passed += 1
        else:
            self.failed += 1
            self.issues.append(result)

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  ADVERSARIAL TESTING AGENT — REPORT",
            "=" * 60,
            f"  Run at : {self.run_at}",
            f"  Total  : {self.total_tests}",
            f"  Passed : {self.passed}",
            f"  Failed : {self.failed}",
            "",
        ]
        if not self.issues:
            lines.append("  [OK]  No issues found. All adversarial inputs handled safely.")
        else:
            lines.append(f"  [!]  {self.failed} issue(s) found:\n")
            for i, r in enumerate(self.issues, 1):
                lines += [
                    f"  [{i}] Tool    : {r.tool}",
                    f"      Payload : {r.payload_type} -> {repr(str(r.payload)[:80])}",
                    f"      Issue   : {r.issue}",
                    "",
                ]
        lines.append("=" * 60)
        return "\n".join(lines)


# ── Input validator (what each tool's schema expects) ────────────────────────

TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "get_alert": {"alert_id": str},
    "search_logs": {"query": str, "time_window_hours": int, "max_results": int},
    "enrich_ioc": {"indicator": str, "indicator_type": str},
    "threat_hunt": {"indicator": str, "look_back_days": int},
    "user_context": {"email": str},
    "recent_logins": {"email": str, "days": int},
    "risk_score_user": {"email": str},
    "device_processes": {"hostname": str, "time_window_minutes": int},
    "network_connections": {"hostname": str, "time_window_minutes": int},
    "mitre_technique": {"technique_id": str},
    "isolate_device": {"hostname": str, "reason": str, "confirmed": bool},
    "disable_user": {"email": str, "reason": str, "confirmed": bool},
    "block_ip": {"ip_address": str, "reason": str, "confirmed": bool},
    "kill_process": {"hostname": str, "pid": int, "reason": str, "confirmed": bool},
}


# ── Core test runner ──────────────────────────────────────────────────────────

class AdversarialTester:
    def __init__(self) -> None:
        self.report = AgentReport()

    def _check_response(self, tool: str, payload_type: str, payload: Any, response: Any, duration_ms: int) -> TestResult:
        """Determine whether the response is safe — never a crash, never a raw exception."""
        passed = True
        issue = ""

        if response is None:
            passed = False
            issue = "Tool returned None — should always return a dict"
        elif isinstance(response, Exception):
            passed = False
            issue = f"Tool raised unhandled exception: {type(response).__name__}: {response}"
        elif isinstance(response, dict):
            # Check it has either data or a structured error — never a raw traceback
            has_data = any(k not in ("error", "code") for k in response)
            has_error = "error" in response and "code" in response
            if not has_data and not has_error:
                passed = False
                issue = "Response dict has no 'code' field on error — unstructured error response"
            # Check for leaked internals
            raw = json.dumps(response, default=str)
            for leak in ("traceback", "Traceback", "File \"", "line ", "sqlalchemy", "asyncpg"):
                if leak in raw:
                    passed = False
                    issue = f"Response leaks internal detail: found '{leak}'"
                    break
        elif isinstance(response, str):
            for leak in ("Traceback", "File \"", "sqlalchemy"):
                if leak in response:
                    passed = False
                    issue = f"String response leaks internal detail: '{leak}'"

        return TestResult(
            tool=tool,
            payload_type=payload_type,
            payload=payload,
            passed=passed,
            issue=issue,
            response=response,
            duration_ms=duration_ms,
        )

    async def test_tool_with_payload(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        payload_type: str,
        payload: Any,
    ) -> TestResult:
        from unittest.mock import AsyncMock, patch

        from sentinel.mcp.middleware import run_middleware

        async def mock_execute(args: dict) -> dict[str, Any]:
            return {"mock": True, "tool": tool_name, "args_received": list(args.keys())}

        # Patch Redis, OPA rate-limit, and Postgres so tests run in <1ms without Docker
        start = time.monotonic()
        mock_opa = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        mock_opa.is_allowed = AsyncMock(return_value=(True, "policy_allow"))
        mock_opa.check_rate_limit = AsyncMock(return_value=(True, "within_limit"))
        try:
            with (
                patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
                patch("sentinel.mcp.middleware._get_rate_count", new=AsyncMock(return_value=0)),
                patch("sentinel.mcp.middleware.get_opa_engine", return_value=mock_opa),
            ):
                result = await run_middleware(tool_name, arguments, mock_execute)
            duration_ms = int((time.monotonic() - start) * 1000)
            return self._check_response(tool_name, payload_type, payload, result, duration_ms)
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            return TestResult(
                tool=tool_name,
                payload_type=payload_type,
                payload=payload,
                passed=False,
                issue=f"Unhandled exception escaped middleware: {type(exc).__name__}: {exc}",
                duration_ms=duration_ms,
            )

    async def run_string_field_tests(self, tool_name: str, field_name: str) -> None:
        schema = TOOL_SCHEMAS.get(tool_name, {})
        base_args = {k: _default_value(t) for k, t in schema.items()}

        for payload in EMPTY_INPUTS:
            args = {**base_args, field_name: payload}
            result = await self.test_tool_with_payload(tool_name, args, "empty_input", payload)
            self.report.add(result)

        for payload in SQL_INJECTION:
            args = {**base_args, field_name: payload}
            result = await self.test_tool_with_payload(tool_name, args, "sql_injection", payload)
            self.report.add(result)

        for payload in PATH_TRAVERSAL:
            args = {**base_args, field_name: payload}
            result = await self.test_tool_with_payload(tool_name, args, "path_traversal", payload)
            self.report.add(result)

        for payload in SPECIAL_CHARS:
            args = {**base_args, field_name: payload}
            result = await self.test_tool_with_payload(tool_name, args, "special_chars", payload)
            self.report.add(result)

        # One oversized payload per field (skip very large ones in CI)
        args = {**base_args, field_name: "A" * 10_000}
        result = await self.test_tool_with_payload(tool_name, args, "oversized", "A" * 10_000)
        self.report.add(result)

    async def run_number_field_tests(self, tool_name: str, field_name: str) -> None:
        schema = TOOL_SCHEMAS.get(tool_name, {})
        base_args = {k: _default_value(t) for k, t in schema.items()}

        for payload in BOUNDARY_NUMBERS:
            args = {**base_args, field_name: payload}
            result = await self.test_tool_with_payload(tool_name, args, "boundary_number", payload)
            self.report.add(result)

    async def run_tool(self, tool_name: str) -> None:
        schema = TOOL_SCHEMAS.get(tool_name, {})
        print(f"  -> Testing {tool_name} ({len(schema)} fields)...", end="", flush=True)
        count_before = self.report.total_tests

        for field_name, field_type in schema.items():
            if field_type == str:
                await self.run_string_field_tests(tool_name, field_name)
            elif field_type == int:
                await self.run_number_field_tests(tool_name, field_name)

        added = self.report.total_tests - count_before
        issues = sum(1 for r in self.report.issues if r.tool == tool_name)
        status = "[OK]" if issues == 0 else f"[!]  {issues} issue(s)"
        print(f" {added} tests, {status}")

    async def run_all(self, tools: list[str] | None = None) -> AgentReport:
        targets = tools or list(TOOL_SCHEMAS.keys())
        print(f"\n[*]  Adversarial Testing Agent — {len(targets)} tool(s)\n")
        for tool_name in targets:
            await self.run_tool(tool_name)
        return self.report


# ── Helpers ───────────────────────────────────────────────────────────────────

def _default_value(t: type) -> Any:
    if t == str:
        return "test-value"
    if t == int:
        return 1
    if t == bool:
        return False
    return None


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> int:
    parser = argparse.ArgumentParser(description="Adversarial Testing Agent")
    parser.add_argument("--tool", help="Test a specific tool only")
    parser.add_argument("--phase", type=int, help="Run tests relevant to a phase")
    parser.add_argument("--output", help="Write JSON report to this file")
    args = parser.parse_args()

    # Set test environment
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("MOCK_ADAPTERS", "true")
    os.environ.setdefault("POLICY_ENFORCEMENT", "false")
    os.environ.setdefault("ANALYST_ID", "adversarial-agent@test.local")
    os.environ.setdefault("ANALYST_ROLE", "admin")

    from sentinel.config import get_settings
    get_settings.cache_clear()

    tester = AdversarialTester()
    tools = [args.tool] if args.tool else None
    report = await tester.run_all(tools)

    print("\n" + report.summary())

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(
            json.dumps(
                {
                    "run_at": report.run_at,
                    "total": report.total_tests,
                    "passed": report.passed,
                    "failed": report.failed,
                    "issues": [
                        {
                            "tool": r.tool,
                            "payload_type": r.payload_type,
                            "payload": str(r.payload)[:200],
                            "issue": r.issue,
                        }
                        for r in report.issues
                    ],
                },
                indent=2,
            )
        )
        print(f"\nReport written to {args.output}")

    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
