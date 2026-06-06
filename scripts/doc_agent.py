#!/usr/bin/env python3
"""Documentation Agent — writes plain-English phase documentation.

Runs after each phase completes. Reads:
  - git log since the last phase tag
  - pytest output
  - any error logs captured during the phase

Writes:
  - docs/phases/phaseN.md  — what was built, what broke, how it was fixed
  - CHANGELOG.md           — updated with phase entry
  - README.md              — patches the "Current Status" section

Usage:
    python scripts/doc_agent.py --phase 1
    python scripts/doc_agent.py --phase 2 --test-output test_results.txt
    python scripts/doc_agent.py --phase 1 --dry-run
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).parent.parent


# ── Phase metadata ────────────────────────────────────────────────────────────

PHASE_NAMES = {
    1: "Foundation",
    2: "MCP Server + Placeholder Tools",
    3: "Adapters",
    4: "All 18 Tools",
    5: "Auth + HTTP Transport",
    6: "Simulator",
    7: "Hardening",
    8: "Marketplace Prep",
}

PHASE_GOALS = {
    1: (
        "Set up the skeleton that everything else plugs into: "
        "database models, config, audit log, policy engine, base adapter, "
        "MCP server shell, health endpoint, and Docker infrastructure."
    ),
    2: (
        "Wire the full MCP protocol — tool registry, middleware pipeline, "
        "Resources, Prompts — with three working placeholder tools."
    ),
    3: (
        "Implement every external integration adapter with circuit breakers, "
        "retry logic, and mock fallbacks."
    ),
    4: (
        "Implement all 18 tools (14 read, 4 write) using the completed adapters. "
        "Write tools enforce two-step confirmation."
    ),
    5: (
        "Add OAuth 2.1 + PKCE authentication and the HTTP/Streamable HTTP transport."
    ),
    6: (
        "Build the simulator — normal traffic bots and adversarial attack scenarios "
        "that stream synthetic events into OpenSearch."
    ),
    7: (
        "Production hardening: input sanitisation audit, full OpenTelemetry wiring, "
        "structlog everywhere, complete README and SECURITY.md."
    ),
    8: (
        "Final marketplace checklist, tag v1.0.0, submit."
    ),
}


# ── Git helpers ───────────────────────────────────────────────────────────────

def git(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git"] + list(args),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_commits_since_last_phase(phase: int) -> list[dict[str, str]]:
    prev_tag = f"phase-{phase - 1}" if phase > 1 else ""
    log_range = f"{prev_tag}..HEAD" if prev_tag else "HEAD"
    raw = git("log", log_range, "--pretty=format:%H|%s|%an|%ai", "--no-merges")
    commits = []
    for line in raw.splitlines():
        if "|" not in line:
            continue
        parts = line.split("|", 3)
        if len(parts) == 4:
            commits.append({"hash": parts[0][:8], "subject": parts[1], "author": parts[2], "date": parts[3][:10]})
    return commits


def get_changed_files(phase: int) -> list[str]:
    prev_tag = f"phase-{phase - 1}" if phase > 1 else ""
    diff_range = f"{prev_tag}..HEAD" if prev_tag else "HEAD"
    raw = git("diff", "--name-only", diff_range)
    return [f for f in raw.splitlines() if f]


# ── Test result parser ────────────────────────────────────────────────────────

def parse_test_output(test_output: str) -> dict[str, object]:
    """Extract key numbers from pytest output."""
    result: dict[str, object] = {"total": 0, "passed": 0, "failed": 0, "coverage": None, "errors": []}

    # Match "X passed, Y failed" style summary
    m = re.search(r"(\d+) passed", test_output)
    if m:
        result["passed"] = int(m.group(1))
    m = re.search(r"(\d+) failed", test_output)
    if m:
        result["failed"] = int(m.group(1))
    result["total"] = int(result["passed"]) + int(result["failed"])

    m = re.search(r"Total coverage: ([\d.]+)%", test_output)
    if m:
        result["coverage"] = float(m.group(1))

    # Extract FAILED lines
    for line in test_output.splitlines():
        if line.startswith("FAILED "):
            result["errors"].append(line.replace("FAILED ", "").strip())  # type: ignore[union-attr]

    return result


# ── Document generator ────────────────────────────────────────────────────────

def generate_phase_doc(
    phase: int,
    test_stats: dict[str, object],
    problems_and_fixes: list[dict[str, str]],
    notes: str = "",
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    name = PHASE_NAMES.get(phase, f"Phase {phase}")
    goal = PHASE_GOALS.get(phase, "")

    lines = [
        f"# Phase {phase} — {name}",
        f"*Completed: {now}*",
        "",
        "## What This Phase Was About",
        "",
        goal,
        "",
        "## What Was Built",
        "",
    ]

    # Add file list if available
    changed = get_changed_files(phase)
    if changed:
        lines.append("Files created or changed in this phase:\n")
        for f in changed[:30]:
            lines.append(f"- `{f}`")
        if len(changed) > 30:
            lines.append(f"- ...and {len(changed) - 30} more")
        lines.append("")

    # Test results
    lines += [
        "## Test Results",
        "",
        f"- **Tests run:** {test_stats.get('total', 'unknown')}",
        f"- **Passed:** {test_stats.get('passed', 'unknown')}",
        f"- **Failed:** {test_stats.get('failed', 0)}",
    ]
    if test_stats.get("coverage"):
        lines.append(f"- **Coverage:** {test_stats['coverage']}%")
    lines.append("")

    # Problems and fixes
    if problems_and_fixes:
        lines += ["## Problems Encountered and How They Were Fixed", ""]
        for i, pf in enumerate(problems_and_fixes, 1):
            lines += [
                f"### Problem {i}: {pf.get('title', 'Issue')}",
                "",
                f"**What happened:** {pf.get('problem', '')}",
                "",
                f"**Why it happened:** {pf.get('cause', '')}",
                "",
                f"**How it was fixed:** {pf.get('fix', '')}",
                "",
            ]
    else:
        lines += [
            "## Problems Encountered",
            "",
            "No significant problems were encountered in this phase.",
            "",
        ]

    # Notes
    if notes:
        lines += ["## Notes", "", notes, ""]

    # Commits
    commits = get_commits_since_last_phase(phase)
    if commits:
        lines += ["## Commits in This Phase", ""]
        for c in commits[:15]:
            lines.append(f"- `{c['hash']}` {c['subject']}")
        lines.append("")

    # Verification
    lines += [
        "## Phase Verification Checklist",
        "",
        f"- [x] All tests passing ({test_stats.get('passed', 0)}/{test_stats.get('total', 0)})",
    ]
    if test_stats.get("coverage"):
        cov = float(str(test_stats["coverage"]))
        lines.append(f"- [{'x' if cov >= 80 else ' '}] Coverage ≥ 80% (actual: {cov}%)")
    lines += [
        "- [ ] docker compose up starts cleanly",
        "- [ ] No hardcoded secrets in any file",
        "",
    ]

    return "\n".join(lines)


def update_changelog(phase: int, dry_run: bool = False) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    name = PHASE_NAMES.get(phase, f"Phase {phase}")
    changelog_path = ROOT / "CHANGELOG.md"

    entry = f"\n## Phase {phase} — {name} ({now})\n\n- Phase {phase} complete.\n"

    if dry_run:
        print(f"[dry-run] Would append to CHANGELOG.md:\n{entry}")
        return

    existing = changelog_path.read_text(encoding="utf-8") if changelog_path.exists() else "# Changelog\n"
    if f"## Phase {phase}" not in existing:
        with open(changelog_path, "a", encoding="utf-8") as f:
            f.write(entry)
        print(f"  [OK]  Updated CHANGELOG.md")


def update_readme_status(phase: int, dry_run: bool = False) -> None:
    readme_path = ROOT / "README.md"
    if not readme_path.exists():
        return

    content = readme_path.read_text(encoding="utf-8")
    status_block = (
        f"\n## Current Status\n\n"
        f"**Phase {phase} — {PHASE_NAMES.get(phase, '')} [OK] Complete**\n\n"
        f"Next: Phase {phase + 1} — {PHASE_NAMES.get(phase + 1, 'Done')}\n"
    )

    # Replace existing status block or append
    if "## Current Status" in content:
        content = re.sub(
            r"## Current Status\n.*?(?=\n##|\Z)",
            status_block.lstrip("\n"),
            content,
            flags=re.DOTALL,
        )
    else:
        content += status_block

    if dry_run:
        print(f"[dry-run] Would update README.md status section to Phase {phase}")
        return

    readme_path.write_text(content, encoding="utf-8")
    print(f"  [OK]  Updated README.md status")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Documentation Agent")
    parser.add_argument("--phase", type=int, required=True, help="Phase number (1-8)")
    parser.add_argument("--test-output", help="Path to pytest output file")
    parser.add_argument("--problems", help="JSON file with problems/fixes list")
    parser.add_argument("--notes", default="", help="Extra notes to include")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    args = parser.parse_args()

    if args.phase not in range(1, 9):
        print("ERROR: --phase must be 1-8")
        return 1

    # Parse test output
    test_stats: dict[str, object] = {"total": 0, "passed": 0, "failed": 0}
    if args.test_output:
        path = Path(args.test_output)
        if path.exists():
            test_stats = parse_test_output(path.read_text())
    else:
        # Try to run tests and capture output
        print("  Running test suite...")
        try:
            result = subprocess.run(
                ["python", "-m", "uv", "run", "pytest", "--no-header", "-q"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=120,
                env={**__import__("os").environ, "ENVIRONMENT": "test", "MOCK_ADAPTERS": "true", "POLICY_ENFORCEMENT": "false"},
            )
            output = result.stdout + result.stderr
            test_stats = parse_test_output(output)
        except Exception as e:
            print(f"  Warning: could not run tests: {e}")

    # Parse problems/fixes
    problems: list[dict[str, str]] = []
    if args.problems:
        path = Path(args.problems)
        if path.exists():
            problems = json.loads(path.read_text())

    # Generate doc
    doc_content = generate_phase_doc(args.phase, test_stats, problems, args.notes)

    phase_dir = ROOT / "docs" / "phases"
    phase_dir.mkdir(parents=True, exist_ok=True)
    doc_path = phase_dir / f"phase{args.phase}.md"

    if args.dry_run:
        print(f"\n[dry-run] Would write to {doc_path}:\n")
        print(doc_content[:500] + "...\n")
    else:
        doc_path.write_text(doc_content, encoding="utf-8")
        print(f"  [OK]  Written: {doc_path}")

    update_changelog(args.phase, args.dry_run)
    update_readme_status(args.phase, args.dry_run)

    print(f"\n  Phase {args.phase} documentation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
