"""MCP Prompts — reusable investigation playbooks for Claude.

Prompts are pre-written investigation templates that guide Claude through
a structured workflow. An analyst says "run the alert investigation playbook
for ALT-2026-001" and Claude follows the exact steps.

Registered prompts:
  investigate_alert  — full alert investigation workflow
  triage_user        — user risk triage workflow
  morning_briefing   — daily SOC shift handover briefing
"""

from mcp.server.fastmcp import FastMCP
from mcp.types import GetPromptResult, PromptMessage, TextContent

from sentinel.mcp.server import mcp


@mcp.prompt()
def investigate_alert(alert_id: str = "") -> str:
    """Step-by-step playbook for investigating a security alert.

    Guides Claude through the full investigation: fetch alert, profile
    the user, enrich all IOCs, examine endpoint activity, map to MITRE,
    and recommend actions. Ends with a proposed action plan.

    Args:
        alert_id: The alert to investigate (e.g. "ALT-2026-001")
    """
    target = alert_id or "<alert_id>"
    return f"""You are a senior SOC analyst investigating alert {target}.

Follow these steps in order. Do not skip steps.

== STEP 1: Fetch the alert ==
Call get_alert("{target}") and read the full alert details.
Note: severity, affected_user, affected_host, source_ip, mitre_techniques.

== STEP 2: Profile the affected user ==
Call user_context(<affected_user_email>).
Look for: sensitive group memberships, MFA status, registered devices.

== STEP 3: Review login history ==
Call recent_logins(<affected_user_email>, days=7).
Look for: impossible travel, unfamiliar devices, missing MFA, off-hours access.

== STEP 4: Enrich all IOCs ==
For each IP address in the alert: call enrich_ioc(<ip>, "ip").
For each file hash: call enrich_ioc(<hash>, "hash").
Look for: malicious verdict, known malware families, C2 infrastructure.

== STEP 5: Examine endpoint activity ==
If there is an affected_host:
  Call device_processes(<hostname>, time_window_minutes=60).
  Call network_connections(<hostname>, time_window_minutes=60).
Look for: suspicious child processes, connections to flagged IPs.

== STEP 6: Map to MITRE ATT&CK ==
For each technique_id in mitre_techniques:
  Call mitre_technique(<technique_id>).
Use the detection and mitigation guidance in your assessment.

== STEP 7: Risk assessment ==
Call risk_score_user(<affected_user_email>) for the composite risk score.

== STEP 8: Your findings ==
Based on all evidence above, provide:
1. What likely happened (attack narrative in plain English)
2. Confidence level (high/medium/low) and why
3. Immediate recommended actions (ranked by urgency)
4. If isolation/account suspension is warranted, propose the write tool call

== GUARDRAILS ==
- Do NOT call isolate_device or disable_user without explicit analyst approval
- If evidence is ambiguous, say so — do not overstate confidence
- If this looks like a false positive, explain why clearly"""


@mcp.prompt()
def triage_user(email: str = "") -> str:
    """Rapid user risk triage: profile, login history, active alerts, risk score.

    Use this when you receive a tip about a potentially compromised user
    and need a quick risk assessment before deciding whether to escalate.

    Args:
        email: User email to triage (e.g. "bob.finance@acmecorp.com")
    """
    target = email or "<user_email>"
    return f"""Perform a rapid risk triage for user {target}.

== STEP 1: User profile ==
Call user_context("{target}").
Flag: admin groups, access to sensitive systems, lack of MFA.

== STEP 2: Login history (past 14 days) ==
Call recent_logins("{target}", days=14).
Flag: new countries, new devices, missing MFA, failed logins.

== STEP 3: Enrich any suspicious IPs ==
For each unfamiliar IP in the login history: call enrich_ioc(<ip>, "ip").

== STEP 4: Risk score ==
Call risk_score_user("{target}").
Note the score, level, and contributing factors.

== STEP 5: Summary ==
In 3-5 sentences: what is the risk level, what are the top 2-3 concerns,
and what should happen next (monitor / investigate further / escalate)?"""


@mcp.prompt()
def morning_briefing() -> str:
    """Daily SOC shift handover briefing — open alerts, risk users, weekly trend.

    Run this at the start of each shift to get a situational awareness summary.
    """
    return """Generate the morning SOC briefing for the current shift.

== STEP 1: Current open alerts ==
Read the resource sentinel://alerts/active.
Count by severity: critical, high, medium, low.
List the top 3 most urgent alerts.

== STEP 2: Weekly trend ==
Call weekly_summary() for 7-day statistics and trend data.

== STEP 3: Risk assessment of top alert users ==
For the affected users in the top 3 alerts:
  Call risk_score_user(<email>) for each.

== STEP 4: Briefing output ==
Write a structured shift handover in this format:

--- MORNING BRIEFING ---
Date/Time: [now]
Open Alerts: [count] ([critical] critical, [high] high, [medium] medium, [low] low)

TOP PRIORITY:
1. [Alert ID] — [one sentence summary]
2. [Alert ID] — [one sentence summary]
3. [Alert ID] — [one sentence summary]

USERS TO WATCH:
- [email]: risk score [X]/100 — [reason]

WEEKLY TREND:
[2-3 sentences on trend]

RECOMMENDED FOCUS:
[What the analyst should prioritise this shift]
--- END BRIEFING ---"""
