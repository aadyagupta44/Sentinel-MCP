package sentinel.authz

# Default deny — explicit allow required
default allow = false
default reason = "no_matching_rule"

# ── Role definitions ──────────────────────────────────────────────────────────

read_tools := {
    "get_alert",
    "search_logs",
    "correlate_alerts",
    "similar_incidents",
    "enrich_ioc",
    "threat_hunt",
    "user_context",
    "recent_logins",
    "risk_score_user",
    "device_processes",
    "network_connections",
    "mitre_technique",
    "generate_incident_report",
    "weekly_summary",
}

write_tools := {
    "isolate_device",
    "disable_user",
    "block_ip",
    "kill_process",
}

# ── Allow rules ───────────────────────────────────────────────────────────────

# Analysts can call all read tools
allow if {
    input.role == "analyst"
    input.tool_name in read_tools
}

reason = "analyst_read_allowed" if {
    input.role == "analyst"
    input.tool_name in read_tools
}

# Analysts are denied write tools with a clear reason
reason = "write_tools_require_senior_analyst" if {
    input.role == "analyst"
    input.tool_name in write_tools
}

# Senior analysts can call both read and write tools
allow if {
    input.role == "senior_analyst"
    input.tool_name in read_tools
}

allow if {
    input.role == "senior_analyst"
    input.tool_name in write_tools
}

reason = "senior_analyst_allowed" if {
    input.role == "senior_analyst"
    input.tool_name in read_tools | write_tools
}

# Admins can call everything
allow if {
    input.role == "admin"
}

reason = "admin_allowed" if {
    input.role == "admin"
}

# Unknown role — deny with reason
reason = "unknown_role" if {
    not input.role in {"analyst", "senior_analyst", "admin"}
}
