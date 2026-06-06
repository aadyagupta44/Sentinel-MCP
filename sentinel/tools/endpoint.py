"""Endpoint forensics tools.

device_processes    — FULLY IMPLEMENTED (Phase 2, mock data)
network_connections — FULLY IMPLEMENTED (Phase 2, mock data)
"""

from typing import Any

from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp
from sentinel.tools import mock_data as mock


async def _execute_device_processes(args: dict[str, Any]) -> dict[str, Any]:
    hostname = str(args.get("hostname", "")).strip()
    window = max(1, min(int(args.get("time_window_minutes", 60)), 1440))

    if not hostname:
        return {"error": "hostname is required", "code": "MISSING_PARAMETER"}

    processes = mock.device_processes(hostname, window)
    return {
        "hostname": hostname,
        "time_window_minutes": window,
        "total_processes": len(processes),
        "suspicious_count": sum(1 for p in processes if p.get("suspicious")),
        "processes": processes,
    }


@mcp.tool()
async def device_processes(hostname: str, time_window_minutes: int = 60) -> dict[str, Any]:
    """Get process creation events on a host from Wazuh EDR.

    Returns processes with PID, parent PID, command line, and a suspicious
    flag for known-bad process names (encoded PowerShell, mimikatz, procdump,
    etc.). Use this after get_alert() to understand what was running on the
    affected host around the time of the alert.

    Args:
        hostname: Target hostname, e.g. "LAPTOP-HR-03"
        time_window_minutes: Look-back window in minutes (default 60, max 1440)
    """
    return await run_middleware(
        "device_processes",
        {"hostname": hostname, "time_window_minutes": time_window_minutes},
        _execute_device_processes,
    )


async def _execute_network_connections(args: dict[str, Any]) -> dict[str, Any]:
    hostname = str(args.get("hostname", "")).strip()
    window = max(1, min(int(args.get("time_window_minutes", 60)), 1440))

    if not hostname:
        return {"error": "hostname is required", "code": "MISSING_PARAMETER"}

    connections = mock.network_connections(hostname, window)
    return {
        "hostname": hostname,
        "time_window_minutes": window,
        "total_connections": len(connections),
        "threat_intel_flagged": sum(1 for c in connections if c.get("threat_intel_flagged")),
        "connections": connections,
    }


@mcp.tool()
async def network_connections(hostname: str, time_window_minutes: int = 60) -> dict[str, Any]:
    """Get network connection events on a host from Wazuh EDR.

    Returns connections with source/dest IP, port, protocol, and a
    threat_intel_flagged field when the remote IP matches abuse.ch or
    other threat intel sources. Use this to detect C2 callbacks or
    data exfiltration after a suspicious process is identified.

    Args:
        hostname: Target hostname, e.g. "LAPTOP-HR-03"
        time_window_minutes: Look-back window in minutes (default 60, max 1440)
    """
    return await run_middleware(
        "network_connections",
        {"hostname": hostname, "time_window_minutes": time_window_minutes},
        _execute_network_connections,
    )
