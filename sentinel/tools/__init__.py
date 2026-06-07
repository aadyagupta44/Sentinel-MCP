# Import all tool modules so their @mcp.tool() decorators run and register
# tools with the FastMCP server instance.
# This file is imported by sentinel/main.py at startup.
from sentinel.tools import actions, alerts, endpoint, identity, intel, reports  # noqa: F401
