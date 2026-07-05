package sentinel.rate_limit

import data.rate_limits

# Default: allow (rate limit state is tracked in Redis, not OPA)
# This policy defines the LIMITS; the application tracks the COUNTS.
default allow = true
default reason = "within_limit"

# Deny if count exceeds the configured limit for this tool
allow = false if {
    limit := rate_limits[input.tool_name]
    input.count > limit
}

reason = "rate_limit_exceeded" if {
    limit := rate_limits[input.tool_name]
    input.count > limit
}

# Tools not in the rate_limits map are unrestricted
