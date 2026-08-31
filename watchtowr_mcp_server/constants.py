"""Shared constants for the watchTowr MCP server.

Keep API-facing enumerations in one place so every tool uses the exact
values the watchTowr API expects. The API validates these values
strictly — a mismatch results in a 400 Bad Request.
"""

# All severity values accepted by the watchTowr API, in display order
# (most severe first). The API only accepts lowercase values; see the
# SDK's ClientFinding.severity enum validator.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Set form for fast membership checks / validation.
VALID_SEVERITIES: frozenset[str] = frozenset(SEVERITIES)

# Severities used by default in summary/reporting tools (excludes "info",
# which is usually too noisy for executive-level breakdowns).
SUMMARY_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
