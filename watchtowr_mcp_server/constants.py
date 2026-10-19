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

OPEN_FINDINGS_FILTER: dict[str, str] = {"statuses": "confirmed", "severities": ",".join(SUMMARY_SEVERITIES)}
OPEN_FINDINGS_LABEL: str = "Open = Confirmed, critical to low"

# Max unique finding IDs a bulk write tool acts on per call.
MAX_BULK_FINDING_IDS: int = 25

FINDING_STATUSES: tuple[str, ...] = (
    "unconfirmed", "confirmed", "remediated", "risk-accepted", "closed", "asset-no-longer-tracked",
)

# Exact stored status values; the SDK docs lowercase the first letter.
VERIFIED_ASSET_STATUSES = "verified,VerifiedReducedAttack,Tracked"

MAX_TREND_WEEKS: int = 8

REMEDIATION_DATE_CAVEAT = (
    "Remediated findings are placed by their last update, because the platform has no remediation-date filter."
)

READ_ONLY: dict[str, bool] = {"readOnlyHint": True, "openWorldHint": False}
WRITE: dict[str, bool] = {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}
DESTRUCTIVE_WRITE: dict[str, bool] = {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False}
