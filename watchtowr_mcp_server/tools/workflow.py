from datetime import datetime, timedelta

from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.api.activity_log_api import ActivityLogApi
from watchtowr_api_sdk.models.update_client_finding_status_request_body import UpdateClientFindingStatusRequestBody

from ..client import get_api_client, get_total, parse_date, severity_display
from ..constants import SUMMARY_SEVERITIES
from .composite import _ASSET_API_MAP, _count


def register_workflow_tools(mcp):

    @mcp.tool()
    def get_recent_remediations(days: int = 7, page_size: int = 30) -> str:
        """List findings remediated within the last N days.

        Args:
            days: Number of days to look back (default 7).
            page_size: Results per page (max 30).
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            since = datetime.now() - timedelta(days=days)

            resp = findings_api.get_list_findings(
                statuses="remediated",
                created_from=since,
                page_size=min(page_size, 30),
            )

            if not hasattr(resp, 'data') or not resp.data:
                return f"No findings remediated in the last {days} days."

            total = get_total(resp)
            lines = [f"Recently Remediated Findings (Last {days} Days):", ""]
            if total:
                lines.insert(1, f"Total: {total}")

            for f in resp.data:
                fid = getattr(f, 'id', '')
                sev = severity_display(getattr(f, 'severity', None))
                title = getattr(f, 'title', 'No title')
                lines.append(f"- [ID:{fid}] [{sev}] {title}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving recent remediations: {e}"

    @mcp.tool()
    def get_daily_digest() -> str:
        """24-hour digest: new assets, new findings, and recent activity log entries."""
        try:
            client = get_api_client()
            since = datetime.now() - timedelta(hours=24)
            lines = ["Daily Digest (Last 24 Hours)", "=" * 30, ""]

            findings_api = FindingsApi(client)
            new_findings = 0
            findings_by_sev = {}
            for sev in SUMMARY_SEVERITIES:
                try:
                    c = _count(findings_api, "get_list_findings", severities=sev, created_from=since)
                    new_findings += c
                    if c > 0:
                        findings_by_sev[sev] = c
                except Exception:
                    pass

            lines.append(f"New Findings: {new_findings}")
            for sev, count in findings_by_sev.items():
                lines.append(f"  - {severity_display(sev)}: +{count}")
            lines.append("")

            new_assets = 0
            asset_lines = []
            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    c = _count(api_cls(client), method_name, created_from=since)
                    if c > 0:
                        new_assets += c
                        asset_lines.append(f"  - {label}: +{c}")
                except Exception:
                    pass

            lines.append(f"New Assets: {new_assets}")
            lines.extend(asset_lines)
            lines.append("")

            try:
                activity_api = ActivityLogApi(client)
                log_resp = activity_api.get_list_activity_logs(
                    created_from=since, page_size=10
                )
                log_total = get_total(log_resp) or 0
                lines.append(f"Activity Log Entries: {log_total}")
                if hasattr(log_resp, 'data') and log_resp.data:
                    for log in log_resp.data[:5]:
                        desc = getattr(log, 'description', '')
                        causer = getattr(log, 'caused_by', None)
                        user = getattr(causer, 'name', 'System') if causer else 'System'
                        lines.append(f"  - {user}: {desc}")
            except Exception:
                lines.append("Activity Logs: error")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating daily digest: {e}"

    @mcp.tool()
    def bulk_retest_findings(finding_ids: str) -> str:
        """Trigger retests for multiple findings at once.

        Args:
            finding_ids: Comma-separated finding IDs to retest.
        """
        try:
            ids = [int(fid.strip()) for fid in finding_ids.split(",") if fid.strip()]
            if not ids:
                return "No valid finding IDs provided."

            client = get_api_client()
            findings_api = FindingsApi(client)

            results = []
            for fid in ids:
                try:
                    findings_api.start_specific_finding_retest(finding_id=fid)
                    results.append(f"- Finding {fid}: retest initiated")
                except Exception as e:
                    results.append(f"- Finding {fid}: error - {e}")

            return f"Bulk Retest Results ({len(ids)} findings):\n" + "\n".join(results)
        except Exception as e:
            return f"Error in bulk retest: {e}"

    @mcp.tool()
    def bulk_update_finding_status(finding_ids: str, status: str) -> str:
        """Update the status of multiple findings at once.

        Args:
            finding_ids: Comma-separated finding IDs to update.
            status: The new status value to apply to all findings.
        """
        try:
            ids = [int(fid.strip()) for fid in finding_ids.split(",") if fid.strip()]
            if not ids:
                return "No valid finding IDs provided."

            client = get_api_client()
            findings_api = FindingsApi(client)
            VALID_STATUSES = {"confirmed", "unconfirmed", "remediated", "risk-accepted", "closed", "asset-no-longer-tracked"}
            status_lower = status.lower().strip()
            if status_lower not in VALID_STATUSES:
                return f"Invalid status '{status}'. Valid: {', '.join(sorted(VALID_STATUSES))}"
            body = UpdateClientFindingStatusRequestBody(status=status_lower)

            results = []
            for fid in ids:
                try:
                    findings_api.update_finding_status(
                        id=fid,
                        
                        update_client_finding_status_request_body=body,
                    )
                    results.append(f"- Finding {fid}: updated to {status_lower}")
                except Exception as e:
                    results.append(f"- Finding {fid}: error - {e}")

            return f"Bulk Status Update ({len(ids)} findings → {status_lower}):\n" + "\n".join(results)
        except Exception as e:
            return f"Error in bulk status update: {e}"

    @mcp.tool()
    def get_actionable_findings_queue(
        assignee: str = None,
        page_size: int = 30,
    ) -> str:
        """Prioritized queue of open findings sorted by severity then age, optionally filtered by assignee.

        Args:
            assignee: Filter by assignee name. Omit for all.
            page_size: Results per page (max 30).
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            lines = []

            all_findings = []
            for sev in SUMMARY_SEVERITIES:
                kwargs = {
                    "severities": sev,
                    "statuses": "confirmed",
                    "page_size": min(page_size, 30),
                }
                if assignee:
                    kwargs["assignee"] = assignee

                try:
                    resp = findings_api.get_list_findings(**kwargs)
                    if hasattr(resp, 'data') and resp.data:
                        for f in resp.data:
                            all_findings.append((severity_display(sev), f))
                except Exception:
                    pass

            if not all_findings:
                return "No actionable findings in queue." + (f" (assignee: {assignee})" if assignee else "")

            header = "Actionable Findings Queue"
            if assignee:
                header += f" (Assignee: {assignee})"
            lines.append(header)
            lines.append(f"Total: {len(all_findings)}")
            lines.append("")

            for idx, (sev, f) in enumerate(all_findings, 1):
                fid = getattr(f, 'id', '')
                title = getattr(f, 'title', 'No title')
                status = getattr(f, 'status', 'Unknown')
                created = getattr(f, 'created_at', '')
                lines.append(f"{idx}. [{sev}] {title}")
                lines.append(f"   ID: {fid} | Status: {status} | Created: {created}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating findings queue: {e}"

    @mcp.tool()
    def get_findings_needing_assignment(page_size: int = 30) -> str:
        """All open findings with no assignee, grouped by severity — the triage inbox.

        Args:
            page_size: Results per page per severity (max 30).
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)

            lines = ["Findings Needing Assignment:", ""]
            total_unassigned = 0

            for sev in SUMMARY_SEVERITIES:
                display_sev = severity_display(sev)
                try:
                    resp = findings_api.get_list_findings(
                        severities=sev,
                        statuses="confirmed",
                        assignee="No Assignee",
                        page_size=min(page_size, 30),
                    )
                    count = get_total(resp) or (len(resp.data) if hasattr(resp, 'data') and resp.data else 0)
                    total_unassigned += count

                    if count > 0:
                        lines.append(f"{display_sev} ({count}):")
                        if hasattr(resp, 'data') and resp.data:
                            for f in resp.data[:10]:
                                fid = getattr(f, 'id', '')
                                title = getattr(f, 'title', 'No title')
                                created = getattr(f, 'created_at', '')
                                lines.append(f"  - [ID:{fid}] {title} (since {created})")
                            if count > 10:
                                lines.append(f"  ... and {count - 10} more")
                        lines.append("")
                except Exception:
                    lines.append(f"{display_sev}: error")
                    lines.append("")

            lines.insert(1, f"Total Unassigned: {total_unassigned}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving unassigned findings: {e}"
