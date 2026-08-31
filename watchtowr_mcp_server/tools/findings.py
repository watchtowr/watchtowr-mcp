from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.models.update_client_finding_status_request_body import UpdateClientFindingStatusRequestBody

from ..client import get_api_client, get_total, normalize_severities, parse_date, severity_display
from ..constants import SUMMARY_SEVERITIES


def _affected_summary(finding) -> str | None:
    """Extract a one-line summary of the asset a finding affects.

    The SDK exposes `affected` as a dict shaped like {"data": {type, name, id,
    status, ...}}. Return None when no usable asset info is present.
    """
    affected = getattr(finding, 'affected', None)
    if not affected:
        return None
    data = affected.get('data') if isinstance(affected, dict) else getattr(affected, 'data', None)
    if not isinstance(data, dict):
        return None
    asset_type = data.get('type') or ''
    name = data.get('name') or data.get('url') or data.get('iprange') or ''
    asset_id = data.get('id')
    status = data.get('status') or ''
    if not (asset_type or name or asset_id):
        return None
    parts = []
    if name:
        parts.append(str(name))
    if asset_type:
        parts.append(f"[{asset_type}]")
    if asset_id is not None:
        parts.append(f"(ID:{asset_id})")
    if status:
        parts.append(f"- {status}")
    return " ".join(parts)


def _retest_lines(finding) -> list[str]:
    """Format retest progress + history into display lines (empty list if none)."""
    lines: list[str] = []
    retest = getattr(finding, 'retest', None)
    if retest:
        remaining = getattr(retest, 'retest_remaining', None)
        current = getattr(retest, 'current_retest', None)
        if remaining is not None:
            lines.append(f"Retests Remaining: {remaining}")
        if current:
            status = getattr(current, 'retest_status', 'N/A')
            requested_by = getattr(current, 'requested_by', '') or 'Unknown'
            requested_at = getattr(current, 'requested_at', '')
            completed_at = getattr(current, 'completed_at', None)
            line = f"Current Retest: {status} (requested by {requested_by}"
            if requested_at:
                line += f" at {requested_at}"
            line += ")"
            if completed_at:
                line += f" — completed {completed_at}"
            lines.append(line)

    history = getattr(finding, 'retest_history', None)
    if isinstance(history, list) and history:
        lines.append(f"Retest History ({len(history)}):")
        for r in history[:5]:
            status = getattr(r, 'retest_status', 'N/A')
            requested_at = getattr(r, 'requested_at', '')
            requested_by = getattr(r, 'requested_by', '') or 'Unknown'
            lines.append(f"  • {status} by {requested_by} at {requested_at}")
        if len(history) > 5:
            lines.append(f"  ... and {len(history) - 5} more")
    return lines


def _custom_property_lines(finding) -> list[str]:
    """Format custom properties (key=value) into display lines (empty if none)."""
    cps = getattr(finding, 'custom_properties', None)
    if not isinstance(cps, list) or not cps:
        return []
    pairs = []
    for cp in cps:
        if isinstance(cp, dict):
            key = cp.get('key')
            value = cp.get('value')
        else:
            key = getattr(cp, 'key', None)
            value = getattr(cp, 'value', None)
        if key is not None:
            pairs.append(f"{key}={value}")
    if not pairs:
        return []
    return [f"Custom Properties: {', '.join(pairs)}"]


def register_findings_tools(mcp):

    @mcp.tool()
    def list_cisa_kev_findings(page_size: int = 30) -> str:
        """List findings tagged as CISA-KEV (Known Exploited Vulnerabilities).

        Args:
            page_size: Number of results per page (max 30).
        """
        try:
            api = FindingsApi(get_api_client())
            response = api.get_list_findings(tags="CISA-KEV", page_size=min(page_size, 30))

            if not hasattr(response, 'data') or not response.data:
                return "No CISA-KEV findings found."

            total = get_total(response)
            lines = []
            for f in response.data:
                fid = getattr(f, 'id', '')
                severity = severity_display(getattr(f, 'severity', None))
                title = getattr(f, 'title', 'No title')
                status = getattr(f, 'status', 'Unknown')
                lines.append(f"• [ID:{fid}] [{severity}] {title} ({status})")

            header = f"CISA-KEV Findings ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error retrieving CISA-KEV findings: {e}"

    @mcp.tool()
    def list_findings_by_severity(severity: str = "Critical", page_size: int = 30) -> str:
        """List findings filtered by severity level.

        Args:
            severity: Severity level - Critical, High, Medium, or Low.
            page_size: Number of results per page (max 30).
        """
        try:
            api = FindingsApi(get_api_client())
            response = api.get_list_findings(
                severities=normalize_severities(severity),
                page_size=min(page_size, 30),
            )

            if not hasattr(response, 'data') or not response.data:
                return f"No {severity} severity findings found."

            total = get_total(response)
            lines = []
            for f in response.data:
                fid = getattr(f, 'id', '')
                title = getattr(f, 'title', 'No title')
                status = getattr(f, 'status', 'Unknown')
                lines.append(f"• [ID:{fid}] {title} ({status})")

            header = f"{severity} Severity Findings ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error retrieving {severity} findings: {e}"

    @mcp.tool()
    def get_finding_details(finding_id: int) -> str:
        """Get full details for a specific finding including description, evidence, CVSS, CVE, EPSS, and retest history.

        Args:
            finding_id: The finding ID to retrieve.
        """
        try:
            api = FindingsApi(get_api_client())
            response = api.get_finding_details(id=finding_id)

            finding = response.data if hasattr(response, 'data') else response
            if not finding:
                return f"Finding {finding_id} not found."

            lines = [f"Finding #{getattr(finding, 'id', finding_id)}"]
            lines.append(f"Title: {getattr(finding, 'title', 'N/A')}")
            lines.append(f"Severity: {severity_display(getattr(finding, 'severity', None))}")
            lines.append(f"Status: {getattr(finding, 'status', 'N/A')}")

            finding_impact = getattr(finding, 'finding_impact', None)
            if finding_impact:
                lines.append(f"Finding Impact: {finding_impact}")

            state = getattr(finding, 'state', None)
            lines.append(f"State: {state}")

            age = getattr(finding, 'age', None)
            lines.append(f"Age: {age} days" if age is not None else "Age: None")

            criticality = getattr(finding, 'criticality', None)
            lines.append(f"Criticality: {criticality}")

            last_seen = getattr(finding, 'last_seen', None)
            lines.append(f"Last Seen: {last_seen}")

            last_status_updated = getattr(finding, 'last_status_updated_at', None)
            if last_status_updated:
                lines.append(f"Last Status Update: {last_status_updated}")

            detection_rules = getattr(finding, 'detection_rules', None)
            if detection_rules:
                lines.append(f"\nDetection Rules ({len(detection_rules)}):")
                for rule in detection_rules[:5]:
                    title = rule.get('title', 'Unknown') if isinstance(rule, dict) else 'Unknown'
                    rule_type = rule.get('type', '') if isinstance(rule, dict) else ''
                    lines.append(f"  • [{rule_type}] {title}")

            affected = _affected_summary(finding)
            if affected:
                lines.append(f"Affected Asset: {affected}")

            cvss = getattr(finding, 'cvssv3_score', None)
            if cvss is not None:
                lines.append(f"CVSS v3: {cvss}")
                metrics = getattr(finding, 'cvssv3_metrics', None)
                if metrics:
                    lines.append(f"CVSS Metrics: {metrics}")

            cve = getattr(finding, 'cve_id', None)
            if cve:
                lines.append(f"CVE: {cve}")

            epss = getattr(finding, 'epss_score', None)
            if epss is not None:
                lines.append(f"EPSS Score: {epss}")

            desc = getattr(finding, 'description', None)
            if desc:
                lines.append(f"\nDescription:\n{desc}")

            impact = getattr(finding, 'impact', None)
            if impact:
                lines.append(f"\nImpact:\n{impact}")

            evidence = getattr(finding, 'evidence', None)
            if evidence:
                lines.append(f"\nEvidence:\n{evidence}")

            recommendation = getattr(finding, 'recommendation', None)
            if recommendation:
                lines.append(f"\nRecommendation:\n{recommendation}")

            references = getattr(finding, 'references', None)
            if references and references != "No references.":
                lines.append(f"\nReferences:\n{references}")

            tags = getattr(finding, 'tags', [])
            if tags:
                tag_names = [getattr(t, 'name', str(t)) for t in tags]
                lines.append(f"\nTags: {', '.join(tag_names)}")

            assignee = getattr(finding, 'assigned_user', None)
            if assignee:
                lines.append(f"Assigned to: {getattr(assignee, 'name', 'N/A')}")

            cp_lines = _custom_property_lines(finding)
            if cp_lines:
                lines.append("")
                lines.extend(cp_lines)

            retest_lines = _retest_lines(finding)
            if retest_lines:
                lines.append("")
                lines.append("Retest:")
                lines.extend(f"  {rl}" for rl in retest_lines)

            lines.append(f"Created: {getattr(finding, 'created_at', 'N/A')}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving finding details: {e}"

    @mcp.tool()
    def search_findings(
        finding_title: str = None,
        severities: str = None,
        statuses: str = None,
        asset_title: str = None,
        asset_types: str = None,
        assignee: str = None,
        tags: str = None,
        business_unit_ids: str = None,
        finding_impact_threshold: str = None,
        created_from: str = None,
        created_to: str = None,
        only_validated_exploitable: bool = None,
        exploitation_risk_level: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """Search findings with rich filters.

        Args:
            finding_title: Search by finding title keyword.
            severities: Comma-separated severities (Critical,High,Medium,Low).
            statuses: Comma-separated statuses.
            asset_title: Search by asset title.
            asset_types: Comma-separated asset types.
            assignee: Filter by assignee name. Use "No Assignee" for unassigned.
            tags: Comma-separated tags (e.g. "CISA-KEV").
            business_unit_ids: Comma-separated business unit IDs.
            finding_impact_threshold: Impact setting - "High" for prioritised findings or "All" for broader range.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            only_validated_exploitable: Filter to only show findings validated as exploitable.
            exploitation_risk_level: Filter by comma-separated risk levels.
            page: Page number (default 1).
            page_size: Results per page (max 30).
        """
        try:
            api = FindingsApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if finding_title:
                kwargs["finding_title"] = finding_title
            if severities:
                kwargs["severities"] = normalize_severities(severities)
            if statuses:
                kwargs["statuses"] = statuses
            if asset_title:
                kwargs["asset_title"] = asset_title
            if asset_types:
                kwargs["asset_types"] = asset_types
            if assignee:
                kwargs["assignee"] = assignee
            if tags:
                kwargs["tags"] = tags
            if business_unit_ids:
                kwargs["business_unit_ids"] = business_unit_ids
            if finding_impact_threshold:
                kwargs["finding_impact_threshold"] = finding_impact_threshold
            if created_from:
                kwargs["created_from"] = parse_date(created_from)
            if created_to:
                kwargs["created_to"] = parse_date(created_to)
            if only_validated_exploitable is not None:
                kwargs["only_validated_exploitable"] = only_validated_exploitable
            if exploitation_risk_level:
                kwargs["exploitation_risk_level"] = exploitation_risk_level

            response = api.get_list_findings(**kwargs)

            if not hasattr(response, 'data') or not response.data:
                return "No findings match the search criteria."

            total = get_total(response)
            lines = []
            for f in response.data:
                fid = getattr(f, 'id', '')
                sev = severity_display(getattr(f, 'severity', None))
                title = getattr(f, 'title', 'No title')
                status = getattr(f, 'status', 'Unknown')
                affected = _affected_summary(f)
                affected_str = f" → {affected}" if affected else ""
                lines.append(f"• [ID:{fid}] [{sev}] {title} ({status}){affected_str}")

            header = f"Findings ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error searching findings: {e}"

    @mcp.tool()
    def update_finding_status(finding_id: int, status: str) -> str:
        """Update the status of a finding. Use get_finding_statuses to see available values.

        Args:
            finding_id: The finding ID to update.
            status: The new status value.
        """
        try:
            api = FindingsApi(get_api_client())
            body = UpdateClientFindingStatusRequestBody(status=status)
            response = api.update_finding_status(
                id=finding_id,
                
                update_client_finding_status_request_body=body,
            )

            finding = response.data if hasattr(response, 'data') else response
            new_status = getattr(finding, 'status', status) if finding else status
            return f"Finding {finding_id} status updated to: {new_status}"
        except Exception as e:
            return f"Error updating finding status: {e}"

    @mcp.tool()
    def retest_finding(finding_id: int) -> str:
        """Trigger a retest for a specific finding to verify remediation.

        Args:
            finding_id: The finding ID to retest.
        """
        try:
            api = FindingsApi(get_api_client())
            response = api.start_specific_finding_retest(finding_id=finding_id)

            finding = response.data if hasattr(response, 'data') else response
            title = getattr(finding, 'title', '') if finding else ''
            return f"Retest initiated for finding {finding_id}" + (f" ({title})" if title else "")
        except Exception as e:
            return f"Error initiating retest: {e}"

    @mcp.tool()
    def get_finding_statuses() -> str:
        """List all available finding status values."""
        try:
            api = FindingsApi(get_api_client())
            response = api.get_available_finding_statuses()
            statuses = getattr(response, "data", [])
            
            if statuses and isinstance(statuses, list):
                # Handle nested list [["confirmed", ...]]
                first = statuses[0]
                status_list = first if isinstance(first, list) else statuses
                return "Available Finding Statuses:\n" + "\n".join(f"• {s}" for s in status_list)

            return f"Available Finding Statuses: {statuses}"
        except Exception as e:
            return f"Error retrieving finding statuses: {e}"

    @mcp.tool()
    def get_findings_summary_by_severity() -> str:
        """Get a count breakdown of findings by severity level."""
        try:
            api = FindingsApi(get_api_client())
            summary = {}
            for severity in SUMMARY_SEVERITIES:
                response = api.get_list_findings(severities=severity, page_size=1)
                count = get_total(response) or (len(response.data) if hasattr(response, 'data') and response.data else 0)
                summary[severity] = count

            total = sum(summary.values())
            lines = [f"Findings Summary (Total: {total}):"]
            for severity, count in summary.items():
                lines.append(f"• {severity_display(severity)}: {count}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error generating findings summary: {e}"

    @mcp.tool()
    def get_unresolved_findings_by_business_unit(
        business_unit_id: str,
        severities: str = None,
        page_size: int = 30,
    ) -> str:
        """List open/unresolved findings for a specific business unit.

        Excludes findings with status Remediated or Accepted Risk.

        Args:
            business_unit_id: The business unit ID.
            severities: Optional comma-separated severities to filter.
            page_size: Results per page (max 30).
        """
        try:
            api = FindingsApi(get_api_client())
            kwargs = {
                "business_unit_ids": business_unit_id,
                "statuses": "confirmed",
                "page_size": min(page_size, 30),
            }
            if severities:
                kwargs["severities"] = normalize_severities(severities)

            response = api.get_list_findings(**kwargs)

            if not hasattr(response, 'data') or not response.data:
                return f"No unresolved findings for business unit {business_unit_id}."

            total = get_total(response)
            lines = []
            for f in response.data:
                fid = getattr(f, 'id', '')
                sev = severity_display(getattr(f, 'severity', None))
                title = getattr(f, 'title', 'No title')
                status = getattr(f, 'status', 'Unknown')
                lines.append(f"• [ID:{fid}] [{sev}] {title} ({status})")

            header = f"Findings for BU {business_unit_id} ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error retrieving findings by business unit: {e}"

    @mcp.tool()
    def export_finding_pdf(finding_id: int) -> str:
        """Export a finding report as PDF.

        Args:
            finding_id: The finding ID to export.
        """
        try:
            api = FindingsApi(get_api_client())
            api.export_pdf_for_finding(id=finding_id)
            return f"PDF export initiated for finding {finding_id}. Check the watchTowr Platform for the download."
        except Exception as e:
            return f"Error exporting finding PDF: {e}"

    @mcp.tool()
    def update_finding_state(finding_id: int, state: str) -> str:
        """Update the handling state of a finding (e.g. Uninvestigated, In Progress, Completed).

        Args:
            finding_id: The finding ID to update.
            state: The new state value ('Uninvestigated', 'In Progress', 'Completed').
        """
        try:
            from watchtowr_api_sdk.models.update_client_finding_state_request_body import UpdateClientFindingStateRequestBody
            api = FindingsApi(get_api_client())
            body = UpdateClientFindingStateRequestBody(state=state)
            response = api.update_finding_state(
                id=finding_id,
                update_client_finding_state_request_body=body,
            )
            finding = response.data if hasattr(response, 'data') else response
            new_state = getattr(finding, 'state', state) if finding else state
            return f"Finding {finding_id} state updated to: {new_state}"
        except Exception as e:
            return f"Error updating finding state: {e}"
