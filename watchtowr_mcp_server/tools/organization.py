import json

from watchtowr_api_sdk.api.source_ip_addresses_api import SourceIPAddressesApi
from watchtowr_api_sdk.api.activity_log_api import ActivityLogApi
from watchtowr_api_sdk.api.business_unit_api import BusinessUnitApi

from ..client import get_api_client, get_total, parse_date


def _format_log_field(value) -> str:
    """Format an activity log field that may be a dict, string, or other type."""
    if value is None:
        return ""
    if isinstance(value, dict):
        return json.dumps(value, default=str) if value else ""
    return str(value)


def _format_log_entry(log) -> str:
    timestamp = _format_log_field(getattr(log, 'created_at', None)) or 'Unknown time'
    description = _format_log_field(getattr(log, 'description', None)) or 'No description'
    log_type = _format_log_field(getattr(log, 'type', None))
    causer = getattr(log, 'caused_by', None)
    user = getattr(causer, 'name', 'System') if causer else 'System'
    type_str = f" [{log_type}]" if log_type else ""
    return f"• [{timestamp}] {user}: {description}{type_str}"


def register_organization_tools(mcp):

    @mcp.tool()
    def get_watchtowr_source_ips() -> str:
        """Get watchTowr Platform source IP addresses that should be whitelisted."""
        try:
            api = SourceIPAddressesApi(get_api_client())
            response = api.get_list_source_ip_addresses()

            data = getattr(response, 'data', None)
            if not data:
                return "No source IP addresses found."

            if isinstance(data, list):
                lines = []
                for item in data:
                    if isinstance(item, str):
                        lines.append(f"• {item}")
                        continue
                    name = getattr(item, 'name', None) or 'Unknown'
                    region = getattr(item, 'region', '')
                    desc = getattr(item, 'description', '')
                    whitelist = getattr(item, 'whitelist', None)
                    region_str = f" [{region}]" if region else ""
                    desc_str = f" — {desc.strip()}" if desc else ""
                    # whitelist tells the user whether this IP must be allow-listed.
                    if whitelist is True:
                        wl_str = " (whitelist required)"
                    elif whitelist is False:
                        wl_str = " (whitelist not required)"
                    else:
                        wl_str = ""
                    lines.append(f"• {name}{region_str}{desc_str}{wl_str}")
                return f"watchTowr Source IP Addresses ({len(lines)}):\n" + "\n".join(lines)
            return f"watchTowr Source IP Addresses: {data}"
        except Exception as e:
            return f"Error retrieving source IP addresses: {e}"

    @mcp.tool()
    def get_activity_logs(page: int = 1, page_size: int = 10) -> str:
        """Get recent activity logs from the watchTowr Platform.

        Args:
            page: Page number (defaults to 1).
            page_size: Number of results per page (max 30).
        """
        try:
            api = ActivityLogApi(get_api_client())
            response = api.get_list_activity_logs(
                page=page, page_size=min(page_size, 30)
            )

            if not hasattr(response, 'data') or not response.data:
                return "No activity logs found."

            total = get_total(response)
            lines = [_format_log_entry(log) for log in response.data]

            header = f"Activity Logs ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error retrieving activity logs: {e}"

    @mcp.tool()
    def search_activity_logs(
        search: str = None,
        types: str = None,
        user_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """Search activity logs with filters for type, user, keyword, and date range.

        Args:
            search: Search by description keyword.
            types: Comma-separated subject types.
            user_ids: Comma-separated user IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = ActivityLogApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search
            if types:
                # SDK types this as a comma-separated string (not a list).
                kwargs["types"] = types
            if user_ids:
                kwargs["user_ids"] = [u.strip() for u in user_ids.split(",")]
            if created_from:
                kwargs["created_from"] = parse_date(created_from)
            if created_to:
                kwargs["created_to"] = parse_date(created_to)

            response = api.get_list_activity_logs(**kwargs)

            if not hasattr(response, 'data') or not response.data:
                return "No activity logs match the criteria."

            total = get_total(response)
            lines = [_format_log_entry(log) for log in response.data]

            header = f"Activity Logs ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error searching activity logs: {e}"

    @mcp.tool()
    def list_business_units(
        search: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List business units. Useful for discovering BU IDs to filter other tools.

        Args:
            search: Search by business unit name.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = BusinessUnitApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search

            response = api.get_list_business_unit(**kwargs)

            if not hasattr(response, 'data') or not response.data:
                return "No business units found."

            total = get_total(response)
            lines = []
            for bu in response.data:
                buid = getattr(bu, 'id', '')
                name = getattr(bu, 'name', 'Unknown')
                lines.append(f"• [ID:{buid}] {name}")

            header = f"Business Units ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing business units: {e}"

    @mcp.tool()
    def get_business_unit_details(business_unit_id: int) -> str:
        """Get full details for a specific business unit.

        Args:
            business_unit_id: The business unit ID.
        """
        try:
            api = BusinessUnitApi(get_api_client())
            response = api.get_business_unit_details(id=business_unit_id)

            bu = response.data if hasattr(response, 'data') else response
            if not bu:
                return f"Business unit {business_unit_id} not found."

            lines = [
                f"Business Unit #{getattr(bu, 'id', business_unit_id)}",
                f"Name: {getattr(bu, 'name', 'N/A')}",
                f"Description: {getattr(bu, 'description', 'N/A')}",
                f"Type: {getattr(bu, 'type', 'N/A')}",
            ]

            parent_id = getattr(bu, 'parent_id', None)
            if parent_id is not None:
                lines.append(f"Parent BU: #{parent_id}")

            user_ids = getattr(bu, 'user_ids', None)
            if user_ids:
                lines.append(
                    f"Assigned Users ({len(user_ids)}): "
                    + ", ".join(str(uid) for uid in user_ids)
                )

            lines.append(f"Created: {getattr(bu, 'created_at', 'N/A')}")
            lines.append(f"Updated: {getattr(bu, 'updated_at', 'N/A')}")

            rules = getattr(bu, 'rules', None)
            if rules is not None:
                if isinstance(rules, dict):
                    rule_items = rules.get('data')
                    meta = (rules.get('meta') or {})
                    rule_total = meta.get('pagination', {}).get('total')
                else:
                    rule_items = getattr(rules, 'data', None)
                    meta = getattr(rules, 'meta', None)
                    pagination = getattr(meta, 'pagination', None) if meta else None
                    rule_total = getattr(pagination, 'total', None) if pagination else None

                if rule_total is not None:
                    lines.append(f"Rules: {rule_total}")
                elif isinstance(rule_items, list):
                    lines.append(f"Rules: {len(rule_items)}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving business unit details: {e}"
