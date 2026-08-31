from watchtowr_api_sdk.api.dns_record_analysis_api import DNSRecordAnalysisApi

from ...client import get_api_client, get_total, supported_kwargs


def register_asset_dns_tools(mcp):

    @mcp.tool()
    def get_asset_dns_records(
        asset_name: str,
        record_types: str = None,
        page: int = 1,
        page_size: int = 20,
    ) -> str:
        """Get DNS records associated with a specific asset by name.

        Args:
            asset_name: The asset name to look up (e.g. "example.com", "192.168.1.1").
            record_types: Comma-separated record types to filter (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = DNSRecordAnalysisApi(get_api_client())
            kwargs = {
                "page": page,
                "page_size": min(page_size, 30),
                "asset_name": asset_name,
            }
            if record_types:
                kwargs["record_types"] = record_types

            response = api.get_list_dns_records(
                **supported_kwargs(api.get_list_dns_records, kwargs)
            )

            if not hasattr(response, "data") or not response.data:
                return f"No DNS records found for {asset_name}."

            total = get_total(response) or 0
            lines = [f"DNS Records for {asset_name} ({len(response.data)} of {total}):"]
            lines.append("")
            lines.append(f"{'Type':<8}| {'Name':<30}| {'Value':<40}| TTL")
            lines.append("-" * 90)

            for record in response.data:
                rtype = getattr(record, "record_type", "") or getattr(record, "type", "")
                name = getattr(record, "record_name", "") or getattr(record, "name", "")
                value = getattr(record, "record_value", "") or getattr(record, "value", "")
                ttl = getattr(record, "ttl", "")
                lines.append(f"{rtype:<8}| {name:<30}| {value:<40}| {ttl}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.tool()
    def search_dns_records(
        record_name: str = None,
        record_value: str = None,
        record_types: str = None,
        business_unit_ids: str = None,
        start_date: str = None,
        end_date: str = None,
        sort_by: str = None,
        sort_order: str = None,
        page: int = 1,
        page_size: int = 20,
    ) -> str:
        """Search DNS records globally across all monitored assets.

        Args:
            record_name: Filter by record name (e.g. subdomain or domain).
            record_value: Filter by record value (e.g. IP address).
            record_types: Comma-separated record types (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV).
            business_unit_ids: Comma-separated business unit IDs.
            start_date: Start date filter (YYYY-MM-DD).
            end_date: End date filter (YYYY-MM-DD).
            sort_by: Sort field.
            sort_order: Sort direction (asc/desc).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = DNSRecordAnalysisApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if record_name:
                kwargs["record_name"] = record_name
            if record_value:
                kwargs["record_value"] = record_value
            if record_types:
                kwargs["record_types"] = record_types
            if business_unit_ids:
                kwargs["business_unit_ids"] = business_unit_ids
            if start_date:
                kwargs["start_date"] = start_date
            if end_date:
                kwargs["end_date"] = end_date
            if sort_by:
                kwargs["sort_by"] = sort_by
            if sort_order:
                kwargs["sort_order"] = sort_order

            response = api.get_list_dns_records(
                **supported_kwargs(api.get_list_dns_records, kwargs)
            )

            if not hasattr(response, "data") or not response.data:
                return "No DNS records found."

            total = get_total(response) or 0
            lines = [f"DNS Records (global search, {len(response.data)} of {total}):"]
            lines.append("")
            lines.append(f"{'Type':<8}| {'Name':<30}| {'Value':<40}| Asset")
            lines.append("-" * 90)

            for record in response.data:
                rtype = getattr(record, "record_type", "") or getattr(record, "type", "")
                name = getattr(record, "record_name", "") or getattr(record, "name", "")
                value = getattr(record, "record_value", "") or getattr(record, "value", "")
                asset_obj = getattr(record, "asset", None)
                asset_name_val = getattr(asset_obj, "name", "") if asset_obj else ""
                if asset_name_val:
                    asset = f"{asset_name_val} ({getattr(asset_obj, 'type', '')})"
                else:
                    asset = ""
                lines.append(f"{rtype:<8}| {name:<30}| {value:<40}| {asset}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"
