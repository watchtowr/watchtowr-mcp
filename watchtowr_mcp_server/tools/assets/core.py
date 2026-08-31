from watchtowr_api_sdk.api.ip_addresses_api import IPAddressesApi
from watchtowr_api_sdk.api.domains_api import DomainsApi
from watchtowr_api_sdk.api.subdomains_api import SubdomainsApi
from watchtowr_api_sdk.api.ports_api import PortsApi
from watchtowr_api_sdk.api.ip_ranges_api import IPRangesApi
from watchtowr_api_sdk.api.cloud_storage_api import CloudStorageApi
from watchtowr_api_sdk.api.repositories_api import RepositoriesApi
from watchtowr_api_sdk.api.containers_api import ContainersApi
from watchtowr_api_sdk.api.saa_s_platforms_api import SaaSPlatformsApi
from watchtowr_api_sdk.api.mobile_applications_api import MobileApplicationsApi
from watchtowr_api_sdk.api.cloud_integration_assets_api import CloudIntegrationAssetsApi
from watchtowr_api_sdk.api.api_documentation_api import APIDocumentationApi
from watchtowr_api_sdk.api.package_managers_api import PackageManagersApi
from watchtowr_api_sdk.api.add_asset_api import AddAssetApi
from watchtowr_api_sdk.models.update_client_legacy_asset_status_dto import UpdateClientLegacyAssetStatusDto
from watchtowr_api_sdk.models.update_client_next_gen_asset_status_dto import UpdateClientNextGenAssetStatusDto
from watchtowr_api_sdk.models.update_client_cloud_asset_status_dto import UpdateClientCloudAssetStatusDto
from watchtowr_api_sdk.models.update_api_documentation_status_dto import UpdateApiDocumentationStatusDto
from watchtowr_api_sdk.models.create_client_seed_data_request_body import CreateClientSeedDataRequestBody
from watchtowr_api_sdk.models.client_seed_data_dto import ClientSeedDataDto
from watchtowr_api_sdk.models.update_client_engine_settings_dto import UpdateClientEngineSettingsDto
from watchtowr_api_sdk.models.set_criticality_dto import SetCriticalityDto
from watchtowr_api_sdk.models.asset_business_unit_ids_dto import AssetBusinessUnitIdsDTO
from watchtowr_api_sdk.models.hostname_business_unit_ids_dto import HostnameBusinessUnitIDsDTO
from watchtowr_api_sdk.models.create_client_custom_property_dto import CreateClientCustomPropertyDto
from watchtowr_api_sdk.models.update_client_custom_property_dto import UpdateClientCustomPropertyDto
from watchtowr_api_sdk.models.create_client_note_dto import CreateClientNoteDto
from watchtowr_api_sdk.models.ip_range_values import IpRangeValues
from watchtowr_api_sdk.models.filter_by_business_unit_input import FilterByBusinessUnitInput

from ...client import get_api_client, get_total, parse_date, format_bus, supported_kwargs


VALID_SEED_ASSET_TYPES = [
    "domain", "subdomain", "ip", "ipRange", "repository",
    "cloudStorage", "container", "mobileApp", "saasPlatform",
    "apiDocumentation", "packageManager",
]

ALL_ASSET_TYPES = [
    "domain", "subdomain", "ip", "ipRange", "cloudStorage", "container",
    "repository", "mobileApp", "saasPlatform", "cloudAsset", "apiDocumentation",
    "packageManager",
]

ENGINE_SETTINGS_TYPES = ["domain", "subdomain", "ip"]
CRITICALITY_VALUES = ["High", "Medium", "Low", "Unknown"]

ASSET_API_CLASSES = {
    "domain": DomainsApi,
    "subdomain": SubdomainsApi,
    "ip": IPAddressesApi,
    "ipRange": IPRangesApi,
    "cloudStorage": CloudStorageApi,
    "container": ContainersApi,
    "repository": RepositoriesApi,
    "mobileApp": MobileApplicationsApi,
    "saasPlatform": SaaSPlatformsApi,
    "cloudAsset": CloudIntegrationAssetsApi,
    "apiDocumentation": APIDocumentationApi,
    "packageManager": PackageManagersApi,
}

ENGINE_SETTINGS_METHODS = {
    "domain": {"get": "get_asset_domain_engine_settings", "update": "update_asset_domain_engine_settings"},
    "subdomain": {"get": "get_asset_subdomain_engine_settings", "update": "update_asset_subdomain_engine_settings"},
    "ip": {"get": "get_asset_ip_engine_settings", "update": "update_asset_ip_engine_settings"},
}

CRITICALITY_METHODS = {
    "domain": "set_criticality_domain",
    "subdomain": "set_criticality_subdomain",
    "ip": "set_criticality_ip",
    "ipRange": "set_criticality_ip_range",
    "cloudStorage": "set_criticality_cloud_storage",
    "container": "set_criticality_container",
    "repository": "set_criticality_repository",
    "mobileApp": "set_criticality_mobile_app",
    "saasPlatform": "set_criticality_saas_platform",
    "cloudAsset": "set_criticality_cloud_asset",
    "apiDocumentation": "set_criticality_api_documentation",
    "packageManager": "set_criticality_package_manager",
}

BUSINESS_UNIT_METHODS = {
    "domain": {"assign": "assign_domain_to_business_units", "unassign": "unassign_domain_from_business_units"},
    "subdomain": {"assign": "assign_subomain_to_business_units", "unassign": "unassign_subomain_from_business_units"},
    "ip": {"assign": "assign_ip_to_business_units", "unassign": "unassign_ip_from_business_units"},
    "ipRange": {"assign": "assign_ip_range_to_business_units", "unassign": "unassign_ip_range_from_business_units"},
    "cloudStorage": {"assign": "assign_cloud_storage_to_business_units", "unassign": "unassign_cloud_storage_from_business_units"},
    "container": {"assign": "assign_container_to_business_units", "unassign": "unassign_container_from_business_units"},
    "repository": {"assign": "assign_repository_to_business_units", "unassign": "unassign_repository_from_business_units"},
    "mobileApp": {"assign": "assign_mobile_app_to_business_units", "unassign": "unassign_mobile_app_from_business_units"},
    "saasPlatform": {"assign": "assign_saas_platform_to_business_units", "unassign": "unassign_saas_platform_from_business_units"},
    "cloudAsset": {"assign": "assign_cloud_asset_to_business_units", "unassign": "unassign_cloud_asset_from_business_units"},
    "apiDocumentation": {"assign": "assign_api_documentation_to_business_units", "unassign": "unassign_api_documentation_from_business_units"},
    "packageManager": {"assign": "assign_package_manager_to_business_units", "unassign": "unassign_package_manager_from_business_units"},
}

CUSTOM_PROPERTY_METHODS = {
    "domain": {"list": "get_custom_properties_domain", "create": "create_custom_property_domain", "update": "update_custom_property_domain", "delete": "delete_custom_property_domain"},
    "subdomain": {"list": "get_custom_properties_subdomain", "create": "create_custom_property_subdomain", "update": "update_custom_property_subdomain", "delete": "delete_custom_property_subdomain"},
    "ip": {"list": "get_custom_properties_ip", "create": "create_custom_property_ip", "update": "update_custom_property_ip", "delete": "delete_custom_property_ip"},
    "ipRange": {"list": "get_custom_properties_ip_range", "create": "create_custom_property_ip_range", "update": "update_custom_property_ip_range", "delete": "delete_custom_property_ip_range"},
    "cloudStorage": {"list": "get_custom_properties_cloud_storage", "create": "create_custom_property_cloud_storage", "update": "update_custom_property_cloud_storage", "delete": "delete_custom_property_cloud_storage"},
    "container": {"list": "get_custom_properties_container", "create": "create_custom_property_container", "update": "update_custom_property_container", "delete": "delete_custom_property_container"},
    "repository": {"list": "get_custom_properties_repository", "create": "create_custom_property_repository", "update": "update_custom_property_repository", "delete": "delete_custom_property_repository"},
    "mobileApp": {"list": "get_custom_properties_mobile_app", "create": "create_custom_property_mobile_app", "update": "update_custom_property_mobile_app", "delete": "delete_custom_property_mobile_app"},
    "saasPlatform": {"list": "get_custom_properties_saas_platform", "create": "create_custom_property_saas_platform", "update": "update_custom_property_saas_platform", "delete": "delete_custom_property_saas_platform"},
    "cloudAsset": {"list": "get_custom_properties_cloud_asset", "create": "create_custom_property_cloud_asset", "update": "update_custom_property_cloud_asset", "delete": "delete_custom_property_cloud_asset"},
    "apiDocumentation": {"list": "get_custom_properties_api_documentation", "create": "create_custom_property_api_documentation", "update": "update_custom_property_api_documentation", "delete": "delete_custom_property_api_documentation"},
    "packageManager": {"list": "get_custom_properties_package_manager", "create": "create_custom_property_package_manager", "update": "update_custom_property_package_manager", "delete": "delete_custom_property_by_id"},
}

NOTES_METHODS = {
    "domain": {"list": "get_asset_domain_notes", "create": "create_asset_domain_note", "update": "update_asset_domain_note", "delete": "delete_asset_domain_note"},
    "subdomain": {"list": "get_notes_subdomain", "create": "create_note_subdomain", "update": "update_note_subdomain", "delete": "delete_note_subdomain"},
    "ip": {"list": "get_asset_ip_notes", "create": "create_asset_ip_note", "update": "update_asset_ip_note", "delete": "delete_asset_ip_note"},
    "ipRange": {"list": "get_asset_ip_range_notes", "create": "create_note_ip_range", "update": "update_note_ip_range", "delete": "delete_note_ip_range"},
    "cloudStorage": {"list": "get_asset_cloud_storage_notes", "create": "add_asset_cloud_storage_note", "update": "update_asset_cloud_storage_note", "delete": "delete_asset_cloud_storage_note"},
    "container": {"list": "get_asset_container_notes", "create": "create_note_container", "update": "update_note_container", "delete": "delete_note_container"},
    "repository": {"list": "get_asset_repository_notes", "create": "create_note_repository", "update": "update_note_repository", "delete": "delete_note_repository"},
    "mobileApp": {"list": "get_asset_mobile_app_notes", "create": "create_note_mobile_app", "update": "update_note_mobile_app", "delete": "delete_note_mobile_app"},
    "saasPlatform": {"list": "get_asset_saas_platform_notes", "create": "create_note_saas_platform", "update": "update_note_saas_platform", "delete": "delete_note_saas_platform"},
    "cloudAsset": {"list": "get_asset_cloud_asset_notes", "create": "add_asset_cloud_asset_note", "update": "update_asset_cloud_asset_note", "delete": "delete_asset_cloud_asset_note"},
    "apiDocumentation": {"list": "get_asset_api_documentation_notes", "create": "add_asset_api_documentation_note", "update": "update_asset_api_documentation_note", "delete": "delete_asset_api_documentation_note"},
    "packageManager": {"list": "get_asset_package_manager_notes", "create": "add_asset_package_manager_note", "update": "update_asset_package_manager_note", "delete": "delete_asset_package_manager_note"},
}


def _unsupported_asset_error(capability, asset_type, supported):
    return (
        f"Error: {capability} not supported for asset type '{asset_type}'. "
        f"Supported types: {', '.join(supported)}"
    )


def _validate_asset_type(asset_type):
    if asset_type not in ALL_ASSET_TYPES:
        return f"Error: Invalid asset_type '{asset_type}'. Valid types: {', '.join(ALL_ASSET_TYPES)}"
    return None


def _unwrap_data(response):
    return response.data if hasattr(response, "data") else response


def _format_bool(value):
    return "enabled" if value else "disabled"


def _format_engine_settings(asset_type, asset_id, settings):
    fields = [
        ("Adversary Sight", "adversary_sight_enabled"),
        ("DNS Bruteforcing", "dns_bruteforcing_enabled"),
        ("Automated Red Teaming", "automated_red_teaming_enabled"),
        ("Intrusive HTTP Checks", "intrusive_http_checks_enabled"),
        ("Credential Stuffing", "credential_stuffing_enabled"),
        ("Rapid Reaction", "rapid_reaction_enabled"),
    ]
    lines = [f"✓ Engine settings for {asset_type} #{asset_id}:"]
    for label, attr in fields:
        lines.append(f"  • {label}: {_format_bool(getattr(settings, attr, False))}")
    return "\n".join(lines)


def _format_custom_properties(asset_type, asset_id, response, page):
    items = _unwrap_data(response) or []
    if not items:
        return f"No custom properties found for {asset_type} #{asset_id}."
    lines = [f"Custom properties for {asset_type} #{asset_id} (page {page or 1}):"]
    for item in items:
        lines.append(
            f"  • [ID: {getattr(item, 'id', 'N/A')}] "
            f"{getattr(item, 'key', 'N/A')} = {getattr(item, 'value', '')} "
            f"(preset: {str(getattr(item, 'is_preset', False)).lower()})"
        )
    return "\n".join(lines)


def _format_notes(asset_type, asset_id, response, page):
    items = _unwrap_data(response) or []
    if not items:
        return f"No notes found for {asset_type} #{asset_id}."
    lines = [f"Notes for {asset_type} #{asset_id} (page {page or 1}):"]
    for item in items:
        title = getattr(item, "title", "") or "Untitled"
        note = getattr(item, "note", "") or ""
        author = getattr(getattr(item, "author", None), "name", None) or "Unknown"
        created = getattr(item, "last_modified", "N/A")
        lines.append(f"  • [ID: {getattr(item, 'id', 'N/A')}] \"{title}\" - {note[:80]} (by {author}, {created})")
    return "\n".join(lines)

def _build_asset_kwargs(page, page_size, asset_name=None, statuses=None,
                        business_unit_ids=None, created_from=None, created_to=None,
                        source=None,
                        custom_property_key=None, custom_property_value=None):
    kwargs = {"page": page, "page_size": min(page_size, 30)}
    if asset_name:
        kwargs["asset_name"] = asset_name
    if statuses:
        kwargs["statuses"] = [s.strip() for s in statuses.split(",")]
    if business_unit_ids:
        kwargs["business_unit_ids"] = business_unit_ids
    if created_from:
        kwargs["created_from"] = parse_date(created_from)
    if created_to:
        kwargs["created_to"] = parse_date(created_to)
    if source:
        kwargs["source"] = source
    if custom_property_key:
        kwargs["custom_property_key"] = custom_property_key
    if custom_property_value:
        kwargs["custom_property_value"] = custom_property_value
    return kwargs


def register_asset_core_tools(mcp):

    # ── IP Addresses ──────────────────────────────────────────────

    @mcp.tool()
    def list_asset_ips(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        match_type: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered IP addresses.

        Args:
            asset_name: Search by IP address (partial or full match).
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            match_type: Filter by match type ('exact' or 'partial').
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = IPAddressesApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            if match_type:
                kwargs["match_type"] = match_type
            response = api.get_list_asset_ips(**supported_kwargs(api.get_list_asset_ips, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No IP addresses found."

            total = get_total(response)
            lines = []
            for ip in response.data:
                iid = getattr(ip, 'id', '')
                name = getattr(ip, 'name', 'Unknown')
                status = getattr(ip, 'status', 'Unknown')
                country = getattr(ip, 'country', '')
                live = " (live)" if getattr(ip, 'live', False) else ""
                country_str = f" [{country}]" if country else ""
                bus = format_bus(getattr(ip, 'business_units', []))
                lines.append(f"• [ID:{iid}] {name} - {status}{live}{country_str}{bus}")

            header = f"IP Addresses ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing IP addresses: {e}"

    @mcp.tool()
    def get_asset_ip_details(ip_id: int) -> str:
        """Get full details for a specific IP address asset.

        Args:
            ip_id: The IP address asset ID.
        """
        try:
            api = IPAddressesApi(get_api_client())
            response = api.get_asset_ip_details(id=ip_id)

            ip = response.data if hasattr(response, 'data') else response
            if not ip:
                return f"IP address {ip_id} not found."

            lines = [
                f"IP Address #{getattr(ip, 'id', ip_id)}",
                f"Name: {getattr(ip, 'name', 'N/A')}",
                f"Status: {getattr(ip, 'status', 'N/A')}",
                f"Source: {getattr(ip, 'source', 'N/A')}",
                f"Live: {getattr(ip, 'live', 'N/A')}",
                f"Country: {getattr(ip, 'country', 'N/A')}",
                f"Created: {getattr(ip, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(ip, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(ip, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(ip, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving IP address details: {e}"

    @mcp.tool()
    def list_ports_for_ip(
        ip_id: int,
        include_closed_port: bool = None,
        include_no_service: bool = None,
        created_from: str = None,
        created_to: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List all discovered ports belonging to a specific IP address.

        Args:
            ip_id: The IP address asset ID.
            include_closed_port: Include listings with closed ports.
            include_no_service: Include listings without a service.
            created_from: Filter ports created after a given date and time.
            created_to: Filter ports created before a given date and time.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = IPAddressesApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if include_closed_port is not None:
                kwargs["include_closed_port"] = include_closed_port
            if include_no_service is not None:
                kwargs["include_no_service"] = include_no_service
            if created_from:
                kwargs["created_from"] = parse_date(created_from)
            if created_to:
                kwargs["created_to"] = parse_date(created_to)
            response = api.get_asset_ip_ports(id=ip_id, **supported_kwargs(api.get_asset_ip_ports, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return f"No ports found for IP {ip_id}."

            total = get_total(response)
            lines = []
            for p in response.data:
                pid = getattr(p, 'id', '')
                port = getattr(p, 'port', '?')
                service = getattr(p, 'service', '')
                banner = getattr(p, 'banner', '')
                status = getattr(p, 'status', '')
                svc_str = f" ({service})" if service else ""
                banner_str = f" - {banner}" if banner else ""
                lines.append(f"• [ID:{pid}] :{port}{svc_str} {status}{banner_str}")

            header = f"Ports for IP {ip_id} ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing ports for IP: {e}"

    @mcp.tool()
    def get_ip_port_details(ip_id: int, port_id: int) -> str:
        """Get full details for a specific port belonging to an IP address.

        Args:
            ip_id: The IP address asset ID (as string).
            port_id: The port asset ID (as string).
        """
        try:
            api = IPAddressesApi(get_api_client())
            response = api.get_asset_ip_port_details(
                ip_id=int(ip_id), port_id=int(port_id)
            )

            p = response.data if hasattr(response, 'data') else response
            if not p:
                return f"Port {port_id} on IP {ip_id} not found."

            lines = [
                f"Port #{getattr(p, 'id', port_id)} on IP {ip_id}",
                f"Port: {getattr(p, 'port', 'N/A')}",
                f"IP: {getattr(p, 'ip', 'N/A')}",
                f"Service: {getattr(p, 'service', 'N/A')}",
                f"Banner: {getattr(p, 'banner', 'N/A')}",
                f"Status: {getattr(p, 'status', 'N/A')}",
                f"Created: {getattr(p, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(p, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving IP port details: {e}"

    # ── Domains ───────────────────────────────────────────────────

    @mcp.tool()
    def list_asset_domains(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered root domains.

        Args:
            asset_name: Search by domain name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = DomainsApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_domains(**supported_kwargs(api.get_list_asset_domains, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No domains found."

            total = get_total(response)
            lines = []
            for d in response.data:
                did = getattr(d, 'id', '')
                name = getattr(d, 'name', 'Unknown')
                status = getattr(d, 'status', 'Unknown')
                live = " (live)" if getattr(d, 'live', False) else ""
                bus = format_bus(getattr(d, 'business_units', []))
                lines.append(f"• [ID:{did}] {name} - {status}{live}{bus}")

            header = f"Domains ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing domains: {e}"

    @mcp.tool()
    def get_asset_domain_details(domain_id: int) -> str:
        """Get full details for a specific domain.

        Args:
            domain_id: The domain asset ID.
        """
        try:
            api = DomainsApi(get_api_client())
            response = api.get_asset_domain_details(id=int(domain_id))

            d = response.data if hasattr(response, 'data') else response
            if not d:
                return f"Domain {domain_id} not found."

            lines = [
                f"Domain #{getattr(d, 'id', domain_id)}",
                f"Name: {getattr(d, 'name', 'N/A')}",
                f"Status: {getattr(d, 'status', 'N/A')}",
                f"Source: {getattr(d, 'source', 'N/A')}",
                f"Live: {getattr(d, 'live', 'N/A')}",
                f"Created: {getattr(d, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(d, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(d, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(d, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving domain details: {e}"

    # ── Subdomains ────────────────────────────────────────────────

    @mcp.tool()
    def list_asset_subdomains(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered subdomains.

        Args:
            asset_name: Search by subdomain name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = SubdomainsApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_subdomains(**supported_kwargs(api.get_list_asset_subdomains, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No subdomains found."

            total = get_total(response)
            lines = []
            for s in response.data:
                sid = getattr(s, 'id', '')
                name = getattr(s, 'name', 'Unknown')
                status = getattr(s, 'status', 'Unknown')
                live = " (live)" if getattr(s, 'live', False) else ""
                bus = format_bus(getattr(s, 'business_units', []))
                lines.append(f"• [ID:{sid}] {name} - {status}{live}{bus}")

            header = f"Subdomains ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing subdomains: {e}"

    @mcp.tool()
    def get_asset_subdomain_details(subdomain_id: int) -> str:
        """Get full details for a specific subdomain.

        Args:
            subdomain_id: The subdomain asset ID.
        """
        try:
            api = SubdomainsApi(get_api_client())
            response = api.get_asset_subdomain_details(id=int(subdomain_id))

            s = response.data if hasattr(response, 'data') else response
            if not s:
                return f"Subdomain {subdomain_id} not found."

            lines = [
                f"Subdomain #{getattr(s, 'id', subdomain_id)}",
                f"Name: {getattr(s, 'name', 'N/A')}",
                f"Status: {getattr(s, 'status', 'N/A')}",
                f"Source: {getattr(s, 'source', 'N/A')}",
                f"Live: {getattr(s, 'live', 'N/A')}",
                f"Created: {getattr(s, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(s, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(s, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(s, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving subdomain details: {e}"

    # ── Ports ─────────────────────────────────────────────────────

    @mcp.tool()
    def list_asset_ports(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        include_closed_port: bool = None,
        include_no_service: bool = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered open ports across assets.

        Args:
            asset_name: Search by asset name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            include_closed_port: Include listings with closed ports.
            include_no_service: Include listings without a service.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = PortsApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            if include_closed_port is not None:
                kwargs["include_closed_port"] = include_closed_port
            if include_no_service is not None:
                kwargs["include_no_service"] = include_no_service
            response = api.get_list_asset_ports(**supported_kwargs(api.get_list_asset_ports, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No ports found."

            total = get_total(response)
            lines = []
            for p in response.data:
                pid = getattr(p, 'id', '')
                ip = getattr(p, 'ip', 'Unknown')
                port = getattr(p, 'port', '?')
                service = getattr(p, 'service', '')
                banner = getattr(p, 'banner', '')
                svc_str = f" ({service})" if service else ""
                banner_str = f" - {banner}" if banner else ""
                lines.append(f"• [ID:{pid}] {ip}:{port}{svc_str}{banner_str}")

            header = f"Ports ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing ports: {e}"

    @mcp.tool()
    def get_asset_port_details(port_id: int) -> str:
        """Get full details for a specific port including banner and service.

        Args:
            port_id: The port asset ID.
        """
        try:
            api = PortsApi(get_api_client())
            response = api.get_asset_port_details(id=int(port_id))

            p = response.data if hasattr(response, 'data') else response
            if not p:
                return f"Port {port_id} not found."

            lines = [
                f"Port #{getattr(p, 'id', port_id)}",
                f"IP: {getattr(p, 'ip', 'N/A')}",
                f"Port: {getattr(p, 'port', 'N/A')}",
                f"Service: {getattr(p, 'service', 'N/A')}",
                f"Banner: {getattr(p, 'banner', 'N/A')}",
                f"Status: {getattr(p, 'status', 'N/A')}",
                f"Created: {getattr(p, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(p, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving port details: {e}"

    # ── IP Ranges ─────────────────────────────────────────────────

    @mcp.tool()
    def list_asset_ip_ranges(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered IP ranges with ASN and country information.

        Args:
            asset_name: Search by IP range.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = IPRangesApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_ipranges(**supported_kwargs(api.get_list_asset_ipranges, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No IP ranges found."

            total = get_total(response)
            lines = []
            for r in response.data:
                rid = getattr(r, 'id', '')
                iprange = getattr(r, 'iprange', 'Unknown')
                asn = getattr(r, 'asn', '')
                desc = getattr(r, 'desc', '')
                country = getattr(r, 'country', '')
                status = getattr(r, 'status', 'Unknown')
                extras = []
                if asn:
                    extras.append(f"ASN:{asn}")
                if country:
                    extras.append(country)
                if desc:
                    extras.append(desc)
                extra_str = f" ({', '.join(extras)})" if extras else ""
                lines.append(f"• [ID:{rid}] {iprange} - {status}{extra_str}")

            header = f"IP Ranges ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing IP ranges: {e}"

    @mcp.tool()
    def get_asset_iprange_details(iprange_id: int) -> str:
        """Get full details for a specific IP range.

        Args:
            iprange_id: The IP range asset ID.
        """
        try:
            api = IPRangesApi(get_api_client())
            response = api.get_asset_iprange_details(id=int(iprange_id))

            r = response.data if hasattr(response, 'data') else response
            if not r:
                return f"IP range {iprange_id} not found."

            lines = [
                f"IP Range #{getattr(r, 'id', iprange_id)}",
                f"Range: {getattr(r, 'iprange', 'N/A')}",
                f"ASN: {getattr(r, 'asn', 'N/A')}",
                f"Description: {getattr(r, 'desc', 'N/A')}",
                f"Country: {getattr(r, 'country', 'N/A')}",
                f"Status: {getattr(r, 'status', 'N/A')}",
                f"Source: {getattr(r, 'source', 'N/A')}",
                f"Created: {getattr(r, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(r, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(r, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(r, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving IP range details: {e}"

    # ── Cloud Storage ─────────────────────────────────────────────

    @mcp.tool()
    def list_cloud_storage_assets(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered cloud storage assets (S3, GCS, Azure blobs, etc.).

        Args:
            asset_name: Search by storage URL keyword.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = CloudStorageApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_cloud_storages(**supported_kwargs(api.get_list_asset_cloud_storages, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No cloud storage assets found."

            total = get_total(response)
            lines = []
            for cs in response.data:
                csid = getattr(cs, 'id', '')
                name = getattr(cs, 'name', 'Unknown')
                platform = getattr(cs, 'platform', '')
                url = getattr(cs, 'url', '')
                status = getattr(cs, 'status', 'Unknown')
                bus = format_bus(getattr(cs, 'business_units', []))
                plat_str = f" [{platform}]" if platform else ""
                url_str = f" {url}" if url else ""
                lines.append(f"• [ID:{csid}] {name}{plat_str} - {status}{url_str}{bus}")

            header = f"Cloud Storage Assets ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing cloud storage assets: {e}"

    @mcp.tool()
    def get_asset_cloud_storage_details(cloud_storage_id: int) -> str:
        """Get full details for a specific cloud storage asset.

        Args:
            cloud_storage_id: The cloud storage asset ID.
        """
        try:
            api = CloudStorageApi(get_api_client())
            response = api.get_asset_cloud_storage_details(
                id=int(cloud_storage_id)
            )

            cs = response.data if hasattr(response, 'data') else response
            if not cs:
                return f"Cloud storage asset {cloud_storage_id} not found."

            lines = [
                f"Cloud Storage #{getattr(cs, 'id', cloud_storage_id)}",
                f"Name: {getattr(cs, 'name', 'N/A')}",
                f"Platform: {getattr(cs, 'platform', 'N/A')}",
                f"URL: {getattr(cs, 'url', 'N/A')}",
                f"Status: {getattr(cs, 'status', 'N/A')}",
                f"Source: {getattr(cs, 'source', 'N/A')}",
                f"Created: {getattr(cs, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(cs, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(cs, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(cs, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving cloud storage details: {e}"

    # ── Source Code Repositories ──────────────────────────────────

    @mcp.tool()
    def list_source_code_repositories(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered source code repositories.

        Args:
            asset_name: Search by repository name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = RepositoriesApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_repositories(**supported_kwargs(api.get_list_asset_repositories, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No source code repositories found."

            total = get_total(response)
            lines = []
            for r in response.data:
                rid = getattr(r, 'id', '')
                name = getattr(r, 'name', 'Unknown')
                owner = getattr(r, 'owner', '')
                provider = getattr(r, 'provider', '')
                status = getattr(r, 'status', 'Unknown')
                bus = format_bus(getattr(r, 'business_units', []))
                owner_str = f" ({owner})" if owner else ""
                prov_str = f" [{provider}]" if provider else ""
                lines.append(f"• [ID:{rid}] {name}{owner_str}{prov_str} - {status}{bus}")

            header = f"Source Code Repositories ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing repositories: {e}"

    @mcp.tool()
    def get_asset_repository_details(repository_id: int) -> str:
        """Get full details for a specific source code repository.

        Args:
            repository_id: The repository asset ID.
        """
        try:
            api = RepositoriesApi(get_api_client())
            response = api.get_asset_repository_details(
                id=int(repository_id)
            )

            r = response.data if hasattr(response, 'data') else response
            if not r:
                return f"Repository {repository_id} not found."

            lines = [
                f"Repository #{getattr(r, 'id', repository_id)}",
                f"Name: {getattr(r, 'name', 'N/A')}",
                f"Owner: {getattr(r, 'owner', 'N/A')}",
                f"Provider: {getattr(r, 'provider', 'N/A')}",
                f"Status: {getattr(r, 'status', 'N/A')}",
                f"Source: {getattr(r, 'source', 'N/A')}",
                f"Created: {getattr(r, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(r, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(r, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(r, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving repository details: {e}"

    # ── Containers ────────────────────────────────────────────────

    @mcp.tool()
    def list_container_assets(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered container registry images.

        Args:
            asset_name: Search by container name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = ContainersApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_container(**supported_kwargs(api.get_list_asset_container, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No container assets found."

            total = get_total(response)
            lines = []
            for c in response.data:
                cid = getattr(c, 'id', '')
                name = getattr(c, 'name', 'Unknown')
                owner = getattr(c, 'owner', '')
                platform = getattr(c, 'platform', '')
                status = getattr(c, 'status', 'Unknown')
                bus = format_bus(getattr(c, 'business_units', []))
                owner_str = f" ({owner})" if owner else ""
                plat_str = f" [{platform}]" if platform else ""
                lines.append(f"• [ID:{cid}] {name}{owner_str}{plat_str} - {status}{bus}")

            header = f"Container Assets ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing container assets: {e}"

    @mcp.tool()
    def get_asset_container_details(container_id: int) -> str:
        """Get full details for a specific container registry image.

        Args:
            container_id: The container asset ID.
        """
        try:
            api = ContainersApi(get_api_client())
            response = api.get_asset_container_details(
                id=int(container_id)
            )

            c = response.data if hasattr(response, 'data') else response
            if not c:
                return f"Container {container_id} not found."

            lines = [
                f"Container #{getattr(c, 'id', container_id)}",
                f"Name: {getattr(c, 'name', 'N/A')}",
                f"Owner: {getattr(c, 'owner', 'N/A')}",
                f"Platform: {getattr(c, 'platform', 'N/A')}",
                f"URL: {getattr(c, 'url', 'N/A')}",
                f"Status: {getattr(c, 'status', 'N/A')}",
                f"Source: {getattr(c, 'source', 'N/A')}",
                f"Created: {getattr(c, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(c, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(c, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(c, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving container details: {e}"

    # ── SaaS Platforms ────────────────────────────────────────────

    @mcp.tool()
    def list_saas_platforms(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered SaaS platform instances.

        Args:
            asset_name: Search by SaaS URL.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = SaaSPlatformsApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_saas_platforms(**supported_kwargs(api.get_list_asset_saas_platforms, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No SaaS platforms found."

            total = get_total(response)
            lines = []
            for s in response.data:
                sid = getattr(s, 'id', '')
                url = getattr(s, 'url', 'Unknown')
                provider = getattr(s, 'provider', '')
                status = getattr(s, 'status', 'Unknown')
                bus = format_bus(getattr(s, 'business_units', []))
                prov_str = f" [{provider}]" if provider else ""
                lines.append(f"• [ID:{sid}] {url}{prov_str} - {status}{bus}")

            header = f"SaaS Platforms ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing SaaS platforms: {e}"

    @mcp.tool()
    def get_asset_saas_details(saas_id: int) -> str:
        """Get full details for a specific SaaS platform instance.

        Args:
            saas_id: The SaaS platform asset ID.
        """
        try:
            api = SaaSPlatformsApi(get_api_client())
            response = api.get_asset_saas_platform_details(
                id=int(saas_id)
            )

            s = response.data if hasattr(response, 'data') else response
            if not s:
                return f"SaaS platform {saas_id} not found."

            lines = [
                f"SaaS Platform #{getattr(s, 'id', saas_id)}",
                f"URL: {getattr(s, 'url', 'N/A')}",
                f"Provider: {getattr(s, 'provider', 'N/A')}",
                f"Status: {getattr(s, 'status', 'N/A')}",
                f"Source: {getattr(s, 'source', 'N/A')}",
                f"Created: {getattr(s, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(s, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(s, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(s, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving SaaS platform details: {e}"

    # ── Mobile Applications ───────────────────────────────────────

    @mcp.tool()
    def list_mobile_app_assets(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered mobile applications.

        Args:
            asset_name: Search by app name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = MobileApplicationsApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_mobile_apps(**supported_kwargs(api.get_list_asset_mobile_apps, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No mobile applications found."

            total = get_total(response)
            lines = []
            for m in response.data:
                mid = getattr(m, 'id', '')
                name = getattr(m, 'name', 'Unknown')
                publisher = getattr(m, 'publisher', '')
                platform = getattr(m, 'platform', '')
                status = getattr(m, 'status', 'Unknown')
                bus = format_bus(getattr(m, 'business_units', []))
                pub_str = f" by {publisher}" if publisher else ""
                plat_str = f" [{platform}]" if platform else ""
                lines.append(f"• [ID:{mid}] {name}{pub_str}{plat_str} - {status}{bus}")

            header = f"Mobile Applications ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing mobile applications: {e}"

    @mcp.tool()
    def get_asset_mobile_app_details(mobile_app_id: int) -> str:
        """Get full details for a specific mobile application.

        Args:
            mobile_app_id: The mobile application asset ID.
        """
        try:
            api = MobileApplicationsApi(get_api_client())
            response = api.get_asset_mobile_app_details(
                id=int(mobile_app_id)
            )

            m = response.data if hasattr(response, 'data') else response
            if not m:
                return f"Mobile application {mobile_app_id} not found."

            lines = [
                f"Mobile App #{getattr(m, 'id', mobile_app_id)}",
                f"Name: {getattr(m, 'name', 'N/A')}",
                f"Publisher: {getattr(m, 'publisher', 'N/A')}",
                f"Platform: {getattr(m, 'platform', 'N/A')}",
                f"App ID: {getattr(m, 'app_id', 'N/A')}",
                f"URL: {getattr(m, 'url', 'N/A')}",
                f"Status: {getattr(m, 'status', 'N/A')}",
                f"Source: {getattr(m, 'source', 'N/A')}",
                f"Created: {getattr(m, 'created_at', 'N/A')}",
            ]
            discovery_reason = getattr(m, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(m, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving mobile app details: {e}"

    # ── Cloud Assets (Integration) ────────────────────────────────

    @mcp.tool()
    def list_cloud_assets(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        provider: str = None,
        super_type: str = None,
        sub_type: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered cloud assets (AWS, GCP, Azure, etc.).

        Args:
            asset_name: Search by cloud asset name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            provider: Filter assets by cloud provider.
            super_type: Filter assets by cloud asset type.
            sub_type: Filter assets by cloud asset sub-type.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = CloudIntegrationAssetsApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            if provider:
                kwargs["provider"] = provider
            if super_type:
                kwargs["super_type"] = super_type
            if sub_type:
                kwargs["sub_type"] = sub_type
            response = api.get_list_asset_cloud_asset(**supported_kwargs(api.get_list_asset_cloud_asset, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No cloud assets found."

            total = get_total(response)
            lines = []
            for ca in response.data:
                caid = getattr(ca, 'id', '')
                name = getattr(ca, 'name', 'Unknown')
                prov = getattr(ca, 'provider', '')
                status = getattr(ca, 'status', 'Unknown')
                bus = format_bus(getattr(ca, 'business_units', []))
                prov_str = f" [{prov}]" if prov else ""
                lines.append(f"• [ID:{caid}] {name}{prov_str} - {status}{bus}")

            header = f"Cloud Assets ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing cloud assets: {e}"

    @mcp.tool()
    def get_cloud_asset_details(cloud_asset_id: int) -> str:
        """Get full details for a specific cloud asset.

        Args:
            cloud_asset_id: The cloud asset ID.
        """
        try:
            api = CloudIntegrationAssetsApi(get_api_client())
            response = api.get_asset_cloud_asset_details(
                id=int(cloud_asset_id)
            )

            ca = response.data if hasattr(response, 'data') else response
            if not ca:
                return f"Cloud asset {cloud_asset_id} not found."

            lines = [
                f"Cloud Asset #{getattr(ca, 'id', cloud_asset_id)}",
                f"Name: {getattr(ca, 'name', 'N/A')}",
                f"Provider: {getattr(ca, 'provider', 'N/A')}",
                f"Status: {getattr(ca, 'status', 'N/A')}",
                f"Source: {getattr(ca, 'source', 'N/A')}",
            ]
            hostname = getattr(ca, 'hostname', None)
            if hostname:
                lines.append(f"Hostname: {hostname}")
            cloud_resource_id = getattr(ca, 'cloud_resource_id', None)
            if cloud_resource_id:
                lines.append(f"Cloud Resource ID: {cloud_resource_id}")
            super_type = getattr(ca, 'super_type', None)
            if super_type:
                lines.append(f"Super Type: {super_type}")
            sub_type = getattr(ca, 'sub_type', None)
            if sub_type:
                lines.append(f"Sub Type: {sub_type}")
            criticality = getattr(ca, 'criticality', None)
            if criticality:
                lines.append(f"Criticality: {criticality}")
            lines.append(f"Created: {getattr(ca, 'created_at', 'N/A')}")
            bus = format_bus(getattr(ca, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving cloud asset details: {e}"

    # ── API Documentations ────────────────────────────────────────

    @mcp.tool()
    def list_api_documentations(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered API documentation assets.

        Args:
            asset_name: Search by API URL/path.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = APIDocumentationApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_api_documentation(**supported_kwargs(api.get_list_asset_api_documentation, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No API documentations found."

            total = get_total(response)
            lines = []
            for ad in response.data:
                adid = getattr(ad, 'id', '')
                name = getattr(ad, 'name', None) or getattr(ad, 'url', None) or 'Unknown'
                url = getattr(ad, 'url', '')
                status = getattr(ad, 'status', 'Unknown')
                bus = format_bus(getattr(ad, 'business_units', []))
                url_str = f" - {url}" if url and url != name else ""
                lines.append(f"• [ID:{adid}] {name}{url_str} - {status}{bus}")

            header = f"API Documentations ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing API documentations: {e}"

    @mcp.tool()
    def get_api_documentation_details(api_documentation_id: int) -> str:
        """Get full details for a specific API documentation asset.

        Args:
            api_documentation_id: The API documentation asset ID.
        """
        try:
            api = APIDocumentationApi(get_api_client())
            response = api.get_asset_api_documentation_details(
                id=int(api_documentation_id)
            )

            ad = response.data if hasattr(response, 'data') else response
            if not ad:
                return f"API documentation asset {api_documentation_id} not found."

            lines = [
                f"API Documentation #{getattr(ad, 'id', api_documentation_id)}",
                f"Name: {getattr(ad, 'name', 'N/A')}",
                f"URL: {getattr(ad, 'url', 'N/A')}",
                f"Platform: {getattr(ad, 'platform', 'N/A')}",
                f"Status: {getattr(ad, 'status', 'N/A')}",
                f"Source: {getattr(ad, 'source', 'N/A')}",
                f"Created: {getattr(ad, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(ad, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving API documentation details: {e}"

    # ── Package Managers ──────────────────────────────────────────

    @mcp.tool()
    def list_package_managers(
        asset_name: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        source: str = None,
        custom_property_key: str = None,
        custom_property_value: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List discovered package manager registry assets.

        Args:
            asset_name: Search by package manager name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            source: Filter assets by the source that discovered the asset.
            custom_property_key: Filter assets by custom property key.
            custom_property_value: Filter assets by custom property value.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = PackageManagersApi(get_api_client())
            kwargs = _build_asset_kwargs(
                page, page_size, asset_name, statuses, business_unit_ids,
                created_from, created_to, source,
                custom_property_key, custom_property_value
            )
            response = api.get_list_asset_package_managers(**supported_kwargs(api.get_list_asset_package_managers, kwargs))

            if not hasattr(response, 'data') or not response.data:
                return "No package managers found."

            total = get_total(response)
            lines = []
            for pm in response.data:
                pmid = getattr(pm, 'id', '')
                name = getattr(pm, 'name', 'Unknown')
                platform = getattr(pm, 'platform', '')
                status = getattr(pm, 'status', 'Unknown')
                bus = format_bus(getattr(pm, 'business_units', []))
                plat_str = f" [{platform}]" if platform else ""
                lines.append(f"• [ID:{pmid}] {name}{plat_str} - {status}{bus}")

            header = f"Package Managers ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing package managers: {e}"

    @mcp.tool()
    def get_package_manager_details(package_manager_id: int) -> str:
        """Get full details for a specific package manager asset.

        Args:
            package_manager_id: The package manager asset ID.
        """
        try:
            api = PackageManagersApi(get_api_client())
            response = api.get_asset_package_manager_details(
                id=int(package_manager_id)
            )

            pm = response.data if hasattr(response, 'data') else response
            if not pm:
                return f"Package manager asset {package_manager_id} not found."

            lines = [
                f"Package Manager #{getattr(pm, 'id', package_manager_id)}",
                f"Name: {getattr(pm, 'name', 'N/A')}",
                f"Platform: {getattr(pm, 'platform', 'N/A')}",
                f"Status: {getattr(pm, 'status', 'N/A')}",
                f"Source: {getattr(pm, 'source', 'N/A')}",
                f"Created: {getattr(pm, 'created_at', 'N/A')}",
            ]
            bus = format_bus(getattr(pm, 'business_units', []))
            if bus:
                lines.append(f"Business Units:{bus}")
            discovery_reason = getattr(pm, 'discovery_reason', None)
            if discovery_reason:
                lines.append(f"Discovery Reason: {discovery_reason}")
            metadata = getattr(pm, 'metadata', None)
            if metadata and metadata != {}:
                lines.append(f"Metadata: {metadata}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving package manager details: {e}"

    # ── Generic Asset Management Tools ─────────────────────────────

    @mcp.tool()
    def manage_engine_settings(
        asset_type: str,
        asset_id: int,
        action: str = "get",
        adversary_sight_enabled: bool = None,
        dns_bruteforcing_enabled: bool = None,
        automated_red_teaming_enabled: bool = None,
        intrusive_http_checks_enabled: bool = None,
        credential_stuffing_enabled: bool = None,
        rapid_reaction_enabled: bool = None,
    ) -> str:
        """Get or update scan engine settings for a domain, subdomain, or IP asset."""
        if asset_type not in ENGINE_SETTINGS_TYPES:
            return _unsupported_asset_error("Engine settings", asset_type, ENGINE_SETTINGS_TYPES)
        if action not in ("get", "update"):
            return "Error: action must be one of: get, update"

        try:
            api = ASSET_API_CLASSES[asset_type](get_api_client())
            methods = ENGINE_SETTINGS_METHODS[asset_type]
            current = _unwrap_data(getattr(api, methods["get"])(id=asset_id))
            if action == "get":
                return _format_engine_settings(asset_type, asset_id, current)
            # Fetch-then-merge: omitted fields preserve current settings
            def _merge(caller_val, attr):
                return caller_val if caller_val is not None else getattr(current, attr, False)
            dto = UpdateClientEngineSettingsDto(
                adversary_sight_enabled=_merge(adversary_sight_enabled, "adversary_sight_enabled"),
                dns_bruteforcing_enabled=_merge(dns_bruteforcing_enabled, "dns_bruteforcing_enabled"),
                automated_red_teaming_enabled=_merge(automated_red_teaming_enabled, "automated_red_teaming_enabled"),
                intrusive_http_checks_enabled=_merge(intrusive_http_checks_enabled, "intrusive_http_checks_enabled"),
                credential_stuffing_enabled=_merge(credential_stuffing_enabled, "credential_stuffing_enabled"),
                rapid_reaction_enabled=_merge(rapid_reaction_enabled, "rapid_reaction_enabled"),
            )
            response = getattr(api, methods["update"])(
                id=asset_id,
                update_client_engine_settings_dto=dto,
            )
            return _format_engine_settings(asset_type, asset_id, _unwrap_data(response))
        except Exception as e:
            return f"Error: {e}"

    @mcp.tool()
    def set_asset_criticality(asset_type: str, asset_id: int, criticality: str) -> str:
        """Set the criticality level for any supported asset type."""
        validation_error = _validate_asset_type(asset_type)
        if validation_error:
            return validation_error
        if criticality not in CRITICALITY_VALUES:
            return f"Error: criticality must be one of: {', '.join(CRITICALITY_VALUES)}"

        try:
            api = ASSET_API_CLASSES[asset_type](get_api_client())
            dto = SetCriticalityDto(criticality=criticality)
            getattr(api, CRITICALITY_METHODS[asset_type])(id=asset_id, set_criticality_dto=dto)
            return f"✓ Criticality set to '{criticality}' for {asset_type} #{asset_id}"
        except Exception as e:
            return f"Error: {e}"

    @mcp.tool()
    def manage_asset_business_units(
        asset_type: str,
        asset_id: int,
        action: str,
        business_unit_ids: list[int],
    ) -> str:
        """Assign or unassign business units for any supported asset type."""
        validation_error = _validate_asset_type(asset_type)
        if validation_error:
            return validation_error
        if action not in ("assign", "unassign"):
            return "Error: action must be one of: assign, unassign"
        if not isinstance(business_unit_ids, list) or not business_unit_ids:
            return "Error: business_unit_ids must be a non-empty list"

        try:
            import watchtowr_mcp_server.tools.assets as assets_module

            api = ASSET_API_CLASSES[asset_type](assets_module.get_api_client())
            method_name = BUSINESS_UNIT_METHODS[asset_type][action]
            method = getattr(api, method_name)
            if action == "assign":
                if asset_type in ("domain", "subdomain"):
                    dto = HostnameBusinessUnitIDsDTO(
                        business_unit_ids=business_unit_ids,
                        cascade_subdomain=False,
                        cascade_ip=False,
                    )
                    method(id=asset_id, hostname_business_unit_ids_dto=dto)
                else:
                    dto = AssetBusinessUnitIdsDTO(business_unit_ids=business_unit_ids)
                    method(id=asset_id, asset_business_unit_ids_dto=dto)
            else:
                kwargs = {"id": asset_id, "business_unit_ids": [str(x) for x in business_unit_ids]}
                if asset_type in ("domain", "subdomain"):
                    kwargs["cascade_subdomain"] = "false"
                    kwargs["cascade_ip"] = "false"
                method(**kwargs)
            verb = "Assigned" if action == "assign" else "Unassigned"
            prep = "to" if action == "assign" else "from"
            return f"✓ {verb} business units {business_unit_ids} {prep} {asset_type} #{asset_id}"
        except Exception as e:
            return f"Error: {e}"

    @mcp.tool()
    def manage_asset_custom_property(
        asset_type: str,
        asset_id: int,
        action: str,
        custom_property_id: int = None,
        key: str = None,
        value: str = None,
        is_preset: bool = None,
        page: int = None,
        page_size: int = None,
    ) -> str:
        """List, create, update, or delete custom properties on an asset."""
        validation_error = _validate_asset_type(asset_type)
        if validation_error:
            return validation_error
        if action not in ("list", "create", "update", "delete"):
            return "Error: action must be one of: list, create, update, delete"
        if action == "create" and not key:
            return "Error: key is required when action is 'create'"
        if action == "create" and value is None:
            return "Error: value is required when action is 'create'"
        if action == "update":
            if custom_property_id is None:
                return "Error: custom_property_id is required when action is 'update'"
            if not key:
                return "Error: key is required when action is 'update'"
        if action == "delete" and custom_property_id is None:
            return "Error: custom_property_id is required when action is 'delete'"

        try:
            api = ASSET_API_CLASSES[asset_type](get_api_client())
            method = getattr(api, CUSTOM_PROPERTY_METHODS[asset_type][action])
            if action == "list":
                response = method(id=asset_id, page=page, page_size=page_size)
                return _format_custom_properties(asset_type, asset_id, response, page)
            if action == "create":
                dto = CreateClientCustomPropertyDto(key=key, value=value, is_preset=is_preset)
                response = method(id=asset_id, create_client_custom_property_dto=dto)
                prop = _unwrap_data(response)
                return (
                    f"✓ Custom property created: {getattr(prop, 'key', key)} = "
                    f"{getattr(prop, 'value', value)} (ID: {getattr(prop, 'id', 'N/A')})"
                )
            if action == "update":
                dto = UpdateClientCustomPropertyDto(key=key, value=value)
                response = method(
                    id=asset_id,
                    custom_property_id=custom_property_id,
                    update_client_custom_property_dto=dto,
                )
                prop = _unwrap_data(response)
                return (
                    f"✓ Custom property updated: {getattr(prop, 'key', key)} = "
                    f"{getattr(prop, 'value', value)} (ID: {getattr(prop, 'id', custom_property_id)})"
                )
            method(id=asset_id, custom_property_id=custom_property_id)
            return f"✓ Custom property #{custom_property_id} deleted from {asset_type} #{asset_id}"
        except Exception as e:
            return f"Error: {e}"

    @mcp.tool()
    def manage_asset_notes(
        asset_type: str,
        asset_id: int,
        action: str,
        note_id: int = None,
        title: str = None,
        note: str = None,
        page: int = None,
        page_size: int = None,
    ) -> str:
        """List, create, update, or delete notes on an asset."""
        validation_error = _validate_asset_type(asset_type)
        if validation_error:
            return validation_error
        if action not in ("list", "create", "update", "delete"):
            return "Error: action must be one of: list, create, update, delete"
        if action == "create" and not note:
            return "Error: note is required when action is 'create'"
        if action == "update":
            if note_id is None:
                return "Error: note_id is required when action is 'update'"
            if not note:
                return "Error: note is required when action is 'update'"
        if action == "delete" and note_id is None:
            return "Error: note_id is required when action is 'delete'"

        try:
            import watchtowr_mcp_server.tools.assets as assets_module

            api = ASSET_API_CLASSES[asset_type](assets_module.get_api_client())
            method = getattr(api, NOTES_METHODS[asset_type][action])
            if action == "list":
                response = method(id=asset_id, page=page, page_size=page_size)
                return _format_notes(asset_type, asset_id, response, page)
            if action == "create":
                dto = CreateClientNoteDto(title=title, note=note)
                response = method(id=asset_id, create_client_note_dto=dto)
                created = _unwrap_data(response)
                return f"✓ Note created for {asset_type} #{asset_id} (ID: {getattr(created, 'id', 'N/A')})"
            if action == "update":
                dto = CreateClientNoteDto(title=title, note=note)
                response = method(id=asset_id, note_id=note_id, create_client_note_dto=dto)
                updated = _unwrap_data(response)
                return f"✓ Note updated for {asset_type} #{asset_id} (ID: {getattr(updated, 'id', note_id)})"
            method(id=asset_id, note_id=note_id)
            return f"✓ Note #{note_id} deleted from {asset_type} #{asset_id}"
        except Exception as e:
            return f"Error: {e}"

    # ── Update Asset Status (unified) ─────────────────────────────

    @mcp.tool()
    def update_asset_status(
        asset_type: str,
        asset_id: int,
        status: str,
        status_reason: str = None,
    ) -> str:
        """Update the status of any asset type.

        Args:
            asset_type: One of: domain, subdomain, ip, ipRange, container, cloudStorage, saasPlatform, mobileApp, repository, cloudAsset, apiDocumentation, packageManager (snake_case aliases also accepted).
            asset_id: The asset ID to update.
            status: The new status value.
            status_reason: Optional reason for the status change.
        """
        try:
            client = get_api_client()

            ASSET_TYPE_ALIASES = {
                "ip_range": "ipRange", "cloud_storage": "cloudStorage",
                "saas_platform": "saasPlatform", "mobile_app": "mobileApp",
                "cloud_asset": "cloudAsset", "api_documentation": "apiDocumentation",
                "package_manager": "packageManager",
            }
            if asset_type in ASSET_TYPE_ALIASES:
                asset_type = ASSET_TYPE_ALIASES[asset_type]

            legacy_types = {
                "domain": (DomainsApi, "update_asset_domain_status"),
                "subdomain": (SubdomainsApi, "update_asset_subdomain_status"),
                "ip": (IPAddressesApi, "update_asset_ip_status"),
                "ipRange": (IPRangesApi, "update_asset_ip_range_status"),
            }
            nextgen_types = {
                "container": (ContainersApi, "update_asset_container_status"),
                "cloudStorage": (CloudStorageApi, "update_asset_cloud_storage_status"),
                "saasPlatform": (SaaSPlatformsApi, "update_asset_saas_platform_status"),
                "mobileApp": (MobileApplicationsApi, "update_asset_mobile_app_status"),
                "repository": (RepositoriesApi, "update_asset_repository_status"),
                "cloudAsset": (CloudIntegrationAssetsApi, "update_asset_cloud_asset_status"),
                "apiDocumentation": (APIDocumentationApi, "update_asset_api_documentation_status"),
                "packageManager": (PackageManagersApi, "update_asset_package_manager_status"),
            }

            if asset_type in legacy_types:
                api_cls, method_name = legacy_types[asset_type]
                dto_kwargs = {"status": status}
                if status_reason:
                    dto_kwargs["status_reason"] = status_reason
                dto = UpdateClientLegacyAssetStatusDto(**dto_kwargs)
                api = api_cls(client)
                method = getattr(api, method_name)
                param_name = "update_client_legacy_asset_status_dto"
                method(id=asset_id, **{param_name: dto})
            elif asset_type in nextgen_types:
                api_cls, method_name = nextgen_types[asset_type]
                dto_kwargs = {"status": status}
                if status_reason:
                    dto_kwargs["status_reason"] = status_reason

                if asset_type == "cloudAsset":
                    dto = UpdateClientCloudAssetStatusDto(**dto_kwargs)
                    param_name = "update_client_cloud_asset_status_dto"
                elif asset_type == "apiDocumentation":
                    dto = UpdateApiDocumentationStatusDto(**dto_kwargs)
                    param_name = "update_api_documentation_status_dto"
                else:
                    dto = UpdateClientNextGenAssetStatusDto(**dto_kwargs)
                    param_name = "update_client_next_gen_asset_status_dto"

                api = api_cls(client)
                method = getattr(api, method_name)
                method(id=asset_id, **{param_name: dto})
            else:
                valid = sorted(list(legacy_types.keys()) + list(nextgen_types.keys()))
                return f"Unknown asset type '{asset_type}'. Valid types: {', '.join(valid)}"

            return f"Asset {asset_type} {asset_id} status updated to: {status}"
        except Exception as e:
            return f"Error updating asset status: {e}"

    # ── Add Seed Asset ────────────────────────────────────────────

    @mcp.tool()
    def add_seed_asset(
        asset_type: str,
        asset_value: str = None,
        asset_title: str = None,
        cidr: str = None,
        asn: str = None,
        business_unit_ids: list[int] = None,
    ) -> str:
        """Submit a new seed asset for discovery and monitoring.

        Args:
            asset_type: Asset type. Valid types: domain, subdomain, ip, ipRange, repository,
                cloudStorage, container, mobileApp, saasPlatform, apiDocumentation, packageManager.
            asset_value: The asset value (e.g. "example.com", "1.2.3.4"). Not required for ipRange.
            asset_title: Optional display title. Defaults to asset_value or a generated title.
            cidr: CIDR notation for IP range (required when asset_type == "ipRange").
            asn: ASN for IP range (required when asset_type == "ipRange").
            business_unit_ids: Optional list of business unit IDs to assign the asset.
        """
        
        if asset_type not in VALID_SEED_ASSET_TYPES:
            return f"Error: Invalid asset_type '{asset_type}'. Valid types: {', '.join(VALID_SEED_ASSET_TYPES)}"

        if asset_type == "ipRange":
            if not cidr or not asn:
                return "Error: 'cidr' and 'asn' are required when asset_type is 'ipRange'"
        else:
            if not asset_value:
                return "Error: 'asset_value' is required for non-ipRange types"

        
        try:
            api = AddAssetApi(get_api_client())

            ip_range_values = None
            if asset_type == "ipRange":
                ip_range_values = IpRangeValues(cidr=cidr, asn=asn)

            seed = ClientSeedDataDto(
                title=asset_title or asset_value or f"{cidr} ({asn})",
                type=asset_type,
                value=asset_value or cidr,
                values=ip_range_values,
            )

            business_units = None
            if business_unit_ids:
                business_units = [
                    FilterByBusinessUnitInput(id=bu_id, type="BUSINESS_UNIT")
                    for bu_id in business_unit_ids
                ]

            body = CreateClientSeedDataRequestBody(data=[seed], business_units=business_units)
            response = api.submit_asset(create_client_seed_data_request_body=body)

            # ── Format response ──
            lines = ["✓ Seed asset submitted successfully:"]
            lines.append(f"  • Type: {asset_type}")
            lines.append(f"  • Title: {asset_title or asset_value or f'{cidr} ({asn})'}")
            if asset_type == "ipRange":
                lines.append(f"  • CIDR: {cidr}")
                lines.append(f"  • ASN: {asn}")
            else:
                lines.append(f"  • Value: {asset_value}")
            if business_unit_ids:
                lines.append(f"  • Business Units: {business_unit_ids}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error submitting seed asset: {e}"
