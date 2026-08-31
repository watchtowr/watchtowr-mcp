from watchtowr_api_sdk.api.domains_api import DomainsApi
from watchtowr_api_sdk.api.subdomains_api import SubdomainsApi
from watchtowr_api_sdk.api.ip_addresses_api import IPAddressesApi
from watchtowr_api_sdk.api.ip_ranges_api import IPRangesApi
from watchtowr_api_sdk.api.cloud_storage_api import CloudStorageApi
from watchtowr_api_sdk.api.repositories_api import RepositoriesApi
from watchtowr_api_sdk.api.containers_api import ContainersApi
from watchtowr_api_sdk.api.mobile_applications_api import MobileApplicationsApi
from watchtowr_api_sdk.api.saa_s_platforms_api import SaaSPlatformsApi
from watchtowr_api_sdk.api.api_documentation_api import APIDocumentationApi
from watchtowr_api_sdk.api.package_managers_api import PackageManagersApi
from watchtowr_api_sdk.api.cloud_integration_assets_api import CloudIntegrationAssetsApi

from ...client import get_api_client


_CHANGELOG_DISPATCH = {
    "domain": (DomainsApi, "get_asset_domain_changelog"),
    "subdomain": (SubdomainsApi, "get_asset_subdomain_changelog"),
    "ip": (IPAddressesApi, "get_asset_ip_changelog"),
    "ip_range": (IPRangesApi, "get_asset_iprange_changelog"),
    "cloud_storage": (CloudStorageApi, "get_asset_cloud_storage_changelog"),
    "repository": (RepositoriesApi, "get_asset_repository_changelog"),
    "container": (ContainersApi, "get_asset_container_changelog"),
    "mobile_app": (MobileApplicationsApi, "get_asset_mobile_app_changelog"),
    "saas_platform": (SaaSPlatformsApi, "get_asset_saas_platform_changelog"),
    "api_documentation": (APIDocumentationApi, "get_asset_api_documentation_changelog"),
    "package_manager": (PackageManagersApi, "get_asset_package_manager_changelog"),
    "cloud_asset": (CloudIntegrationAssetsApi, "get_asset_cloud_asset_changelog"),
}


def register_asset_changelog_tools(mcp):

    @mcp.tool()
    def get_asset_changelog(
        asset_type: str,
        asset_id: int,
        page: int = 1,
        page_size: int = 10,
    ) -> str:
        """Get change history (changelog) for a specific asset.

        Args:
            asset_type: Asset type (domain, subdomain, ip, ip_range, cloud_storage, repository, container, mobile_app, saas_platform, api_documentation, package_manager, cloud_asset).
            asset_id: The asset ID.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            dispatch = _CHANGELOG_DISPATCH.get(asset_type)
            if not dispatch:
                supported = ", ".join(sorted(_CHANGELOG_DISPATCH.keys()))
                return f"Unsupported asset_type '{asset_type}'. Supported: {supported}"

            api_cls, method_name = dispatch
            api = api_cls(get_api_client())
            method = getattr(api, method_name)
            response = method(id=int(asset_id), page=page, page_size=min(page_size, 30))

            data = response.data if hasattr(response, "data") else None
            if not data:
                return f"No changelog entries found for {asset_type} #{asset_id}."

            meta = getattr(response, "meta", None)
            total = 0
            if isinstance(meta, dict):
                pagination = meta.get("pagination", {})
                total = pagination.get("total", 0)

            lines = [f"Asset Changelog for {asset_type} #{asset_id} ({len(data)} of {total}):"]
            lines.append("")

            for entry in data:
                if isinstance(entry, dict):
                    ts = entry.get("created_at", "")
                    action = entry.get("type", "") or "unknown"
                    description = entry.get("description", "")
                    caused_by = entry.get("caused_by")
                    user = caused_by.get("name", "") if isinstance(caused_by, dict) else ""
                else:
                    ts = getattr(entry, "created_at", "")
                    action = getattr(entry, "type", "") or "unknown"
                    description = getattr(entry, "description", "")
                    caused_by = getattr(entry, "caused_by", None)
                    user = getattr(caused_by, "name", "") if caused_by else ""

                line = f"[{ts}] {action}"
                if description:
                    line += f" — {description}"
                if user:
                    line += f" (by {user})"
                lines.append(line)

            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"
