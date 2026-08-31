"""Static check: every SDK class/method the MCP server imports actually exists.

Built from a manual audit of `watchtowr_mcp_server/tools/*.py` and
`watchtowr_mcp_server/client.py`. If you add a new SDK call site to the MCP
server, append the (module, class, method) triple here so the suite enforces
that it resolves once the submodule is pulled.

A second test (`test_sdk_calls_match_source`) walks the MCP source with AST
and proves the hand-written SDK_CALLS list still mirrors reality — if you add
a new SDK call to a tools/*.py file and forget to update SDK_CALLS, you get a
clear failure at unit-test time naming the orphaned (class, method) pair.
"""
from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SOURCE_DIRS = [
    REPO_ROOT / "watchtowr_mcp_server" / "tools",
    REPO_ROOT / "watchtowr_mcp_server",  # picks up client.py
]


SDK_CALLS = [
    # Findings
    ("watchtowr_api_sdk.api.findings_api", "FindingsApi", "get_list_findings"),
    ("watchtowr_api_sdk.api.findings_api", "FindingsApi", "get_finding_details"),
    ("watchtowr_api_sdk.api.findings_api", "FindingsApi", "update_finding_status"),
    ("watchtowr_api_sdk.api.findings_api", "FindingsApi", "start_specific_finding_retest"),
    ("watchtowr_api_sdk.api.findings_api", "FindingsApi", "get_available_finding_statuses"),
    ("watchtowr_api_sdk.api.findings_api", "FindingsApi", "export_pdf_for_finding"),
    ("watchtowr_api_sdk.api.findings_api", "FindingsApi", "update_finding_state"),
    # Hunts
    ("watchtowr_api_sdk.api.hunts_api", "HuntsApi", "get_client_hunts"),
    ("watchtowr_api_sdk.api.hunts_api", "HuntsApi", "show_the_detail_hunt"),
    ("watchtowr_api_sdk.api.hunts_api", "HuntsApi", "get_list_finding_by_hunt"),
    ("watchtowr_api_sdk.api.hunts_api", "HuntsApi", "get_list_asset_by_hunt"),
    # Business unit
    ("watchtowr_api_sdk.api.business_unit_api", "BusinessUnitApi", "get_list_business_unit"),
    ("watchtowr_api_sdk.api.business_unit_api", "BusinessUnitApi", "get_business_unit_details"),
    # Activity log
    ("watchtowr_api_sdk.api.activity_log_api", "ActivityLogApi", "get_list_activity_logs"),
    # Source IPs
    ("watchtowr_api_sdk.api.source_ip_addresses_api", "SourceIPAddressesApi", "get_list_source_ip_addresses"),
    # Service listing
    ("watchtowr_api_sdk.api.service_discovery_api", "ServiceDiscoveryApi", "get_list_service_listing"),
    ("watchtowr_api_sdk.api.service_discovery_api", "ServiceDiscoveryApi", "get_technology_statistics"),
    # Asset IPs
    ("watchtowr_api_sdk.api.ip_addresses_api", "IPAddressesApi", "get_list_asset_ips"),
    ("watchtowr_api_sdk.api.ip_addresses_api", "IPAddressesApi", "get_asset_ip_details"),
    ("watchtowr_api_sdk.api.ip_addresses_api", "IPAddressesApi", "get_asset_ip_ports"),
    ("watchtowr_api_sdk.api.ip_addresses_api", "IPAddressesApi", "get_asset_ip_port_details"),
    ("watchtowr_api_sdk.api.ip_addresses_api", "IPAddressesApi", "update_asset_ip_status"),
    # Asset domains
    ("watchtowr_api_sdk.api.domains_api", "DomainsApi", "get_list_asset_domains"),
    ("watchtowr_api_sdk.api.domains_api", "DomainsApi", "get_asset_domain_details"),
    ("watchtowr_api_sdk.api.domains_api", "DomainsApi", "update_asset_domain_status"),
    # Asset subdomains
    ("watchtowr_api_sdk.api.subdomains_api", "SubdomainsApi", "get_list_asset_subdomains"),
    ("watchtowr_api_sdk.api.subdomains_api", "SubdomainsApi", "get_asset_subdomain_details"),
    ("watchtowr_api_sdk.api.subdomains_api", "SubdomainsApi", "update_asset_subdomain_status"),
    # Asset ports
    ("watchtowr_api_sdk.api.ports_api", "PortsApi", "get_list_asset_ports"),
    ("watchtowr_api_sdk.api.ports_api", "PortsApi", "get_asset_port_details"),
    # Asset IP ranges
    ("watchtowr_api_sdk.api.ip_ranges_api", "IPRangesApi", "get_list_asset_ipranges"),
    ("watchtowr_api_sdk.api.ip_ranges_api", "IPRangesApi", "get_asset_iprange_details"),
    ("watchtowr_api_sdk.api.ip_ranges_api", "IPRangesApi", "update_asset_ip_range_status"),
    # Asset cloud storage
    ("watchtowr_api_sdk.api.cloud_storage_api", "CloudStorageApi", "get_list_asset_cloud_storages"),
    ("watchtowr_api_sdk.api.cloud_storage_api", "CloudStorageApi", "get_asset_cloud_storage_details"),
    ("watchtowr_api_sdk.api.cloud_storage_api", "CloudStorageApi", "update_asset_cloud_storage_status"),
    # Asset source code repos
    ("watchtowr_api_sdk.api.repositories_api", "RepositoriesApi", "get_list_asset_repositories"),
    ("watchtowr_api_sdk.api.repositories_api", "RepositoriesApi", "get_asset_repository_details"),
    ("watchtowr_api_sdk.api.repositories_api", "RepositoriesApi", "update_asset_repository_status"),
    # Asset containers
    ("watchtowr_api_sdk.api.containers_api", "ContainersApi", "get_list_asset_container"),
    ("watchtowr_api_sdk.api.containers_api", "ContainersApi", "get_asset_container_details"),
    ("watchtowr_api_sdk.api.containers_api", "ContainersApi", "update_asset_container_status"),
    # Asset SaaS platforms
    ("watchtowr_api_sdk.api.saa_s_platforms_api", "SaaSPlatformsApi", "get_list_asset_saas_platforms"),
    ("watchtowr_api_sdk.api.saa_s_platforms_api", "SaaSPlatformsApi", "get_asset_saas_platform_details"),
    ("watchtowr_api_sdk.api.saa_s_platforms_api", "SaaSPlatformsApi", "update_asset_saas_platform_status"),
    # Asset mobile apps
    ("watchtowr_api_sdk.api.mobile_applications_api", "MobileApplicationsApi", "get_list_asset_mobile_apps"),
    ("watchtowr_api_sdk.api.mobile_applications_api", "MobileApplicationsApi", "get_asset_mobile_app_details"),
    ("watchtowr_api_sdk.api.mobile_applications_api", "MobileApplicationsApi", "update_asset_mobile_app_status"),
    # Add asset
    ("watchtowr_api_sdk.api.add_asset_api", "AddAssetApi", "submit_asset"),
    # Suspicious domains
    ("watchtowr_api_sdk.api.suspicious_domains_api", "SuspiciousDomainsApi", "get_list_suspicious_domain"),
    ("watchtowr_api_sdk.api.suspicious_domains_api", "SuspiciousDomainsApi", "get_suspicious_domain_details"),
    # Points of interest
    ("watchtowr_api_sdk.api.points_of_interest_api", "PointsOfInterestApi", "get_list_points_of_interest"),
    # Certificates
    ("watchtowr_api_sdk.api.certificates_api", "CertificatesApi", "get_list_certificates"),
    ("watchtowr_api_sdk.api.certificates_api", "CertificatesApi", "get_certificate_details"),
    # API Documentation
    ("watchtowr_api_sdk.api.api_documentation_api", "APIDocumentationApi", "get_asset_api_documentation_details"),
    ("watchtowr_api_sdk.api.api_documentation_api", "APIDocumentationApi", "get_list_asset_api_documentation"),
    ("watchtowr_api_sdk.api.api_documentation_api", "APIDocumentationApi", "update_asset_api_documentation_status"),
    # Cloud Integration Assets
    ("watchtowr_api_sdk.api.cloud_integration_assets_api", "CloudIntegrationAssetsApi", "get_asset_cloud_asset_details"),
    ("watchtowr_api_sdk.api.cloud_integration_assets_api", "CloudIntegrationAssetsApi", "get_list_asset_cloud_asset"),
    ("watchtowr_api_sdk.api.cloud_integration_assets_api", "CloudIntegrationAssetsApi", "update_asset_cloud_asset_status"),
    # Package Managers
    ("watchtowr_api_sdk.api.package_managers_api", "PackageManagersApi", "get_asset_package_manager_details"),
    ("watchtowr_api_sdk.api.package_managers_api", "PackageManagersApi", "get_list_asset_package_managers"),
    ("watchtowr_api_sdk.api.package_managers_api", "PackageManagersApi", "update_asset_package_manager_status"),
    # Vulnerability Intelligence
    ("watchtowr_api_sdk.api.vulnerability_intelligence_api", "VulnerabilityIntelligenceApi", "get_list_vulnerability_intelligence"),
    ("watchtowr_api_sdk.api.vulnerability_intelligence_api", "VulnerabilityIntelligenceApi", "get_vulnerability_intelligence_details"),
    # Adversary Intelligence
    ("watchtowr_api_sdk.api.adversary_intelligence_api", "AdversaryIntelligenceApi", "get_list_adversary_intelligence"),
    ("watchtowr_api_sdk.api.adversary_intelligence_api", "AdversaryIntelligenceApi", "get_adversary_intelligence_details"),
    # Compromised Endpoints
    # ("watchtowr_api_sdk.api.compromised_endpoints_api", "CompromisedEndpointsApi", "get_list_compromised_endpoints"),
    # ("watchtowr_api_sdk.api.compromised_endpoints_api", "CompromisedEndpointsApi", "get_list_compromised_endpoint_harvested_credentials"),
    # Credential Attempt Logs
    # ("watchtowr_api_sdk.api.credential_attempt_logs_api", "CredentialAttemptLogsApi", "get_list_credential_attempt_logs"),
    # Finding Retest History
    ("watchtowr_api_sdk.api.finding_retest_history_api", "FindingRetestHistoryApi", "get_list_finding_retest_history"),
    # DNS records
    ("watchtowr_api_sdk.api.dns_record_analysis_api", "DNSRecordAnalysisApi", "get_list_dns_records"),
    # Pending domains
    ("watchtowr_api_sdk.api.pending_domains_api", "PendingDomainsApi", "get_list_pending_domains"),
    # Security posture dashboard
    ("watchtowr_api_sdk.api.security_posture_dashboard_api", "SecurityPostureDashboardApi", "get_security_posture_dashboard"),
    # Active defense library
    ("watchtowr_api_sdk.api.active_defense_library_api", "ActiveDefenseLibraryApi", "get_list_active_defense_library_rules"),
    # Capability search
    ("watchtowr_api_sdk.api.capability_search_api", "CapabilitySearchApi", "capability_search"),
    # Changelogs
    ("watchtowr_api_sdk.api.api_documentation_api", "APIDocumentationApi", "get_asset_api_documentation_changelog"),
    ("watchtowr_api_sdk.api.cloud_integration_assets_api", "CloudIntegrationAssetsApi", "get_asset_cloud_asset_changelog"),
    ("watchtowr_api_sdk.api.cloud_storage_api", "CloudStorageApi", "get_asset_cloud_storage_changelog"),
    ("watchtowr_api_sdk.api.containers_api", "ContainersApi", "get_asset_container_changelog"),
    ("watchtowr_api_sdk.api.domains_api", "DomainsApi", "get_asset_domain_changelog"),
    ("watchtowr_api_sdk.api.ip_addresses_api", "IPAddressesApi", "get_asset_ip_changelog"),
    ("watchtowr_api_sdk.api.ip_ranges_api", "IPRangesApi", "get_asset_iprange_changelog"),
    ("watchtowr_api_sdk.api.mobile_applications_api", "MobileApplicationsApi", "get_asset_mobile_app_changelog"),
    ("watchtowr_api_sdk.api.package_managers_api", "PackageManagersApi", "get_asset_package_manager_changelog"),
    ("watchtowr_api_sdk.api.repositories_api", "RepositoriesApi", "get_asset_repository_changelog"),
    ("watchtowr_api_sdk.api.saa_s_platforms_api", "SaaSPlatformsApi", "get_asset_saas_platform_changelog"),
    ("watchtowr_api_sdk.api.subdomains_api", "SubdomainsApi", "get_asset_subdomain_changelog"),
]



MODEL_IMPORTS = [
    ("watchtowr_api_sdk.models.update_client_finding_status_request_body", "UpdateClientFindingStatusRequestBody"),
    ("watchtowr_api_sdk.models.update_client_legacy_asset_status_dto", "UpdateClientLegacyAssetStatusDto"),
    ("watchtowr_api_sdk.models.update_client_next_gen_asset_status_dto", "UpdateClientNextGenAssetStatusDto"),
    ("watchtowr_api_sdk.models.create_client_seed_data_request_body", "CreateClientSeedDataRequestBody"),
    ("watchtowr_api_sdk.models.client_seed_data", "ClientSeedData"),
]


INFRA_IMPORTS = [
    ("watchtowr_api_sdk.configuration", "Configuration"),
    ("watchtowr_api_sdk.api_client", "ApiClient"),
]


@pytest.mark.parametrize("module,cls,method", SDK_CALLS)
def test_sdk_method_resolves(module, cls, method):
    mod = importlib.import_module(module)
    api_class = getattr(mod, cls, None)
    assert api_class is not None, f"{module}.{cls} not found in SDK"
    assert hasattr(api_class, method), f"{cls}.{method} missing — SDK drift"


@pytest.mark.parametrize("module,cls", MODEL_IMPORTS)
def test_sdk_model_resolves(module, cls):
    mod = importlib.import_module(module)
    assert hasattr(mod, cls), f"{module}.{cls} missing — SDK drift"


@pytest.mark.parametrize("module,cls", INFRA_IMPORTS)
def test_sdk_infra_resolves(module, cls):
    mod = importlib.import_module(module)
    assert hasattr(mod, cls), f"{module}.{cls} missing — SDK drift"


def test_sdk_call_count_matches_expectation():
    """If this fails, the SDK_CALLS list and the MCP source have drifted."""
    assert len(SDK_CALLS) == 85, (
        "Expected 85 distinct SDK (class, method) call sites. Update both this "
        "constant and SDK_CALLS when you add/remove an SDK call in the MCP tools."
    )



# ─────────────────────────────────────────────────────────────────────────────
# Meta-test: AST-walk the MCP source and compare discovered SDK calls against
# the hand-written SDK_CALLS constant above. Catches PRs that add a new SDK
# call to a tools/*.py file without updating SDK_CALLS.
# ─────────────────────────────────────────────────────────────────────────────


def _collect_python_files() -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for d in MCP_SOURCE_DIRS:
        for f in d.rglob("*.py"):
            if f in seen:
                continue
            seen.add(f)
            files.append(f)
    return files


class _SDKCallVisitor(ast.NodeVisitor):
    """Find (api_class, method) pairs the MCP source invokes against the SDK.

    Recognises three patterns:

    1. Variable assignment + attribute call::

           api = FindingsApi(client)
           api.get_list_findings(...)

    2. Direct constructor chain::

           FindingsApi(client).get_list_findings(...)

    3. Class+method-name pairs carried in tuple literals (dispatch tables)::

           _ASSET_API_MAP = [("Domains", DomainsApi, "get_list_asset_domains"), ...]
           legacy_types = {"domain": (DomainsApi, "update_asset_domain_status")}

       The second/third element pattern handles both 2-tuples and 3-tuples.
    """

    def __init__(self, imported_api_classes: dict[str, str]):
        # class_name -> module dotted path (e.g. "FindingsApi" -> "watchtowr_api_sdk.api.findings_api")
        self.imported = imported_api_classes
        # local variable name -> class name
        self.var_to_class: dict[str, str] = {}
        # discovered (module, class, method) triples
        self.calls: set[tuple[str, str, str]] = set()

    def _record(self, cls_name: str, method: str) -> None:
        module = self.imported.get(cls_name)
        if module:
            self.calls.add((module, cls_name, method))

    def visit_Assign(self, node: ast.Assign) -> None:
        # `var = SomeApi(...)` → remember var → class
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in self.imported
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.var_to_class[target.id] = node.value.func.id
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # `var.method` where var is bound to an Api class
        if isinstance(node.value, ast.Name):
            cls = self.var_to_class.get(node.value.id)
            if cls:
                self._record(cls, node.attr)
        # `SomeApi(...).method`
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if node.value.func.id in self.imported:
                self._record(node.value.func.id, node.attr)
        self.generic_visit(node)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        self._scan_class_method_literal(node.elts)
        self.generic_visit(node)

    def _scan_class_method_literal(self, elts: list[ast.expr]) -> None:
        # (Class, "method") OR (label, Class, "method") — scan for adjacent
        # Name-of-known-class followed by a string Constant.
        for i, elt in enumerate(elts):
            if not (isinstance(elt, ast.Name) and elt.id in self.imported):
                continue
            if i + 1 >= len(elts):
                continue
            nxt = elts[i + 1]
            if isinstance(nxt, ast.Constant) and isinstance(nxt.value, str):
                self._record(elt.id, nxt.value)


def _collect_imports(tree: ast.Module) -> dict[str, str]:
    """Map `class_name` -> `module` for `from watchtowr_api_sdk.api.<mod> import <Class>`."""
    imported: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if not node.module or not node.module.startswith("watchtowr_api_sdk.api."):
            continue
        for alias in node.names:
            name = alias.asname or alias.name
            imported[name] = node.module
    return imported


def _discover_sdk_calls() -> set[tuple[str, str, str]]:
    discovered: set[tuple[str, str, str]] = set()
    for path in _collect_python_files():
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError:
            continue
        imported = _collect_imports(tree)
        if not imported:
            continue
        visitor = _SDKCallVisitor(imported)
        visitor.visit(tree)
        discovered |= visitor.calls
    return discovered


def test_sdk_calls_match_source():
    """SDK_CALLS must mirror what the MCP source actually invokes.

    If you add a new `<ApiClass>.<method>` call site to a tools/*.py file and
    forget to append it to SDK_CALLS above, this test fails with the missing
    triple. Likewise if you remove a call site but leave SDK_CALLS stale.
    """
    declared = set(SDK_CALLS)
    discovered = _discover_sdk_calls()

    missing_from_constant = discovered - declared
    stale_in_constant = declared - discovered

    msg_lines = []
    if missing_from_constant:
        msg_lines.append(
            "SDK call sites found in source but NOT listed in SDK_CALLS — append these:"
        )
        for triple in sorted(missing_from_constant):
            msg_lines.append(f"  {triple!r},")
    if stale_in_constant:
        msg_lines.append(
            "SDK_CALLS entries that no source file actually calls — remove these:"
        )
        for triple in sorted(stale_in_constant):
            msg_lines.append(f"  {triple!r},")
    assert not msg_lines, "\n" + "\n".join(msg_lines)
