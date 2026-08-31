"""Live-API tests for the 22 read-only Assets tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_list_asset_ips(live_env, call):
    assert_ok(call("list_asset_ips", page_size=5), allow_empty=True)


def test_list_asset_ips_with_new_filters(live_env, call):
    assert_ok(call("list_asset_ips", page_size=5, source="test", match_type="exact", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_asset_ip_details(live_env, call, sample_ip_id):
    assert_ok(call("get_asset_ip_details", ip_id=sample_ip_id))


def test_list_ports_for_ip(live_env, call, sample_ip_id):
    assert_ok(call("list_ports_for_ip", ip_id=sample_ip_id, page_size=5), allow_empty=True)


def test_list_ports_for_ip_with_new_filters(live_env, call, sample_ip_id):
    assert_ok(call("list_ports_for_ip", ip_id=sample_ip_id, page_size=5, include_closed_port=True, include_no_service=True), allow_empty=True)


def test_get_ip_port_details(live_env, call, sample_ip_id):
    # We need a port ID scoped to this IP. Pull one out of list_ports_for_ip.
    response = call("list_ports_for_ip", ip_id=sample_ip_id, page_size=5)
    if isinstance(response, str) and response.startswith("Error"):
        pytest.skip(f"list_ports_for_ip errored: {response}")
    import re
    match = re.search(r"\[ID:(\d+)\]", response or "")
    if not match:
        pytest.skip("sample IP has no ports — cannot exercise get_ip_port_details")
    port_id = match.group(1)
    assert_ok(call("get_ip_port_details", ip_id=str(sample_ip_id), port_id=port_id))


def test_list_asset_domains(live_env, call):
    assert_ok(call("list_asset_domains", page_size=5), allow_empty=True)


def test_get_asset_domain_details(live_env, call, sample_domain_id):
    assert_ok(call("get_asset_domain_details", domain_id=sample_domain_id))


def test_list_asset_subdomains(live_env, call):
    assert_ok(call("list_asset_subdomains", page_size=5), allow_empty=True)


def test_get_asset_subdomain_details(live_env, call, sample_subdomain_id):
    assert_ok(call("get_asset_subdomain_details", subdomain_id=sample_subdomain_id))


def test_list_asset_ports(live_env, call):
    assert_ok(call("list_asset_ports", page_size=5), allow_empty=True)


def test_list_asset_ports_with_new_filters(live_env, call):
    assert_ok(call("list_asset_ports", page_size=5, include_closed_port=True, include_no_service=True, custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_asset_port_details(live_env, call, sample_port_id):
    assert_ok(call("get_asset_port_details", port_id=sample_port_id))


def test_list_asset_ip_ranges(live_env, call):
    assert_ok(call("list_asset_ip_ranges", page_size=5), allow_empty=True)


def test_list_asset_ip_ranges_with_new_filters(live_env, call):
    assert_ok(call("list_asset_ip_ranges", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_asset_iprange_details(live_env, call, sample_iprange_id):
    assert_ok(call("get_asset_iprange_details", iprange_id=sample_iprange_id))


def test_list_cloud_storage_assets(live_env, call):
    assert_ok(call("list_cloud_storage_assets", page_size=5), allow_empty=True)


def test_list_cloud_storage_assets_with_new_filters(live_env, call):
    assert_ok(call("list_cloud_storage_assets", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_asset_cloud_storage_details(live_env, call, sample_cloud_storage_id):
    assert_ok(call("get_asset_cloud_storage_details", cloud_storage_id=sample_cloud_storage_id))


def test_list_source_code_repositories(live_env, call):
    assert_ok(call("list_source_code_repositories", page_size=5), allow_empty=True)


def test_list_source_code_repositories_with_new_filters(live_env, call):
    assert_ok(call("list_source_code_repositories", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_asset_repository_details(live_env, call, sample_repo_id):
    assert_ok(call("get_asset_repository_details", repository_id=sample_repo_id))


def test_list_container_assets(live_env, call):
    assert_ok(call("list_container_assets", page_size=5), allow_empty=True)


def test_list_container_assets_with_new_filters(live_env, call):
    assert_ok(call("list_container_assets", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_asset_container_details(live_env, call, sample_container_id):
    assert_ok(call("get_asset_container_details", container_id=sample_container_id))


def test_list_saas_platforms(live_env, call):
    assert_ok(call("list_saas_platforms", page_size=5), allow_empty=True)


def test_list_saas_platforms_with_new_filters(live_env, call):
    assert_ok(call("list_saas_platforms", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_asset_saas_details(live_env, call, sample_saas_id):
    assert_ok(call("get_asset_saas_details", saas_id=sample_saas_id))


def test_list_mobile_app_assets(live_env, call):
    assert_ok(call("list_mobile_app_assets", page_size=5), allow_empty=True)


def test_list_mobile_app_assets_with_new_filters(live_env, call):
    assert_ok(call("list_mobile_app_assets", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_asset_mobile_app_details(live_env, call, sample_mobile_id):
    assert_ok(call("get_asset_mobile_app_details", mobile_app_id=sample_mobile_id))


def test_list_cloud_assets(live_env, call):
    assert_ok(call("list_cloud_assets", page_size=5), allow_empty=True)


def test_list_cloud_assets_with_new_filters(live_env, call):
    assert_ok(call("list_cloud_assets", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_cloud_asset_details(live_env, call, sample_cloud_asset_id):
    assert_ok(call("get_cloud_asset_details", cloud_asset_id=sample_cloud_asset_id))


def test_list_api_documentations(live_env, call):
    assert_ok(call("list_api_documentations", page_size=5), allow_empty=True)


def test_list_api_documentations_with_new_filters(live_env, call):
    assert_ok(call("list_api_documentations", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_api_documentation_details(live_env, call, sample_api_documentation_id):
    assert_ok(call("get_api_documentation_details", api_documentation_id=sample_api_documentation_id))


def test_list_package_managers(live_env, call):
    assert_ok(call("list_package_managers", page_size=5), allow_empty=True)


def test_list_package_managers_with_new_filters(live_env, call):
    assert_ok(call("list_package_managers", page_size=5, source="test", custom_property_key="env", custom_property_value="prod"), allow_empty=True)


def test_get_package_manager_details(live_env, call, sample_package_manager_id):
    assert_ok(call("get_package_manager_details", package_manager_id=sample_package_manager_id))

