from __future__ import annotations

from types import SimpleNamespace as NS

import pytest
from watchtowr_api_sdk.api.domains_api import DomainsApi
from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.api.ip_addresses_api import IPAddressesApi
from watchtowr_api_sdk.api.ports_api import PortsApi
from watchtowr_api_sdk.api.service_discovery_api import ServiceDiscoveryApi
from watchtowr_api_sdk.api.subdomains_api import SubdomainsApi

import watchtowr_mcp_server.client as client_module


def _finding(fid, asset_type, asset_id, name):
    return NS(id=fid, title=f"finding-{fid}", severity="high", status="confirmed",
              affected={"data": {"type": asset_type, "id": str(asset_id), "name": name}})


def _port_finding(fid, port_id, ip_id):
    return NS(id=fid, title=f"finding-{fid}", severity="high", status="confirmed",
              affected={"data": {"type": "TCP", "id": str(port_id), "ip_id": ip_id, "port": 443}})


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())

    def stub(cls, method, response):
        monkeypatch.setattr(cls, method, lambda *a, **k: response)
    return stub


def test_ip_does_not_return_findings_on_longer_ips(tools, api):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(FindingsApi, "get_list_findings", NS(data=[
        _finding(1, "ip", 1, "192.0.2.1"),
        _finding(2, "ip", 10, "192.0.2.10"),
        _finding(3, "ip", 100, "192.0.2.100"),
    ], meta=None))

    out = tools["get_findings_by_asset"](asset_type="ip", asset_id=1)

    assert "[ID:1]" in out
    assert "[ID:2]" not in out and "[ID:3]" not in out
    assert "Removed 2 finding(s)" in out


def test_domain_does_not_return_findings_on_similar_domains(tools, api):
    api(DomainsApi, "get_asset_domain_details", NS(data=NS(name="example.com")))
    api(FindingsApi, "get_list_findings", NS(data=[
        _finding(1, "domain", 7, "example.com"),
        _finding(2, "domain", 8, "notexample.com"),
        _finding(3, "domain", 9, "example.com.au"),
    ], meta=None))

    out = tools["get_findings_by_asset"](asset_type="domain", asset_id=7)

    assert "[ID:1]" in out
    assert "[ID:2]" not in out and "[ID:3]" not in out
    assert "Removed 2 finding(s)" in out


def test_port_shows_only_its_own_findings(tools, api):
    api(PortsApi, "get_asset_port_details", NS(data=NS(ip="192.0.2.1", port=443)))
    api(FindingsApi, "get_list_findings", NS(data=[
        _port_finding(1, port_id=5, ip_id=1),
        _port_finding(2, port_id=6, ip_id=1),
        _finding(3, "ip", 5, "192.0.2.1"),
    ], meta=None))

    out = tools["get_findings_by_asset"](asset_type="port", asset_id=5)

    assert "[ID:1]" in out
    assert "[ID:2]" not in out and "[ID:3]" not in out


def test_ip_keeps_findings_on_its_own_ports(tools, api):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(FindingsApi, "get_list_findings", NS(data=[
        _finding(1, "ip", 1, "192.0.2.1"),
        _port_finding(2, port_id=5, ip_id=1),
        _port_finding(3, port_id=6, ip_id=10),
    ], meta=None))

    out = tools["get_findings_by_asset"](asset_type="ip", asset_id=1)

    assert "[ID:1]" in out and "[ID:2]" in out
    assert "[ID:3]" not in out
    assert "Removed 1 finding(s)" in out


def test_only_near_matches_reads_as_no_findings(tools, api):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(FindingsApi, "get_list_findings", NS(data=[_finding(2, "ip", 10, "192.0.2.10")], meta=None))

    out = tools["get_findings_by_asset"](asset_type="ip_address", asset_id=1)

    assert out.startswith("No findings found")
    assert "Removed 1 finding(s)" in out


def test_related_subdomains_match_on_label_boundary(tools, api):
    api(DomainsApi, "get_asset_domain_details", NS(data=NS(name="example.com")))
    api(SubdomainsApi, "get_list_asset_subdomains", NS(data=[
        NS(name="shop.example.com", status="verified"),
        NS(name="shop.notexample.com", status="verified"),
        NS(name="example.com.au", status="verified"),
    ], meta=None))

    out = tools["find_related_assets"](asset_id=1, asset_type="domain")

    assert "shop.example.com" in out
    assert "notexample.com" not in out and "example.com.au" not in out
    assert "Subdomains (1):" in out
    assert "Removed 2 subdomain(s) under similarly named domains" in out


def test_related_ip_findings_exclude_longer_ips(tools, api):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(IPAddressesApi, "get_asset_ip_ports", NS(data=[], meta=None))
    api(ServiceDiscoveryApi, "get_list_service_listing", NS(data=[], meta=None))
    api(FindingsApi, "get_list_findings", NS(data=[
        _finding(1, "ip", 1, "192.0.2.1"),
        _finding(2, "ip", 10, "192.0.2.10"),
    ], meta=None))

    out = tools["find_related_assets"](asset_id=1, asset_type="ip")

    assert "Findings (1):" in out
    assert "[ID:1]" in out and "[ID:2]" not in out
    assert "Removed 1 finding(s)" in out


def test_related_subdomain_findings_exclude_similar_subdomains(tools, api):
    api(SubdomainsApi, "get_asset_subdomain_details", NS(data=NS(name="shop.example.com")))
    api(ServiceDiscoveryApi, "get_list_service_listing", NS(data=[], meta=None))
    api(FindingsApi, "get_list_findings", NS(data=[
        _finding(1, "subdomain", 3, "SHOP.example.com"),
        _finding(2, "subdomain", 4, "shop.example.com.evil.net"),
    ], meta=None))

    out = tools["find_related_assets"](asset_id=3, asset_type="subdomain")

    assert "[ID:1]" in out and "[ID:2]" not in out


def _service(ip, port, service, hostname=None):
    return NS(ip=ip, hostname=hostname, port=port, service=service, technologies=[], ip_id=None)


def test_related_ip_services_exclude_longer_ips(tools, api):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(IPAddressesApi, "get_asset_ip_ports", NS(data=[], meta=None))
    api(ServiceDiscoveryApi, "get_list_service_listing", NS(data=[
        _service("192.0.2.1", 22, "ssh"),
        _service("192.0.2.10", 3389, "ms-wbt-server"),
        _service("192.0.2.100", 5900, "vnc"),
    ], meta=None))
    api(FindingsApi, "get_list_findings", NS(data=[], meta=None))

    out = tools["find_related_assets"](asset_id=1, asset_type="ip")

    assert "Services on 192.0.2.1:\n  • :22 (" in out
    assert "3389" not in out and "5900" not in out
    assert "(Removed 2 service(s) on other hosts.)" in out


def test_related_ip_with_only_other_hosts_services_says_none_on_this_host(tools, api):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(IPAddressesApi, "get_asset_ip_ports", NS(data=[], meta=None))
    api(ServiceDiscoveryApi, "get_list_service_listing", NS(data=[_service("192.0.2.10", 3389, "ms-wbt-server")], meta=None))
    api(FindingsApi, "get_list_findings", NS(data=[], meta=None))

    out = tools["find_related_assets"](asset_id=1, asset_type="ip")

    assert "Services: none on this host.\n  (Removed 1 service(s) on other hosts.)" in out
    assert "Services on 192.0.2.1" not in out


def test_related_subdomain_services_keep_its_resolved_ips_and_its_own_ports(tools, api):
    api(SubdomainsApi, "get_asset_subdomain_details", NS(data=NS(
        name="shop.example.com", dns_records=[NS(type="A", value="192.0.2.1"), NS(type="CNAME", value="192.0.2.7")])))
    api(FindingsApi, "get_list_findings", NS(data=[], meta=None))
    api(ServiceDiscoveryApi, "get_list_service_listing", NS(data=[
        _service("192.0.2.1", 443, "https"),
        _service("192.0.2.5", 8443, "https-alt", hostname="SHOP.example.com"),
        _service("192.0.2.7", 25, "smtp"),
        _service("192.0.2.9", 8080, "http-proxy", hostname="shop.example.com.evil.net"),
    ], meta=None))

    out = tools["find_related_assets"](asset_id=3, asset_type="subdomain")

    assert "192.0.2.1:443" in out and "192.0.2.5:8443" in out
    assert "192.0.2.7" not in out and "192.0.2.9" not in out
    assert "(Removed 2 service(s) on other hosts.)" in out


def test_related_subdomain_without_records_or_own_ports_says_none_on_this_host(tools, api):
    api(SubdomainsApi, "get_asset_subdomain_details", NS(data=NS(name="shop.example.com", dns_records=[])))
    api(FindingsApi, "get_list_findings", NS(data=[], meta=None))
    api(ServiceDiscoveryApi, "get_list_service_listing", NS(data=[_service("192.0.2.9", 8080, "http-proxy")], meta=None))

    out = tools["find_related_assets"](asset_id=3, asset_type="subdomain")

    assert "\nServices: none on this host.\n  (Removed 1 service(s) on other hosts.)" in out


def test_search_is_narrowed_to_the_asset_type(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    monkeypatch.setattr(IPAddressesApi, "get_asset_ip_details", lambda *a, **k: NS(data=NS(name="192.0.2.1")))
    seen = {}
    monkeypatch.setattr(FindingsApi, "get_list_findings", lambda *a, **k: seen.update(k) or NS(data=[], meta=None))

    tools["get_findings_by_asset"](asset_type="ip_address", asset_id=1)

    assert seen["asset_types"] == "ip"


def test_full_page_of_near_matches_does_not_claim_no_findings(tools, api):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(FindingsApi, "get_list_findings", NS(
        data=[_finding(i, "ip", 10 + i, f"192.0.2.1{i}") for i in range(30)],
        meta=NS(pagination=NS(total=200)),
    ))

    out = tools["get_findings_by_asset"](asset_type="ip", asset_id=1)

    assert out.startswith("No exact matches in the first 90 findings")
    assert "matched 200 finding(s) by name" in out


def _paged(monkeypatch, pages, total):
    calls = []

    def list_findings(*a, page=1, **k):
        calls.append(page)
        return NS(data=pages[page - 1], meta=NS(pagination=NS(total=total)))
    monkeypatch.setattr(FindingsApi, "get_list_findings", list_findings)
    return calls


def _near_matches(start):
    return [_finding(start + i, "ip", 10 + i, f"192.0.2.1{i}") for i in range(30)]


def test_exact_match_on_a_later_page_is_found(tools, api, monkeypatch):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    calls = _paged(monkeypatch, [_near_matches(100), [_finding(1, "ip", 1, "192.0.2.1")]], total=31)

    out = tools["get_findings_by_asset"](asset_type="ip", asset_id=1)

    assert calls == [1, 2]
    assert "[ID:1]" in out
    assert "Removed 30 finding(s)" in out


def test_stops_after_three_pages_of_near_matches(tools, api, monkeypatch):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    calls = _paged(monkeypatch, [_near_matches(100 * p) for p in range(1, 5)], total=120)

    tools["get_findings_by_asset"](asset_type="ip", asset_id=1)

    assert calls == [1, 2, 3]


def test_related_ip_with_only_near_matches_says_none_for_this_asset(tools, api):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(IPAddressesApi, "get_asset_ip_ports", NS(data=[], meta=None))
    api(ServiceDiscoveryApi, "get_list_service_listing", NS(data=[], meta=None))
    api(FindingsApi, "get_list_findings", NS(data=[_finding(2, "ip", 10, "192.0.2.10")], meta=None))

    out = tools["find_related_assets"](asset_id=1, asset_type="ip")

    assert "Findings: none for this asset.\n  (Removed 1 finding(s)" in out


def test_related_ip_capped_with_only_near_matches_says_none_in_the_first_checked(tools, api, monkeypatch):
    api(IPAddressesApi, "get_asset_ip_details", NS(data=NS(name="192.0.2.1")))
    api(IPAddressesApi, "get_asset_ip_ports", NS(data=[], meta=None))
    api(ServiceDiscoveryApi, "get_list_service_listing", NS(data=[], meta=None))
    _paged(monkeypatch, [_near_matches(100 * p) for p in range(1, 4)], total=200)

    out = tools["find_related_assets"](asset_id=1, asset_type="ip")

    assert "Findings: none in the first 90 checked." in out
    assert "none for this asset" not in out


def test_related_domain_with_only_similar_subdomains_says_none(tools, api):
    api(DomainsApi, "get_asset_domain_details", NS(data=NS(name="example.com")))
    api(SubdomainsApi, "get_list_asset_subdomains", NS(data=[
        NS(name="shop.notexample.com", status="verified"),
        NS(name="example.com.au", status="verified"),
    ], meta=None))

    out = tools["find_related_assets"](asset_id=1, asset_type="domain")

    assert "Subdomains: none under this domain.\n  (Removed 2 subdomain(s)" in out


def test_findings_by_asset_docstring_states_the_real_cap(tools):
    cap = client_module.EXACT_MATCH_MAX_PAGES * client_module.EXACT_MATCH_PAGE_SIZE
    assert f"At most the first {cap} findings" in tools["get_findings_by_asset"].__doc__
