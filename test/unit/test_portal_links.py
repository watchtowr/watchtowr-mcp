from __future__ import annotations

from typing import NamedTuple

import pytest
from fastmcp.exceptions import ToolError
from watchtowr_api_sdk.models.asset_id import AssetId

from watchtowr_mcp_server.client import portal_line, portal_link, portal_url
from test.unit.conftest import JsonReply, finding_json, page_of, port_json
from test.unit.test_points_of_interest_output import _point_json
from test.unit.test_sdk_compat import _domain_payload, _hunt_detail_payload, _hunt_payload

HOST = "https://tenant.example.io"


@pytest.fixture(autouse=True)
def platform_host(monkeypatch):
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", HOST)


@pytest.mark.parametrize(
    ("kind", "path"),
    [
        ("finding", "/findings/42"),
        ("hunt", "/hunts/42/overview"),
        ("vulnerability", "/ti/vulnerability-intelligence/42/overview"),
        ("adversary", "/ti/adversary-intelligence/42/overview"),
        ("compromised_endpoint", "/compromised-endpoints/42/overview"),
        ("business_unit", "/organisation/business-unit/42"),
        ("port", "/assets/ip/42/ports"),
    ],
)
def test_each_entity_links_to_its_portal_page(kind, path):
    assert portal_url(kind, 42) == HOST + path


@pytest.mark.parametrize(
    ("segment", "spellings"),
    [
        ("ip", ["ip", "IP", "ip_address", "IpAddress"]),
        ("domain", ["domain", "DOMAIN"]),
        ("subdomain", ["subdomain"]),
        ("ip-range", ["ipRange", "ip_range", "ip-range", "IP RANGE"]),
        ("cloud-storage", ["cloudStorage", "cloud_storage", "cloud-storage", "CLOUD STORAGE"]),
        ("repository", ["repository"]),
        ("container", ["container"]),
        ("saas-platform", ["saasPlatform", "saas_platform", "saas-platform", "SAAS PLATFORM"]),
        ("mobile-app", ["mobileApp", "mobile_app", "mobile-app", "MOBILE APP"]),
        ("cloud-asset", ["cloudAsset", "cloud_asset", "cloud-asset"]),
        ("api-documentation", ["apiDocumentation", "api_documentation", "api-documentation"]),
        ("package-manager", ["packageManager", "package_manager", "package-manager"]),
    ],
)
def test_each_asset_type_links_to_its_overview_in_any_spelling(segment, spellings):
    for asset_type in spellings:
        assert portal_url("asset", 7, asset_type) == f"{HOST}/assets/{segment}/7/overview", asset_type


@pytest.mark.parametrize("entity_id", [42, 42.0, "42", " 42 ", AssetId(42.0), AssetId("42")])
def test_whole_number_ids_link_as_digits(entity_id):
    assert portal_url("finding", entity_id) == f"{HOST}/findings/42"


@pytest.mark.parametrize("entity_id", [None, "", True, False, 42.5, -1, -1.0, "CVE-2024-1", "12a", "1,2", "٤٢", float("nan")])
def test_ids_the_portal_would_reject_get_no_link(entity_id):
    assert portal_url("finding", entity_id) is None
    assert portal_link("finding", entity_id) == ""
    assert portal_line("finding", entity_id) == []


@pytest.mark.parametrize("asset_type", [None, "", "port", "dnsRecord", "certificate"])
def test_asset_types_without_an_overview_page_get_no_link(asset_type):
    assert portal_url("asset", 7, asset_type) is None


def test_unknown_kind_gets_no_link():
    assert portal_url("suspicious_domain", 7) is None


@pytest.mark.parametrize("host", [f"{HOST}/", f'"{HOST}/"', f"  {HOST}  "])
def test_host_is_used_without_trailing_slash_quotes_or_spaces(monkeypatch, host):
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", host)
    assert portal_url("finding", 1) == f"{HOST}/findings/1"


def test_no_link_without_a_platform_host(monkeypatch):
    monkeypatch.delenv("WATCHTOWR_PLATFORM_HOST")
    assert portal_url("finding", 1) is None
    assert portal_link("finding", 1) == ""
    assert portal_line("finding", 1) == []


def test_link_and_line_formats():
    assert portal_link("finding", 1) == f" — {HOST}/findings/1"
    assert portal_link("finding", 1, label="Finding") == f" — Finding: {HOST}/findings/1"
    assert portal_line("finding", 1) == [f"Portal: {HOST}/findings/1"]


def _service_json() -> dict:
    return {
        "id": 21, "portId": 9, "ip": "192.0.2.1", "port": 443, "service": "https", "ipId": 4, "findingId": 5,
        "technologies": [], "serviceTypes": [], "businessUnits": [], "isConcerning": False, "suppressed": False,
    }


def _hunt_asset_json() -> dict:
    return {
        "id": 7, "created_at": "2026-05-29T16:10:47Z", "source": None, "type": "subdomain", "status": "verified",
        "name": "www.example.com", "country": None, "platform": None, "provider": None, "url": None,
        "businessUnits": [], "discovery_reason": None, "owner": None, "live": True, "sub_type": None,
        "super_type": None, "metadata": {},
    }


def _compromised_endpoint_json() -> dict:
    return {
        "id": 13, "hostname": "workstation", "ip": None, "stealerId": "s-1", "stealerFamily": None,
        "status": "pending", "dateCompromised": None, "operatingSystem": None, "malwarePath": None, "country": None,
        "discoveryType": None, "discoveryValue": None, "createdAt": "2026-05-29", "updatedAt": "2026-05-29",
    }


def _business_unit_detail_json() -> dict:
    return {"data": {
        "id": 14, "name": "Example Business Unit", "description": None, "type": "custom",
        "created_at": "2026-05-29T16:10:47Z", "updated_at": "2026-05-29T16:10:47Z", "rules": {},
    }}


class LinkCase(NamedTuple):
    tool: str
    args: dict
    routes: dict[str, dict]
    marker: str
    url: str


LINK_CASES = [
    LinkCase("search_findings", {}, {r"/findings/list$": page_of([finding_json(5)])},
             "[ID:5", f"{HOST}/findings/5"),
    LinkCase("get_finding_details", {"finding_id": 5}, {r"/findings/show/5(\.0)?$": {"data": finding_json(5)}},
             "Portal:", f"{HOST}/findings/5"),
    LinkCase("get_finding_details", {"finding_id": 5}, {r"/findings/show/5(\.0)?$": {"data": finding_json(5)}},
             "Affected Asset:", f"{HOST}/assets/domain/3/overview"),
    LinkCase("get_finding_details", {"finding_id": 5},
             {r"/findings/show/5(\.0)?$": {"data": finding_json(5, {"type": "PORT", "id": 9, "ip_id": 4, "port": 443})}},
             "Affected Asset:", f"{HOST}/assets/ip/4/ports"),
    LinkCase("list_recent_hunts", {}, {r"/hunts/list$": page_of([_hunt_payload("Misconfig")])},
             "[ID:42", f"{HOST}/hunts/42/overview"),
    LinkCase("get_hunt_details", {"hunt_id": 42}, {r"/hunts/show/42(\.0)?$": {"data": _hunt_detail_payload(None)}},
             "Portal:", f"{HOST}/hunts/42/overview"),
    LinkCase("list_assets_by_hunt", {"hunt_id": 42}, {r"/hunts/show/42(\.0)?/assets$": page_of([_hunt_asset_json()])},
             "www.example.com", f"{HOST}/assets/subdomain/7/overview"),
    LinkCase("list_asset_domains", {}, {r"/assets/domain/list$": page_of([_domain_payload({})])},
             "[ID:101]", f"{HOST}/assets/domain/101/overview"),
    LinkCase("list_asset_ports", {}, {r"/assets/ip/port/list$": page_of([port_json()])},
             "[ID:9]", f"{HOST}/assets/ip/4/ports"),
    LinkCase("search_dns_records", {},
             {r"/dns-records/list$": page_of([{
                 "id": 1, "recordName": "example.com", "type": "A", "value": "192.0.2.1",
                 "createdAt": "2026-05-29T16:10:47Z", "asset": {"id": 3, "name": "example.com", "type": "domain"},
             }])},
             "example.com (domain)", f"{HOST}/assets/domain/3/overview"),
    LinkCase("get_asset_changelog", {"asset_type": "domain", "asset_id": 3},
             {r"/assets/domain/show/3(\.0)?/changelog$": {
                 "data": [{"created_at": "2026-05-29T16:10:47Z", "type": "updated", "description": "renamed"}],
                 "meta": {"pagination": {"total": 1}},
             }},
             "Portal:", f"{HOST}/assets/domain/3/overview"),
    LinkCase("get_stale_findings", {}, {r"/findings/list$": page_of([finding_json(5)])},
             "[ID:5", f"{HOST}/findings/5"),
    LinkCase("get_new_assets_since", {}, {r"/assets/ip/port/list$": page_of([port_json()])},
             "• 192.0.2.1:443 (verified)", f"{HOST}/assets/ip/4/ports"),
    LinkCase("get_out_of_scope_assets", {}, {r"/assets/domain/list$": page_of([_domain_payload({})])},
             "example.com", f"{HOST}/assets/domain/101/overview"),
    LinkCase("get_asset_inventory_by_business_unit", {"business_unit_id": 14},
             {r"/business-unit/show/14(\.0)?$": _business_unit_detail_json(),
              r"/assets/domain/list$": page_of([_domain_payload({})])},
             "Asset Inventory:", f"{HOST}/organisation/business-unit/14"),
    LinkCase("get_asset_inventory_by_business_unit", {"business_unit_id": 14},
             {r"/business-unit/show/14(\.0)?$": _business_unit_detail_json(),
              r"/assets/domain/list$": page_of([_domain_payload({})])},
             "• example.com", f"{HOST}/assets/domain/101/overview"),
    LinkCase("get_assets_by_technology", {"technology_search": "nginx"},
             {r"/service-listing/list$": page_of([_service_json()])},
             "192.0.2.1:443", f"{HOST}/assets/ip/4/ports"),
    LinkCase("get_recent_remediations", {}, {r"/findings/list$": page_of([finding_json(5)])},
             "[ID:5", f"{HOST}/findings/5"),
    LinkCase("list_services", {}, {r"/service-listing/list$": page_of([_service_json()])},
             "[ID:21", f"Ports: {HOST}/assets/ip/4/ports"),
    LinkCase("list_services", {}, {r"/service-listing/list$": page_of([_service_json()])},
             "[ID:21", f"Finding: {HOST}/findings/5"),
    LinkCase("list_points_of_interest", {},
             {r"/points-of-interest/list$": page_of([
                 {**_point_json(1), "assetId": 3, "assetName": "example.com", "assetType": "domain", "findingId": 5},
             ])},
             "[ID:1", f"Asset: {HOST}/assets/domain/3/overview"),
    LinkCase("list_points_of_interest", {},
             {r"/points-of-interest/list$": page_of([
                 {**_point_json(1), "assetId": 3, "assetName": "example.com", "assetType": "domain", "findingId": 5},
             ])},
             "[ID:1", f"Finding: {HOST}/findings/5"),
    LinkCase("get_vulnerability_intelligence_details", {"identifier": "CVE-2023-27350"},
             {r"/vulnerability-intelligence/show/": {"data": {
                 "vulnerabilityId": 11, "cveId": "CVE-2023-27350", "displayName": "CVE-2023-27350 example",
                 "affectedKbEntryIds": [], "isAffected": False,
             }}},
             "Portal:", f"{HOST}/ti/vulnerability-intelligence/11/overview"),
    LinkCase("list_adversary_intelligence", {},
             {r"/adversary-intelligence/list$": page_of([
                 {"attackerId": 12, "name": "Example Adversary", "type": "APT", "isAffected": False},
             ])},
             "[ID:12", f"{HOST}/ti/adversary-intelligence/12/overview"),
    LinkCase("list_compromised_endpoints", {},
             {r"/compromised-endpoints/list$": page_of([_compromised_endpoint_json()])},
             "[ID:13", f"{HOST}/compromised-endpoints/13/overview"),
    LinkCase("list_business_units", {},
             {r"/business-unit/list$": page_of([{
                 "id": 14, "name": "Example Business Unit", "description": None, "type": "manual",
                 "created_at": "2026-05-29T16:10:47Z", "updated_at": "2026-05-29T16:10:47Z",
             }])},
             "[ID:14", f"{HOST}/organisation/business-unit/14"),
]


@pytest.mark.parametrize("case", LINK_CASES, ids=[f"{case.tool}:{case.url.split(HOST)[-1]}" for case in LINK_CASES])
def test_tools_print_the_portal_link_on_the_entity_line(case, tools, fake_platform):
    fake_platform.route(r".", JsonReply(page_of([])))
    for path, body in case.routes.items():
        fake_platform.route(path, JsonReply(body))

    out = tools[case.tool](**case.args)

    line = next((line for line in out.splitlines() if case.marker in line), None)
    assert line is not None, f"no line with {case.marker!r}:\n{out}"
    assert case.url in line, f"{case.tool} line lacks {case.url}:\n{out}"


def test_export_finding_pdf_names_the_finding_it_links_to(tools, fake_platform):
    fake_platform.route(r"/findings/show/5(\.0)?$", JsonReply({"data": finding_json(5)}))

    out = tools["export_finding_pdf"](finding_id=5)

    assert out == (
        "This tool cannot return the PDF. Open finding 5 (Example finding) in the watchTowr Platform "
        "and export the PDF there.\n"
        f"Portal: {HOST}/findings/5"
    )


def test_export_finding_pdf_gives_no_link_for_a_finding_the_platform_cannot_find(tools, fake_platform):
    fake_platform.route(r"/findings/show/", JsonReply({"message": "Not Found"}, status=404))

    with pytest.raises(ToolError, match="404"):
        tools["export_finding_pdf"](finding_id=999999999)


def test_affected_port_without_its_ip_gets_no_link(tools, fake_platform):
    affected = {"type": "port", "id": 9, "port": 443}
    fake_platform.route(r"/findings/show/5(\.0)?$", JsonReply({"data": finding_json(5, affected)}))

    out = tools["get_finding_details"](finding_id=5)

    affected_line = next(line for line in out.splitlines() if line.startswith("Affected Asset:"))
    assert HOST not in affected_line


def test_detail_portal_line_follows_the_header(tools, fake_platform):
    fake_platform.route(r"/hunts/show/42(\.0)?$", JsonReply({"data": _hunt_detail_payload(None)}))

    lines = tools["get_hunt_details"](hunt_id=42).splitlines()

    assert lines[:2] == ["Hunt #42", f"Portal: {HOST}/hunts/42/overview"]


def test_list_header_link_is_on_its_own_line(tools, fake_platform):
    fake_platform.route(r"/hunts/show/42(\.0)?/findings$", JsonReply(page_of([finding_json(5)])))

    lines = tools["list_findings_by_hunt"](hunt_id=42).splitlines()

    assert lines[0].endswith("):")
    assert lines[1] == f"Portal: {HOST}/hunts/42/overview"
    assert lines[2].endswith(f" — {HOST}/findings/5")


def test_harvested_credentials_header_link_is_on_its_own_line(tools, fake_platform):
    fake_platform.route(r"/harvested-credentials$", JsonReply(page_of([{
        "id": 31, "type": "password", "url": None, "username": None, "compromisedEndpointId": 13,
        "createdAt": "2026-05-29", "updatedAt": "2026-05-29",
    }])))

    lines = tools["get_compromised_endpoint_credentials"](endpoint_id=13).splitlines()

    assert lines[0].endswith("):")
    assert lines[1] == f"Portal: {HOST}/compromised-endpoints/13/overview"

