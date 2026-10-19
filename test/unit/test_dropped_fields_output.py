from __future__ import annotations

import re

from test.unit.conftest import JsonReply, page_of
from test.unit.test_portal_links import _finding_json

FENCE = re.compile(r"<untrusted-data-[0-9a-f]+>(.*?)</untrusted-data-[0-9a-f]+>")
BUSINESS_UNITS = [{"id": 3, "name": "Retail"}, {"id": 4, "name": "Payments"}]


def _service_json(**overrides) -> dict:
    return {
        "id": 1, "portId": 2, "ip": "203.0.113.10", "port": 443, "service": "https",
        "technologies": [{"id": 9, "name": "citrix-adc", "displayName": "Citrix ADC", "version": "13.1-49.13"}],
        "serviceTypes": [], "businessUnits": [], "isConcerning": False, "suppressed": False, "ipId": 7,
        **overrides,
    }


def _vulnerability_json(**overrides) -> dict:
    return {
        "vulnerabilityId": 5, "type": "CVE", "displayName": "CVE-2023-4966 Citrix Bleed", "isAffected": True,
        "kevTypes": {"cisa": True, "vulncheck": False, "watchtowr": False},
        "minKevDateAdded": "2023-10-18T00:00:00Z",
        **overrides,
    }


def _port_json(**overrides) -> dict:
    return {
        "type": "TCP", "status": "open", "created_at": "2024-01-02T03:04:05Z", "last_seen_at": "2024-05-06T07:08:09Z",
        "id": "11", "ip": "203.0.113.10", "ip_id": 7, "port": 443, "service": "https",
        "businessUnits": BUSINESS_UNITS, "metadata": {},
        **overrides,
    }


def test_assets_by_technology_shows_version_and_ip_id(tools, fake_platform):
    fake_platform.route(r"/service-listing/list$", JsonReply(page_of([_service_json()])))

    row = tools["get_assets_by_technology"]("Citrix").splitlines()[2]

    assert "Citrix ADC" in row
    assert FENCE.findall(row) == ["https", "13.1-49.13"]
    assert row.endswith("(IP_ID:7)")


def test_vulnerability_intel_shows_kev_date_added(tools, fake_platform):
    fake_platform.route(r"/vulnerability-intelligence/list$", JsonReply(page_of([_vulnerability_json()])))

    out = tools["list_vulnerability_intelligence"]()

    assert "KEV: cisa | KEV added: 2023-10-18" in out


def test_search_capabilities_shows_hunt_id(tools, fake_platform):
    hunt = {
        "id": 42, "type": "proactive", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-02T00:00:00Z",
        "total_findings": 1, "total_assets": 2, "hunt_request_type": None, "title": "Citrix Bleed",
        "status": "completed", "cve_ids": ["CVE-2023-4966"],
    }
    body = {"data": {"hunts": [hunt], "ttp_library": []}, "meta": page_of([hunt])["meta"]}
    fake_platform.route(r"/capability-search$", JsonReply(body))

    out = tools["search_capabilities"]("Citrix")

    assert "1. [ID:42] Citrix Bleed" in out.splitlines()


def _findings(fake_platform, titles_and_ids: list[tuple[str, int]]):
    findings = [{**_finding_json(fid), "title": title} for title, fid in titles_and_ids]
    fake_platform.route(r"/findings/list$", JsonReply(page_of(findings)))
    fake_platform.route(r"/certificates/list$", JsonReply(page_of([])))


def test_critical_exposure_report_lists_finding_ids(tools, fake_platform):
    _findings(fake_platform, [("Citrix Bleed", 12), ("Open RDP", 30), ("Citrix Bleed", 15)])

    out = tools["get_critical_exposure_report"]()

    assert "  • (2x) Citrix Bleed — IDs: 12, 15" in out.splitlines()
    assert "  • (1x) Open RDP — IDs: 30" in out.splitlines()


def test_top_findings_lists_finding_ids_and_caps_at_five(tools, fake_platform):
    _findings(fake_platform, [("Citrix Bleed", n) for n in range(1, 8)])

    out = tools["get_top_findings_by_occurrence"]()

    assert "  • (7x) [High] Citrix Bleed — IDs: 1, 2, 3, 4, 5, +2 more" in out.splitlines()


def test_list_ports_for_ip_shows_last_seen_and_bus(tools, fake_platform):
    fake_platform.route(r"/assets/ip/show/[^/]+/port/list$", JsonReply(page_of([_port_json()])))

    row = tools["list_ports_for_ip"](7).splitlines()[1]

    assert " Last seen: 2024-05-06 [BU: Retail, Payments]" in row


def test_list_asset_ports_shows_ip_id_last_seen_and_bus(tools, fake_platform):
    fake_platform.route(r"/assets/ip/port/list$", JsonReply(page_of([_port_json()])))

    row = tools["list_asset_ports"]().splitlines()[1]

    assert " (IP_ID:7) Last seen: 2024-05-06 [BU: Retail, Payments]" in row


def test_absent_optional_fields_add_nothing(tools, fake_platform):
    service = _service_json(ipId=None, technologies=[{"id": 9, "name": "nginx", "displayName": "nginx"}])
    fake_platform.route(r"/service-listing/list$", JsonReply(page_of([service])))
    fake_platform.route(r"/vulnerability-intelligence/list$", JsonReply(page_of([_vulnerability_json(minKevDateAdded=None)])))
    fake_platform.route(r"/assets/ip/port/list$", JsonReply(page_of([_port_json(ip_id=None, businessUnits=[])])))

    technology_row = tools["get_assets_by_technology"]("nginx").splitlines()[2]
    intel = tools["list_vulnerability_intelligence"]()
    port_row = tools["list_asset_ports"]().splitlines()[1]

    assert technology_row.endswith("[nginx]")
    assert FENCE.findall(technology_row) == ["https"]
    assert "KEV added" not in intel
    assert "IP_ID" not in port_row and "[BU:" not in port_row


def test_null_ip_and_port_status_print_no_none(tools, fake_platform):
    fake_platform.route(r"/assets/ip/show/[^/]+/port/list$", JsonReply(page_of([_port_json(status=None)])))
    fake_platform.route(r"/assets/ip/port/list$", JsonReply(page_of([_port_json(ip=None)])))
    fake_platform.route(r"/service-listing/list$", JsonReply(page_of([_service_json(ip=None)])))

    rows = [
        tools["list_ports_for_ip"](7).splitlines()[1],
        tools["list_asset_ports"]().splitlines()[1],
        tools["list_services"]().splitlines()[1],
    ]

    assert all("None" not in row for row in rows), rows
    assert " Unknown:443" in rows[1] and " Unknown:443" in rows[2]


def test_port_details_print_na_for_a_null_ip_and_status(tools, fake_platform):
    port = _port_json(ip=None, status=None)
    fake_platform.route(r"/assets/ip/show/[^/]+/port/show/[^/]+$", JsonReply({"data": port}))
    fake_platform.route(r"/assets/ip/port/show/[^/]+$", JsonReply({"data": port}))

    outputs = [tools["get_ip_port_details"](7, 11), tools["get_asset_port_details"](11)]

    for out in outputs:
        assert "None" not in out and "IP: N/A" in out and "Status: N/A" in out, out
