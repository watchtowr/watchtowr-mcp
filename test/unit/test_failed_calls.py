from __future__ import annotations

import inspect
import re
from types import SimpleNamespace as NS
from typing import NamedTuple
from urllib.parse import parse_qs, urlsplit

import pytest
from fastmcp.exceptions import ToolError
from urllib3.exceptions import ReadTimeoutError
from watchtowr_api_sdk.api.domains_api import DomainsApi
from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.api.hunts_api import HuntsApi
from watchtowr_api_sdk.api.ip_addresses_api import IPAddressesApi
from watchtowr_api_sdk.api.service_discovery_api import ServiceDiscoveryApi
from watchtowr_api_sdk.api.subdomains_api import SubdomainsApi
from watchtowr_api_sdk.exceptions import ApiException

import watchtowr_mcp_server.client as client_module

from test.unit.conftest import JsonReply, page_of
from test.unit.test_tool_error_path import _minimal_args, _tool_names
from test.unit.test_tool_errors import _call_tool_over_mcp
from watchtowr_mcp_server.constants import MAX_TREND_WEEKS
from watchtowr_mcp_server.mcp import create_server


FINDINGS_LIST_URL = "/api/client/findings/list"
EMPTY_PAGE = JsonReply(page_of([]))
BUSINESS_UNIT = JsonReply({"data": {
    "id": 1.0,
    "name": "Example Business Unit",
    "description": None,
    "type": "custom",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "rules": {},
}})
SERVER_ERROR = JsonReply({"message": "Server Error"}, status=500)
NONE_FOUND_LINE = re.compile(r"^No ", re.MULTILINE)
ALL_TYPES_HAVE_FINDINGS = "All asset types with assets also have findings"
ASSET_TYPES_THE_FINDINGS_API_ACCEPTS = {
    "domain", "subdomain", "ip", "port", "ipRange",
    "cloudStorage", "repository", "container", "saasPlatform", "mobileApp",
    "cloudAsset", "apiDocumentation", "packageManager",
}


NO_ANSWER = "no answer from the watchTowr Platform within 30 seconds"


def _read_timeout() -> ReadTimeoutError:
    return ReadTimeoutError(None, FINDINGS_LIST_URL, "Read timed out. (read timeout=30)")


class CompositeTool(NamedTuple):
    arguments: dict
    failing_path: str
    failing_query: str = ""


COMPOSITE_TOOLS = {
    "get_assets_without_findings": CompositeTool({}, r"/assets/domain/list"),
    "get_shadow_it_candidates": CompositeTool({"days": 7}, r"/assets/domain/list"),
    "get_out_of_scope_assets": CompositeTool({}, r"/assets/domain/list"),
    "get_actionable_findings_queue": CompositeTool({}, r"/findings/list", "severities=critical"),
    "get_new_assets_since": CompositeTool({"days": 7}, r"/assets/domain/list"),
    "get_daily_digest": CompositeTool({}, r"/findings/list", "severities=high"),
    "get_executive_risk_scorecard": CompositeTool({}, r"/assets/domain/list"),
    "get_week_over_week_delta": CompositeTool({"weeks": 2}, r"/assets/ip/list"),
    "get_business_unit_posture": CompositeTool({"business_unit_id": 1}, r"/assets/domain/list"),
    "get_attack_surface_summary": CompositeTool({}, r"/assets/domain/list"),
    "get_attack_surface_delta": CompositeTool({}, r"/assets/domain/list"),
    "get_critical_exposure_report": CompositeTool({}, r"/findings/list", "tags=CISA-KEV"),
    "get_asset_findings_count_by_type": CompositeTool({}, r"/findings/list", "assetTypes=domain"),
    "get_asset_inventory_by_business_unit": CompositeTool({"business_unit_id": 1}, r"/assets/domain/list"),
    "get_verified_vs_unverified_assets": CompositeTool({}, r"/assets/domain/list"),
    "get_finding_age_distribution": CompositeTool({}, r"/findings/list", "severities=high"),
    "get_finding_status_timeline": CompositeTool({"days": 14}, r"/findings/list", "statuses=remediated"),
    "get_findings_needing_assignment": CompositeTool({}, r"/findings/list", "severities=high"),
    "get_certificate_health_report": CompositeTool({}, r"/certificates/list", "not_after_from"),
    "get_cisa_kev_remediation_status": CompositeTool({}, r"/findings/list", "statuses=remediated"),
    "get_unassigned_critical_findings": CompositeTool({}, r"/findings/list", "severities=high"),
    "get_findings_summary_by_severity": CompositeTool({}, r"/findings/list", "severities=high"),
}


class ToolAnswer(NamedTuple):
    text: str
    raised_tool_error: bool


def _answer(tools, tool_name: str) -> ToolAnswer:
    try:
        return ToolAnswer(tools[tool_name](**COMPOSITE_TOOLS[tool_name].arguments), False)
    except ToolError as tool_error:
        return ToolAnswer(str(tool_error), True)


def _answer_every_call_with(tools, fake_platform, tool_name: str, outcome) -> ToolAnswer:
    fake_platform.route(r".", outcome)
    if outcome is EMPTY_PAGE:
        fake_platform.route(r"/business-unit/show/", BUSINESS_UNIT)
    return _answer(tools, tool_name)


@pytest.mark.parametrize("tool_name", sorted(COMPOSITE_TOOLS))
def test_one_failed_part_is_reported_as_incomplete_and_no_none_line_is_printed(tool_name, tools, fake_platform):
    tool = COMPOSITE_TOOLS[tool_name]
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/business-unit/show/", BUSINESS_UNIT)
    fake_platform.route(tool.failing_path, SERVER_ERROR, query_contains=tool.failing_query)

    answer = _answer(tools, tool_name)

    assert not answer.raised_tool_error, answer.text
    assert "Incomplete:" in answer.text
    assert "failed: HTTP 500" in answer.text
    assert not NONE_FOUND_LINE.search(answer.text), answer.text
    assert ALL_TYPES_HAVE_FINDINGS not in answer.text


@pytest.mark.parametrize("tool_name", sorted(COMPOSITE_TOOLS))
def test_empty_failed_and_timed_out_answers_are_all_different(tool_name, tools, fake_platform):
    empty = _answer_every_call_with(tools, fake_platform, tool_name, EMPTY_PAGE)
    failed = _answer_every_call_with(tools, fake_platform, tool_name, SERVER_ERROR)
    timed_out = _answer_every_call_with(tools, fake_platform, tool_name, _read_timeout())

    assert not empty.raised_tool_error
    assert "Incomplete:" not in empty.text
    assert "HTTP 500" not in empty.text
    assert NO_ANSWER not in empty.text
    assert failed.raised_tool_error
    assert "failed: HTTP 500" in failed.text
    assert NO_ANSWER not in failed.text
    assert timed_out.raised_tool_error
    assert NO_ANSWER in timed_out.text
    assert "HTTP 500" not in timed_out.text
    assert len({empty.text, failed.text, timed_out.text}) == 3


def test_server_instructions_explain_incomplete_lines_and_at_least_totals():
    instructions = create_server().instructions or ""
    assert 'A line starting "Incomplete:"' in instructions
    assert '"at least N"' in instructions


def test_assets_without_findings_sends_only_asset_types_the_findings_api_accepts(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)

    tools["get_assets_without_findings"]()

    sent_asset_types = {
        asset_type
        for url in map(urlsplit, fake_platform.requested_urls)
        if url.path == FINDINGS_LIST_URL
        for asset_type in parse_qs(url.query).get("assetTypes", [])
    }
    assert sent_asset_types == ASSET_TYPES_THE_FINDINGS_API_ACCEPTS


def test_new_asset_total_comes_after_the_incomplete_lines(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/assets/domain/list", SERVER_ERROR)

    lines = tools["get_new_assets_since"](days=7).splitlines()

    first_incomplete = next(i for i, line in enumerate(lines) if line.startswith("Incomplete:"))
    total = next(i for i, line in enumerate(lines) if line.startswith("Total New Assets:"))
    assert first_incomplete < total


def test_week_line_says_the_findings_count_is_incomplete_when_its_call_failed(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(FINDINGS_LIST_URL, SERVER_ERROR)

    answer = tools["get_week_over_week_delta"](weeks=1)

    assert "+error" not in answer
    assert "findings incomplete" in answer


@pytest.mark.parametrize(
    ("tool_name", "arguments", "failing_path", "failing_query", "total_line"),
    [
        ("get_daily_digest", {}, FINDINGS_LIST_URL, "severities=high", "New Findings: at least 0"),
        ("get_daily_digest", {}, r"/assets/domain/list", "", "New Assets: at least 0"),
        ("get_business_unit_posture", {"business_unit_id": 1}, FINDINGS_LIST_URL, "severities=critical", "  Total: at least 0"),
        ("get_attack_surface_summary", {}, r"/assets/domain/list", "", "Assets (Total: at least 0):"),
        ("get_attack_surface_summary", {}, FINDINGS_LIST_URL, "severities=low", "Findings (Total: at least 0):"),
        ("get_attack_surface_delta", {}, FINDINGS_LIST_URL, "severities=low", "New Findings (at least 0):"),
        ("get_asset_findings_count_by_type", {}, FINDINGS_LIST_URL, "assetTypes=port", "Total: at least 0"),
        ("get_asset_inventory_by_business_unit", {"business_unit_id": 1}, r"/assets/ip/list", "", "Total Assets: at least 0"),
        ("get_findings_needing_assignment", {}, FINDINGS_LIST_URL, "severities=low", "Total Unassigned: at least 0"),
        ("get_executive_risk_scorecard", {}, r"/assets/domain/list", "", "Total Assets: at least 0"),
        ("get_executive_risk_scorecard", {}, FINDINGS_LIST_URL, "severities=high", "  Total Open: at least 0"),
        ("get_out_of_scope_assets", {}, r"/assets/domain/list", "", "Total: at least 0"),
        ("get_shadow_it_candidates", {"days": 7}, r"/assets/domain/list", "", "Total Candidates: at least 0"),
        ("get_new_assets_since", {"days": 7}, r"/assets/domain/list", "", "Total New Assets: at least 0"),
        ("get_actionable_findings_queue", {}, FINDINGS_LIST_URL, "severities=critical", "Total: at least 0"),
        ("get_week_over_week_delta", {"weeks": 1}, r"/assets/ip/list", "", "at least 0 new assets, 0 new findings"),
        (
            "get_cisa_kev_remediation_status", {}, FINDINGS_LIST_URL, "statuses=remediated",
            "CISA-KEV Remediation Status (at least 0 findings):",
        ),
    ],
)
def test_a_total_that_leaves_out_a_failed_part_says_at_least(
    tool_name, arguments, failing_path, failing_query, total_line, tools, fake_platform
):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/business-unit/show/", BUSINESS_UNIT)
    fake_platform.route(failing_path, SERVER_ERROR, query_contains=failing_query)

    answer = tools[tool_name](**arguments)

    assert any(
        line.strip() == total_line.strip() or line.strip().endswith(f": {total_line}") for line in answer.splitlines()
    ), answer


def test_totals_stay_exact_when_their_own_parts_answered(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/assets/domain/list", SERVER_ERROR)

    answer = tools["get_daily_digest"]()

    assert "New Findings: 0" in answer.splitlines()
    assert "New Assets: at least 0" in answer.splitlines()


def test_cisa_kev_total_stays_exact_when_only_the_open_listing_failed(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(FINDINGS_LIST_URL, SERVER_ERROR, query_contains="pageSize=30")

    answer = tools["get_cisa_kev_remediation_status"]()

    assert "CISA-KEV Remediation Status (0 findings):" in answer.splitlines()


def test_every_part_failing_with_an_http_error_says_every_call_failed(tools, fake_platform):
    fake_platform.route(r".", SERVER_ERROR)

    with pytest.raises(ToolError) as raised:
        tools["get_out_of_scope_assets"]()

    message = str(raised.value)
    assert message.startswith("Out-of-scope asset lookup failed: every part of the answer failed.")
    assert "answered" not in message


@pytest.mark.parametrize("tool_name", ["get_business_unit_posture", "get_asset_inventory_by_business_unit"])
def test_business_unit_tools_take_a_json_number(tool_name, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/business-unit/show/", BUSINESS_UNIT)

    result = _call_tool_over_mcp(tool_name, {"business_unit_id": 1})

    assert not result.is_error, result.content[0].text
    assert "Example Business Unit" in result.content[0].text


@pytest.mark.parametrize("tool_name", ["get_business_unit_posture", "get_asset_inventory_by_business_unit"])
def test_business_unit_tools_reject_a_non_numeric_id_before_calling_the_platform(tool_name, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)

    result = _call_tool_over_mcp(tool_name, {"business_unit_id": "sales"})

    assert result.is_error
    assert fake_platform.requested_urls == []


@pytest.mark.parametrize("tool_name", ["get_business_unit_posture", "get_asset_inventory_by_business_unit"])
def test_missing_business_unit_is_an_error_not_zero_totals(tool_name, tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/business-unit/show/", JsonReply({"message": "Not Found"}, status=404))

    with pytest.raises(ToolError, match="HTTP 404"):
        tools[tool_name](business_unit_id=999)


def test_business_unit_posture_puts_incomplete_lines_after_the_description(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/business-unit/show/", JsonReply({"data": {**BUSINESS_UNIT.body["data"], "description": "Example description"}}))
    fake_platform.route(r"/assets/domain/list", SERVER_ERROR)

    lines = tools["get_business_unit_posture"](business_unit_id=1).splitlines()

    assert lines[:3] == [
        "Business Unit: Example Business Unit (ID: 1)",
        "Description: Example description",
        "Incomplete: Domains failed: HTTP 500 - platform error, retry later",
    ]


def test_a_failed_part_is_logged_with_the_answer_it_belongs_to(tools, fake_platform, caplog):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/business-unit/show/", BUSINESS_UNIT)
    fake_platform.route(r"/assets/domain/list", RuntimeError("unexpected"))

    tools["get_business_unit_posture"](business_unit_id=1)

    assert "Domains in Business unit 1 posture" in caplog.text


def test_certificate_health_report_leaves_out_the_valid_count_when_a_bucket_failed(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/certificates/list", SERVER_ERROR, query_contains="not_after_to")

    answer = tools["get_certificate_health_report"]()

    assert "  • Expired: count incomplete" in answer.splitlines()
    assert "  • Valid (30+ days): count incomplete" in answer.splitlines()


def _baseline_requests(fn, args, fake_platform) -> int | None:
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/business-unit/show/", BUSINESS_UNIT)
    try:
        fn(**args)
    except ToolError:
        return None
    return len(fake_platform.requested_urls)


@pytest.mark.parametrize("tool_name", _tool_names())
def test_a_failed_platform_call_is_never_silent(tool_name, tools, fake_platform):
    fn = tools[tool_name]
    args = _minimal_args(fn, tool_name)
    calls = _baseline_requests(fn, args, fake_platform)
    if calls is None:
        return

    for call_number in range(1, calls + 1):
        fake_platform.requested_urls.clear()
        fake_platform.fail_call(call_number, SERVER_ERROR)
        try:
            answer = fn(**args)
        except ToolError as tool_error:
            assert "HTTP 500" in str(tool_error), f"call {call_number}: {tool_error}"
            continue
        assert "Incomplete:" in answer and "failed: HTTP 500" in answer, f"call {call_number} of {calls}:\n{answer}"


@pytest.mark.parametrize("tool_name", _tool_names())
def test_every_platform_call_failing_is_a_tool_error(tool_name, tools, fake_platform):
    fn = tools[tool_name]
    args = _minimal_args(fn, tool_name)
    if _baseline_requests(fn, args, fake_platform) is None:
        return

    for outcome, expected in [(SERVER_ERROR, "HTTP 500"), (_read_timeout(), "no answer from the watchTowr Platform")]:
        fake_platform.route(r".", outcome)
        with pytest.raises(ToolError, match=expected):
            fn(**args)


def test_assets_without_findings_says_the_answered_types_are_covered_when_one_type_failed(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)
    fake_platform.route(r"/assets/domain/list", SERVER_ERROR)

    answer = tools["get_assets_without_findings"]()

    assert "Incomplete: Domains failed" in answer
    assert "Every other asset type with assets also has findings." in answer


def _raise_platform_error(*args, **kwargs):
    raise ApiException(status=500, reason="Server Error")


def test_hunt_remediation_list_says_which_finding_details_failed(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    monkeypatch.setattr(HuntsApi, "show_the_detail_hunt", lambda *a, **k: NS(data=NS(title="Hunt", status="completed")))
    monkeypatch.setattr(HuntsApi, "get_list_finding_by_hunt", lambda *a, **k: NS(data=[NS(id=7, title="Finding", severity="high", status="confirmed")], meta=None))
    monkeypatch.setattr(FindingsApi, "get_finding_details", _raise_platform_error)

    answer = tools["get_hunt_remediation_list"](hunt_id=1)

    assert "Incomplete: Finding 7 remediation failed: HTTP 500" in answer


def test_finding_with_asset_context_says_the_asset_details_failed(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    finding = NS(data=NS(id=1, title="Finding", affected={"data": {"type": "domain", "id": 3, "name": "example.com"}}))
    monkeypatch.setattr(FindingsApi, "get_finding_details", lambda *a, **k: finding)
    monkeypatch.setattr(DomainsApi, "get_asset_domain_details", _raise_platform_error)

    answer = tools["get_finding_with_asset_context"](finding_id=1)

    assert "Asset Name: example.com" in answer
    assert "Incomplete: Asset details failed: HTTP 500" in answer


def test_related_assets_keep_what_was_fetched_when_a_later_call_fails(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    monkeypatch.setattr(IPAddressesApi, "get_asset_ip_details", lambda *a, **k: NS(data=NS(name="192.0.2.1")))
    monkeypatch.setattr(IPAddressesApi, "get_asset_ip_ports", lambda *a, **k: NS(data=[NS(port=443, service="https")], meta=None))
    monkeypatch.setattr(ServiceDiscoveryApi, "get_list_service_listing", lambda *a, **k: NS(data=[], meta=None))
    monkeypatch.setattr(FindingsApi, "get_list_findings", _raise_platform_error)

    answer = tools["find_related_assets"](asset_id=1, asset_type="ip")

    assert "IP Address: 192.0.2.1" in answer
    assert "  • :443 (<untrusted-data-" in answer
    assert "Incomplete: Findings failed: HTTP 500" in answer


def test_related_assets_with_every_part_failing_is_a_tool_error(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    monkeypatch.setattr(DomainsApi, "get_asset_domain_details", lambda *a, **k: NS(data=NS(name="example.com")))
    monkeypatch.setattr(SubdomainsApi, "get_list_asset_subdomains", _raise_platform_error)

    with pytest.raises(ToolError, match="every part of the answer failed"):
        tools["find_related_assets"](asset_id=1, asset_type="domain")


def test_related_assets_for_an_ip_without_a_name_search_nothing(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    monkeypatch.setattr(IPAddressesApi, "get_asset_ip_details", lambda *a, **k: NS(data=NS(name="")))
    monkeypatch.setattr(ServiceDiscoveryApi, "get_list_service_listing", _raise_platform_error)
    monkeypatch.setattr(FindingsApi, "get_list_findings", _raise_platform_error)

    answer = tools["find_related_assets"](asset_id=1, asset_type="ip")

    assert "Incomplete:" not in answer


def _hunt_with_assets_failing(monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    monkeypatch.setattr(HuntsApi, "show_the_detail_hunt", lambda *a, **k: NS(data=NS(id=1, title="Hunt", status="completed")))
    monkeypatch.setattr(HuntsApi, "get_list_asset_by_hunt", _raise_platform_error)


def test_hunt_impact_summary_keeps_the_findings_when_the_asset_list_fails(tools, monkeypatch):
    _hunt_with_assets_failing(monkeypatch)
    monkeypatch.setattr(HuntsApi, "get_list_finding_by_hunt", lambda *a, **k: NS(data=[NS(severity="high")], meta=None))

    lines = tools["get_hunt_impact_summary"](hunt_id=1).splitlines()

    assert lines[1].startswith("Incomplete: Assets failed: HTTP 500")
    assert "  • High: 1" in lines


def test_hunt_impact_summary_with_both_lists_failing_is_a_tool_error(tools, monkeypatch):
    _hunt_with_assets_failing(monkeypatch)
    monkeypatch.setattr(HuntsApi, "get_list_finding_by_hunt", _raise_platform_error)

    with pytest.raises(ToolError, match="every part of the answer failed"):
        tools["get_hunt_impact_summary"](hunt_id=1)


def test_findings_by_asset_rejects_an_unknown_asset_type_before_calling_the_platform(tools, fake_platform):
    with pytest.raises(ToolError, match=r"Invalid asset_type 'bogus'\. Valid types: ip, ip_address, domain, "):
        tools["get_findings_by_asset"](asset_type="bogus", asset_id=1)

    assert fake_platform.requested_urls == []


def test_actionable_queue_total_is_the_platform_total_not_the_rows_fetched(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())

    def one_finding_per_severity(self, severities, **kwargs):
        total = 120 if severities == "critical" else 1
        return NS(data=[NS(id=1, title="Finding", status="confirmed", created_at="2026-01-01")], meta=NS(pagination=NS(total=total)))

    monkeypatch.setattr(FindingsApi, "get_list_findings", one_finding_per_severity)

    lines = tools["get_actionable_findings_queue"](page_size=1).splitlines()

    assert "Total: 123" in lines
    assert "Showing 4: the first 1 of each severity." in lines


@pytest.mark.parametrize(
    ("tool_name", "arguments", "most_calls"),
    [
        ("get_week_over_week_delta", {"weeks": 52}, MAX_TREND_WEEKS * 14),
        ("get_finding_status_timeline", {"days": 365}, MAX_TREND_WEEKS * 2),
    ],
)
def test_trend_tools_cap_how_many_weeks_they_break_down(tool_name, arguments, most_calls, tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)

    tools[tool_name](**arguments)

    assert len(fake_platform.requested_urls) == most_calls


def test_list_asset_ports_offers_only_filters_the_ports_api_has(tools):
    parameters = inspect.signature(tools["list_asset_ports"]).parameters
    assert "statuses" not in parameters
    assert "source" not in parameters


@pytest.mark.parametrize("tool_name", ["get_out_of_scope_assets", "get_verified_vs_unverified_assets"])
def test_status_breakdowns_leave_out_ports_and_say_so(tool_name, tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)

    answer = tools[tool_name]()

    assert "Not included, because their API cannot filter by status: Ports." in answer
    assert not any("/port/list" in url for url in fake_platform.requested_urls)


def test_compromised_endpoint_filters_drop_empty_segments(tools, fake_platform):
    fake_platform.route(r".", EMPTY_PAGE)

    tools["list_compromised_endpoints"](statuses="active,", countries=" SG , ")

    query = parse_qs(urlsplit(fake_platform.requested_urls[0]).query)
    assert query["statuses"] == ["active"]
    assert query["countries"] == ["SG"]
