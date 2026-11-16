from __future__ import annotations

import inspect
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastmcp.exceptions import ToolError

from test.unit.conftest import JsonReply, page_of
from test.unit.test_tool_error_path import OfflineTransport, transport_calls  # noqa: F401
from watchtowr_mcp_server.client import get_total, no_results, supported_kwargs


SUMMARY_TOOLS = {"get_open_ports_summary", "get_top_findings_by_occurrence"}

PAGED_TOOLS = {
    "get_hunt_remediation_list": {"hunt_id": 1},
    "get_stale_findings": {},
    "get_unassigned_critical_findings": {},
    "list_cisa_kev_findings": {},
    "list_findings_by_severity": {},
    "get_unresolved_findings_by_business_unit": {"business_unit_id": "1"},
    "list_recent_hunts": {},
    "search_assets_by_country": {"country_code": "us"},
    "get_assets_by_technology": {"technology_search": "nginx"},
    "get_expiring_certificates": {},
    "get_recent_remediations": {},
    "get_actionable_findings_queue": {},
    "get_findings_needing_assignment": {},
}

NEW_FILTERS = {
    "get_assets_by_technology": (
        {"technology_search": "nginx", "countries": "us, de", "business_unit_ids": "3,4"},
        {"countries": ["US,DE"], "businessUnitIds": ["3.0", "4.0"]},
    ),
    "search_findings": (
        {"updated_from": "2026-01-01", "updated_to": "2026-01-31", "only_ai_discovered": True},
        {"updated_from": ["2026-01-01T00:00:00"], "updated_to": ["2026-01-31T00:00:00"], "onlyAiDiscovered": ["true"]},
    ),
    "list_points_of_interest": (
        {"start_date": "2026-01-01", "end_date": "2026-01-31", "asset_statuses": "verified"},
        {"startDate": ["2026-01-01T00:00:00"], "endDate": ["2026-01-31T00:00:00"], "assetStatuses": ["verified"]},
    ),
    "list_suspicious_domains": (
        {"updated_from": "2026-01-01", "updated_to": "2026-01-31"},
        {"updated_from": ["2026-01-01T00:00:00"], "updated_to": ["2026-01-31T00:00:00"]},
    ),
    "list_certificates": (
        {"subject_countries": "us,de"},
        {"subjectCountries": ["US", "DE"]},
    ),
}


def _page_with_total(items: list, total: int) -> dict:
    reply = page_of(items)
    reply["meta"]["pagination"]["total"] = total
    return reply


def _route_hunt(fake_platform) -> None:
    fake_platform.route(r"/hunts/show/[\d.]+$", JsonReply({"data": {
        "id": 1, "title": "Hunt", "type": "proactive", "status": "completed", "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z", "total_findings": 42, "total_assets": 1, "cves": [],
    }}))
    fake_platform.route(r"/hunts/show/[\d.]+/findings$", JsonReply(_page_with_total([], 42)))


def _sent_query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query)


def test_every_page_size_tool_takes_page_or_is_a_summary(tools):
    missing = sorted(
        name for name, fn in tools.items()
        if "page_size" in inspect.signature(fn).parameters
        and "page" not in inspect.signature(fn).parameters
        and name not in SUMMARY_TOOLS
    )
    assert not missing, f"take page_size but no page: {missing}"


@pytest.mark.parametrize(
    ("tool_name", "path", "item"),
    [
        ("get_open_ports_summary", r"/service-listing/list$", {
            "id": 1, "portId": 1, "port": 443, "service": "https", "technologies": [], "serviceTypes": [],
            "businessUnits": [], "isConcerning": False, "suppressed": False,
        }),
        ("get_top_findings_by_occurrence", r"/findings/list$", {"id": 1, "title": "TLS", "severity": "low"}),
    ],
)
def test_summary_tool_says_it_counted_only_the_first_rows(tool_name, path, item, tools, fake_platform):
    fake_platform.route(path, JsonReply(_page_with_total([item], 500)))

    assert "from the first 1 of 500" in tools[tool_name]()


@pytest.mark.parametrize("tool_name", sorted(PAGED_TOOLS))
def test_paged_tool_sends_the_page_to_every_list_call(tool_name, tools, fake_platform):
    fake_platform.route(r"/list$", JsonReply(_page_with_total([], 42)))
    _route_hunt(fake_platform)

    tools[tool_name](**PAGED_TOOLS[tool_name], page=2)

    list_calls = [url for url in fake_platform.requested_urls if urlsplit(url).path.endswith(("/list", "/findings"))]
    assert list_calls, "no list call was sent"
    for url in list_calls:
        assert _sent_query(url).get("page") == ["2.0"], url


@pytest.mark.parametrize("tool_name", sorted(PAGED_TOOLS))
def test_a_page_past_the_end_says_so(tool_name, tools, fake_platform):
    fake_platform.route(r"/list$", JsonReply(_page_with_total([], 42)))
    _route_hunt(fake_platform)

    answer = tools[tool_name](**PAGED_TOOLS[tool_name], page=3)

    assert "Page 3 is past the end (total " in answer


def test_a_severity_with_no_rows_left_is_still_named_on_a_later_page(tools, fake_platform):
    finding = {"id": 1, "title": "TLS", "severity": "high", "status": "confirmed"}
    fake_platform.route(r"/findings/list$", JsonReply(_page_with_total([finding], 45)), query_contains="severities=high")
    fake_platform.route(r"/findings/list$", JsonReply(_page_with_total([], 20)), query_contains="severities=critical")

    answer = tools["get_unassigned_critical_findings"](page=2)

    assert "Critical (20): none left on this page" in answer


def test_no_results_names_the_page_and_total_past_the_end():
    response = SimpleNamespace(meta=SimpleNamespace(pagination=SimpleNamespace(total=42)))

    assert no_results(response, 3, "No findings found.") == "Page 3 is past the end (total 42)."
    assert no_results(response, 1, "No findings found.") == "No findings found."
    assert no_results(SimpleNamespace(meta=None), 2, "No findings found.") == "No findings found."


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("search_assets_by_country", {"country_code": "SG"}),
        ("get_hunt_remediation_list", {"hunt_id": 1}),
        ("get_unassigned_critical_findings", {}),
        ("get_findings_needing_assignment", {}),
        ("get_actionable_findings_queue", {}),
    ],
)
def test_a_page_below_one_is_refused(tool_name, arguments, tools, fake_platform):
    with pytest.raises(ToolError, match="page must be 1 or more, got 0"):
        tools[tool_name](**arguments, page=0)

    assert not fake_platform.requested_urls


def test_no_results_says_none_found_when_nothing_matched_or_no_page_was_given():
    empty = SimpleNamespace(meta=SimpleNamespace(pagination=SimpleNamespace(total=0)))

    assert no_results(empty, 2, "No findings found.") == "No findings found."
    assert no_results(empty, None, "No notes found.") == "No notes found."


def test_a_failed_severity_is_not_hidden_behind_past_the_end(tools, fake_platform):
    fake_platform.route(r"/findings/list$", JsonReply(_page_with_total([], 42)))
    fake_platform.route(r"/findings/list$", JsonReply({"message": "boom"}, status=500), query_contains="severities=critical")

    answer = tools["get_findings_needing_assignment"](page=2)

    assert "Incomplete: Critical findings failed" in answer
    assert "past the end" not in answer


def test_list_asset_ports_offers_no_filter_the_ports_api_lacks(tools):
    params = inspect.signature(tools["list_asset_ports"]).parameters

    assert "statuses" not in params
    assert "source" not in params


def test_supported_kwargs_refuses_a_filter_the_endpoint_lacks():
    def get_list(page=None, page_size=None):
        pass

    with pytest.raises(ToolError, match="does not support the filter\\(s\\) statuses"):
        supported_kwargs(get_list, {"page": 1, "statuses": "pending"})


def test_supported_kwargs_ignores_an_unset_filter():
    def get_list(page=None, page_size=None):
        pass

    assert supported_kwargs(get_list, {"page": 1, "statuses": None}) == {"page": 1}


def test_verified_overall_says_it_excludes_ports(tools, fake_platform):
    fake_platform.route(r"/list$", JsonReply(page_of([])))

    assert "Not included, because their API cannot filter by status: Ports." in tools["get_verified_vs_unverified_assets"]()


def test_get_total_reads_a_dict_meta():
    assert get_total(SimpleNamespace(meta={"pagination": {"total": 7}})) == 7


@pytest.mark.parametrize("tool_name", ["get_out_of_scope_assets", "get_verified_vs_unverified_assets"])
def test_status_count_says_ports_were_not_checked(tool_name, tools, fake_platform):
    fake_platform.route(r"/list$", JsonReply(page_of([])))

    answer = tools[tool_name]()

    assert "Not included, because their API cannot filter by status: Ports." in answer
    assert not [url for url in fake_platform.requested_urls if "/ip/port/list" in url]


@pytest.mark.parametrize("tool_name", sorted(NEW_FILTERS))
def test_new_filter_reaches_the_api(tool_name, tools, transport_calls):  # noqa: F811
    arguments, expected_query = NEW_FILTERS[tool_name]

    with pytest.raises((OfflineTransport, ToolError)):
        tools[tool_name](**arguments)

    query = _sent_query(transport_calls[0][1])
    for key, values in expected_query.items():
        assert query.get(key) == values, key
