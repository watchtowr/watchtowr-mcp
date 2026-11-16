from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace as NS
from urllib.parse import parse_qs, urlsplit

import pytest

from test.unit.conftest import JsonReply, finding_json, page_of, port_json
from watchtowr_mcp_server.client import LIST_BANNER_CHARS, MAX_ASSET_PAGE_SIZE, THIS_TOOLS_FILTERS, paging_lines

FILTERS_AND_EXPORT = {"narrow_with": THIS_TOOLS_FILTERS, "exportable": True}


def _page(total: int | None, per_page: int | None = None, rows: int = 1) -> NS:
    pagination = NS(total=total, per_page=per_page)
    return NS(meta=NS(pagination=pagination), data=[object()] * rows)


def test_a_list_that_fits_on_one_page_has_no_paging_line():
    assert paging_lines(_page(30, 30), 1, 30, **FILTERS_AND_EXPORT) == []
    assert paging_lines(_page(None, 30), 1, 30, **FILTERS_AND_EXPORT) == []
    assert paging_lines(NS(meta=None, data=[]), 1, 30, **FILTERS_AND_EXPORT) == []


def test_an_earlier_page_says_where_it_sits_and_how_to_get_the_next():
    assert paging_lines(_page(45, 30), 1, 30, **FILTERS_AND_EXPORT) == [
        "Page 1 of 2 (30 per page). More: call again with page=2."
    ]


def test_the_last_page_says_it_is_the_last():
    assert paging_lines(_page(45, 30), 2, 30, **FILTERS_AND_EXPORT) == ["Page 2 of 2: the last page."]


def test_the_page_count_uses_the_platforms_per_page_over_the_requested_size():
    assert paging_lines(_page(250, 100), 1, 30, **FILTERS_AND_EXPORT)[0] == (
        "Page 1 of 3 (100 per page). More: call again with page=2."
    )
    assert paging_lines(_page(250, None), None, 100, **FILTERS_AND_EXPORT)[0] == (
        "Page 1 of 3 (100 per page). More: call again with page=2."
    )
    assert paging_lines({"meta": None}, 1, 30, **FILTERS_AND_EXPORT) == []


def test_up_to_five_pages_only_says_where_the_page_sits():
    assert len(paging_lines(_page(150, 30), 1, 30, **FILTERS_AND_EXPORT)) == 1


@pytest.mark.parametrize(("narrow_with", "exportable", "advice"), [
    (THIS_TOOLS_FILTERS, True,
     "Tell the user they can narrow it with this tool's filters, "
     "or export the whole list from the watchTowr portal (Reporting → Generate reports)."),
    (THIS_TOOLS_FILTERS, False, "Tell the user they can narrow it with this tool's filters."),
    ("the filters on search_findings", True,
     "Tell the user they can narrow it with the filters on search_findings, "
     "or export the whole list from the watchTowr portal (Reporting → Generate reports)."),
    (None, True, "Tell the user they can export the whole list from the watchTowr portal (Reporting → Generate reports)."),
    (None, False, "Ask the user before paging through all of it."),
])
def test_a_long_list_says_only_the_ways_this_list_has_to_get_it_whole(narrow_with, exportable, advice):
    for page in (1, 51):
        lines = paging_lines(_page(1504, 30), page, 30, narrow_with=narrow_with, exportable=exportable)

        assert lines[1] == f"The full list of 1,504 takes 51 calls. {advice}"


def _sent_page_size(fake_platform, path: str) -> float:
    """The SDK sends pageSize as a float, such as 100.0."""
    url = next(u for u in fake_platform.requested_urls if urlsplit(u).path.endswith(path))
    return float(parse_qs(urlsplit(url).query)["pageSize"][0])


def _page_json(items: list, total: int, per_page: int) -> dict:
    reply = page_of(items)
    reply["meta"]["pagination"].update(total=total, per_page=per_page, total_pages=-(-total // per_page))
    return reply


RECORDED_SUBDOMAIN = json.loads(
    (Path(__file__).parent / "client_api_responses" / "get_list_asset_subdomains.json").read_text()
)["response"]["data"][0]


def _subdomain_json(n: int) -> dict:
    return {**RECORDED_SUBDOMAIN, "id": str(n), "name": f"host-{n}.example.com"}


def test_asset_lists_ask_for_100_rows_by_default_and_end_with_the_paging_lines(tools, fake_platform):
    fake_platform.route(r"/assets/subdomain/list$", JsonReply(_page_json([_subdomain_json(n) for n in range(100)], 1504, 100)))

    lines = tools["list_asset_subdomains"]().splitlines()

    assert _sent_page_size(fake_platform, "/assets/subdomain/list") == MAX_ASSET_PAGE_SIZE
    assert lines[0] == "Subdomains (100 of 1504):"
    assert lines[-2] == "Page 1 of 16 (100 per page). More: call again with page=2."
    assert lines[-1] == (
        "The full list of 1,504 takes 16 calls. Tell the user they can narrow it with this tool's filters, "
        "or export the whole list from the watchTowr portal (Reporting → Generate reports)."
    )


def test_asset_lists_cap_a_larger_page_size_at_100(tools, fake_platform):
    fake_platform.route(r"/assets/subdomain/list$", JsonReply(_page_json([_subdomain_json(1)], 1, 100)))

    tools["list_asset_subdomains"](page_size=500)

    assert _sent_page_size(fake_platform, "/assets/subdomain/list") == 100


def test_finding_lists_stay_at_30_rows_and_point_to_search_findings(tools, fake_platform):
    findings = [finding_json(n) for n in range(1, 31)]
    fake_platform.route(r"/findings/list$", JsonReply(_page_json(findings, 200, 30)))

    lines = tools["list_findings_by_severity"](severity="High", page_size=100).splitlines()

    assert _sent_page_size(fake_platform, "/findings/list") == 30
    assert lines[-2] == "Page 1 of 7 (30 per page). More: call again with page=2."
    assert "narrow it with the filters on search_findings" in lines[-1]


def test_a_list_with_no_filters_or_export_asks_before_paging_through_it(tools, fake_platform):
    hunt_finding = {**finding_json(1), "hunt_resource": None}
    fake_platform.route(r"/hunts/show/[\d.]+/findings$", JsonReply(_page_json([hunt_finding] * 30, 200, 30)))

    out = tools["list_findings_by_hunt"](hunt_id=1)

    assert out.splitlines()[-1] == "The full list of 200 takes 7 calls. Ask the user before paging through all of it."


@pytest.mark.parametrize(("tool", "args", "path"), [
    ("list_asset_ports", {}, "/assets/ip/port/list"),
    ("list_ports_for_ip", {"ip_id": 4}, "/assets/ip/show/4/port/list"),
])
def test_port_lists_take_100_rows_and_cut_long_banners(tools, fake_platform, tool, args, path):
    ports = [{**port_json(), "id": "1", "banner": "short"}, {**port_json(), "id": "2", "banner": "x" * 5000}]
    fake_platform.route(path.replace("4", r"[\d.]+") + "$", JsonReply(_page_json(ports, 2, 100)))

    out = tools[tool](**args)

    assert _sent_page_size(fake_platform, "/port/list") == 100
    assert "short</untrusted-data-" in out
    assert "x" * LIST_BANNER_CHARS + "…</untrusted-data-" in out
    assert "x" * (LIST_BANNER_CHARS + 1) not in out
    assert "Banners are cut to 200 characters in this list; get_asset_port_details shows a port's whole banner." in out


def test_port_lists_without_long_banners_add_no_note(tools, fake_platform):
    fake_platform.route(r"/assets/ip/port/list$", JsonReply(_page_json([{**port_json(), "banner": "nginx"}], 1, 100)))

    assert "Banners are cut" not in tools["list_asset_ports"]()
