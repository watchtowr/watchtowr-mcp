from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

import pytest

from test.unit.conftest import JsonReply, page_of
from watchtowr_mcp_server.constants import SUMMARY_SEVERITIES


FINDINGS_LIST_URL = "/api/client/findings/list"
OPEN_SEVERITIES = ",".join(SUMMARY_SEVERITIES)
SEVERITY_TOTALS = {"critical": 1, "high": 2, "medium": 3, "low": 4}

TOOLS_THAT_COUNT_OPEN_FINDINGS = {
    "get_finding_age_distribution": {},
    "get_top_findings_by_occurrence": {},
    "get_finding_status_timeline": {"days": 14},
    "get_week_over_week_delta": {"weeks": 2},
    "get_executive_risk_scorecard": {},
}


def _page_with_total(total: int) -> JsonReply:
    page = page_of([])
    page["meta"]["pagination"]["total"] = total
    return JsonReply(page)


def _findings_queries(fake_platform) -> list[dict[str, list[str]]]:
    return [
        parse_qs(url.query)
        for url in map(urlsplit, fake_platform.requested_urls)
        if url.path == FINDINGS_LIST_URL
    ]


@pytest.mark.parametrize("tool_name", sorted(TOOLS_THAT_COUNT_OPEN_FINDINGS))
def test_open_counts_send_the_shared_open_findings_filter(tool_name, tools, fake_platform):
    fake_platform.route(r".", JsonReply(page_of([])))

    tools[tool_name](**TOOLS_THAT_COUNT_OPEN_FINDINGS[tool_name])

    queries = _findings_queries(fake_platform)
    assert queries
    for query in queries:
        assert query["statuses"] in (["confirmed"], ["remediated"]), query
        assert query["severities"] == [OPEN_SEVERITIES] or query["severities"][0] in SUMMARY_SEVERITIES, query


@pytest.mark.parametrize("tool_name", sorted(TOOLS_THAT_COUNT_OPEN_FINDINGS))
def test_open_counts_name_their_definition(tool_name, tools, fake_platform):
    fake_platform.route(r".", JsonReply(page_of([{"id": 1, "title": "Example", "severity": "high"}])))

    answer = tools[tool_name](**TOOLS_THAT_COUNT_OPEN_FINDINGS[tool_name])

    assert "critical to low" in answer, answer


def test_each_age_bucket_equals_its_severity_breakdown(tools, fake_platform):
    for severity, total in SEVERITY_TOTALS.items():
        fake_platform.route(FINDINGS_LIST_URL, _page_with_total(total), query_contains=f"severities={severity}")
    fake_platform.route(
        FINDINGS_LIST_URL, _page_with_total(sum(SEVERITY_TOTALS.values())),
        query_contains="severities=critical%2Chigh%2Cmedium%2Clow",
    )

    answer = tools["get_finding_age_distribution"]()

    buckets = re.findall(r"• [^:]+: (\d+) \(C:(\d+), H:(\d+), M:(\d+), L:(\d+)\)", answer)
    assert len(buckets) == 4, answer
    for total, *breakdown in buckets:
        assert int(total) == sum(map(int, breakdown))


def test_top_findings_without_open_findings_names_the_definition(tools, fake_platform):
    fake_platform.route(r".", JsonReply(page_of([])))

    assert tools["get_top_findings_by_occurrence"]() == "No open critical-to-low findings found."


def test_scorecard_mean_age_names_its_sample_when_more_findings_are_open(tools, fake_platform):
    page = page_of([{"id": 1, "title": "Example", "severity": "high", "created_at": "2026-01-01T00:00:00Z"}])
    page["meta"]["pagination"]["total"] = 200
    fake_platform.route(r".", JsonReply(page_of([])))
    fake_platform.route(FINDINGS_LIST_URL, JsonReply(page))

    answer = tools["get_executive_risk_scorecard"]()

    assert "Incomplete" not in answer, answer
    assert "Mean Finding Age (1 newest open findings): " in answer, answer
