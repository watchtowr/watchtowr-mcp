from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from test.unit.conftest import JsonReply, page_of

FINDINGS_LIST = r"/findings/list$"
FINDING = {"id": 7, "title": "MOVEit Transfer SQL injection", "severity": "critical", "status": "confirmed"}


def _sent_query(fake_platform) -> dict[str, list[str]]:
    [url] = fake_platform.requested_urls
    return parse_qs(urlsplit(url).query)


def test_cve_alone_asks_for_confirmed_findings_and_prints_the_verdict_first(tools, fake_platform):
    fake_platform.route(FINDINGS_LIST, JsonReply(page_of([FINDING])))

    answer = tools["search_findings"](cve=" cve-2023-34362 ")

    assert answer == (
        "Exposure: Confirmed affected. The platform has Confirmed findings for CVE-2023-34362 "
        "at the organization's impact threshold, in your business units.\n"
        "Findings (1 of 1):\n"
        "• [ID:7] [Critical] MOVEit Transfer SQL injection (confirmed)"
    )
    sent = _sent_query(fake_platform)
    assert sent["cve"] == ["CVE-2023-34362"]
    assert sent["statuses"] == ["confirmed"]


def test_cve_with_no_confirmed_findings_is_no_evidence_found(tools, fake_platform):
    fake_platform.route(FINDINGS_LIST, JsonReply(page_of([])))

    answer = tools["search_findings"](cve="CVE-2023-34362")

    assert answer == (
        "Exposure: No evidence found. The platform reports no Confirmed findings for CVE-2023-34362 "
        "at the organization's impact threshold, in your business units. It does not count "
        "unconfirmed findings, remediated or closed findings, findings below the threshold, "
        "findings in other business units, or vulnerabilities no hunt has tested.\n"
        "No findings match the search criteria."
    )


def test_cve_on_a_page_past_the_end_keeps_the_verdict_ahead_of_the_past_the_end_message(tools, fake_platform):
    reply = page_of([])
    reply["meta"]["pagination"]["total"] = 3
    fake_platform.route(FINDINGS_LIST, JsonReply(reply))

    answer = tools["search_findings"](cve="CVE-2023-34362", page=5)

    assert answer == (
        "Exposure: Confirmed affected. The platform has Confirmed findings for CVE-2023-34362 "
        "at the organization's impact threshold, in your business units.\n"
        "Page 5 is past the end (total 3)."
    )
    sent = _sent_query(fake_platform)
    assert sent["cve"] == ["CVE-2023-34362"]
    assert sent["page"] == ["5.0"]


@pytest.mark.parametrize(
    ("other_filter", "sent_statuses"),
    [
        ({"statuses": "remediated"}, ["remediated"]),
        ({"severities": "Critical"}, ["confirmed"]),
        ({"business_unit_ids": "3"}, ["confirmed"]),
    ],
)
def test_cve_with_another_filter_lists_findings_without_a_verdict(tools, fake_platform, other_filter, sent_statuses):
    fake_platform.route(FINDINGS_LIST, JsonReply(page_of([FINDING])))

    answer = tools["search_findings"](cve="CVE-2023-34362", **other_filter)

    assert answer == "Findings (1 of 1):\n• [ID:7] [Critical] MOVEit Transfer SQL injection (confirmed)"
    sent = _sent_query(fake_platform)
    assert sent["cve"] == ["CVE-2023-34362"]
    assert sent["statuses"] == sent_statuses
