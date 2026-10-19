from __future__ import annotations

import pytest

from test.unit.conftest import JsonReply
from test.unit.test_sdk_compat import PAGINATION_META, _hunt_payload


def _capability_search_reply(cve_count: int, status: str = "completed") -> JsonReply:
    cves = [f"CVE-2026-{n:04d}" for n in range(1, cve_count + 1)]
    return JsonReply({
        "data": {
            "hunts": [{**_hunt_payload(None), "status": status, "cve_ids": cves}],
            "ttp_library": [],
        },
        "meta": PAGINATION_META,
    })


@pytest.mark.parametrize(("cve_count", "expected_cve_line"), [
    (7, "Matching CVEs: CVE-2026-0001, CVE-2026-0002, CVE-2026-0003, CVE-2026-0004, CVE-2026-0005, and 2 more CVEs\n"),
    (6, "Matching CVEs: CVE-2026-0001, CVE-2026-0002, CVE-2026-0003, CVE-2026-0004, CVE-2026-0005, and 1 more CVE\n"),
    (5, "Matching CVEs: CVE-2026-0001, CVE-2026-0002, CVE-2026-0003, CVE-2026-0004, CVE-2026-0005\n"),
])
def test_search_capabilities_counts_the_cves_past_the_first_five(tools, fake_platform, cve_count, expected_cve_line):
    fake_platform.route(r"/api/client/capability-search$", _capability_search_reply(cve_count))

    output = tools["search_capabilities"](query="example")

    assert expected_cve_line in output


def test_search_capabilities_prints_a_not_covered_hunt_as_not_covered(tools, fake_platform):
    fake_platform.route(r"/api/client/capability-search$", _capability_search_reply(1, status="not-covered"))

    output = tools["search_capabilities"](query="example")

    assert "Status: not-covered" in output
    assert '"not-covered" means there is no' in tools["search_capabilities"].__doc__
