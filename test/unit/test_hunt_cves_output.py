from __future__ import annotations

import pytest

from test.unit.conftest import JsonReply, page_of
from test.unit.test_sdk_compat import _hunt_detail_payload, _hunt_payload

TWO_CVES = ["CVE-2024-3400", "CVE-2023-4966"]


def _route_hunt_detail(fake_platform, cves: list[str]) -> None:
    fake_platform.route(r"/hunts/show/42$", JsonReply({"data": {**_hunt_detail_payload(None), "cves": cves}}))
    fake_platform.route(r"/hunts/show/42/findings$", JsonReply(page_of([])))
    fake_platform.route(r"/hunts/show/42/assets$", JsonReply(page_of([])))


@pytest.mark.parametrize("tool_name", ["list_recent_hunts", "search_hunts"])
def test_hunt_list_tools_print_each_hunts_cves(tools, fake_platform, tool_name):
    fake_platform.route(r"/hunts/list$", JsonReply(page_of([
        {**_hunt_payload("SoftwareVulnerability"), "id": 43, "cves": TWO_CVES},
        _hunt_payload(None),
    ])))

    lines = tools[tool_name]().splitlines()

    assert "[ID:43] Example hunt - completed" in lines[1]
    assert "CVEs: CVE-2024-3400, CVE-2023-4966" in lines[1]
    assert "CVEs" not in lines[2]


@pytest.mark.parametrize("tool_name", ["get_hunt_details", "get_hunt_impact_summary"])
def test_hunt_detail_tools_print_the_cves_line(tools, fake_platform, tool_name):
    _route_hunt_detail(fake_platform, TWO_CVES)

    output = tools[tool_name](hunt_id=42)

    assert "\nCVEs: CVE-2024-3400, CVE-2023-4966\n" in output


@pytest.mark.parametrize("tool_name", ["get_hunt_details", "get_hunt_impact_summary"])
def test_hunt_detail_tools_omit_the_cves_line_when_none_are_linked(tools, fake_platform, tool_name):
    _route_hunt_detail(fake_platform, [])

    assert "CVEs" not in tools[tool_name](hunt_id=42)
