from __future__ import annotations

from test.unit.conftest import JsonReply
from test.unit.test_exposure_verdicts import EXPOSURE_TOOLS

VULNERABILITY_DETAILS = EXPOSURE_TOOLS["get_vulnerability_intelligence_details"]
ADVERSARY_DETAILS = EXPOSURE_TOOLS["get_adversary_intelligence_details"]


def _vulnerability_details(**fields) -> dict:
    return VULNERABILITY_DETAILS.body({"isAffected": False, **fields})


def _adversary_details(**fields) -> dict:
    return ADVERSARY_DETAILS.body({"isAffected": False, **fields})


def test_affected_products_print_as_one_value(tools, fake_platform):
    fake_platform.route(VULNERABILITY_DETAILS.path, JsonReply(_vulnerability_details(affectedProducts="Example Server 1.0")))

    out = tools["get_vulnerability_intelligence_details"](**VULNERABILITY_DETAILS.arguments)

    products = out.split("Affected Products:\n", 1)[1].splitlines()
    assert len(products) == 1
    assert "Example Server 1.0" in products[0]


def test_cvss_v3_metrics_are_printed(tools, fake_platform):
    fake_platform.route(VULNERABILITY_DETAILS.path, JsonReply(_vulnerability_details(
        cvssV3XMetrics={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8, "severity": "critical"},
    )))

    out = tools["get_vulnerability_intelligence_details"](**VULNERABILITY_DETAILS.arguments)

    cvss_lines = [line for line in out.splitlines() if line.startswith("CVSS v3.x:")]
    assert len(cvss_lines) == 1
    assert "9.8" in cvss_lines[0]


def test_target_industries_and_victim_countries_list_their_values(tools, fake_platform):
    fake_platform.route(ADVERSARY_DETAILS.path, JsonReply(_adversary_details(
        targetIndustries={"data": ["Finance", "Energy"], "totalCount": 2},
        victimCountries={"data": ["SG"], "totalCount": 1},
    )))

    out = tools["get_adversary_intelligence_details"](**ADVERSARY_DETAILS.arguments)

    assert "\nTarget Industries:\n• Finance\n• Energy\n" in out
    assert out.rstrip().endswith("Victim Countries:\n• SG")
    assert "total_count" not in out
