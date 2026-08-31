"""Live-API tests for the 11 Reporting & Compliance tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_get_asset_inventory_by_business_unit(live_env, call, sample_bu_id):
    assert_ok(call("get_asset_inventory_by_business_unit", business_unit_id=str(sample_bu_id)))


def test_get_out_of_scope_assets(live_env, call):
    assert_ok(call("get_out_of_scope_assets"), allow_empty=True)


def test_get_verified_vs_unverified_assets(live_env, call):
    assert_ok(call("get_verified_vs_unverified_assets"))


def test_get_finding_age_distribution(live_env, call):
    assert_ok(call("get_finding_age_distribution"))


def test_get_finding_status_timeline(live_env, call):
    assert_ok(call("get_finding_status_timeline", days=30), allow_empty=True)


def test_get_open_ports_summary(live_env, call):
    assert_ok(call("get_open_ports_summary", page_size=10), allow_empty=True)


def test_get_assets_without_findings(live_env, call):
    assert_ok(call("get_assets_without_findings"))


def test_get_certificate_health_report(live_env, call):
    assert_ok(call("get_certificate_health_report"), allow_empty=True)


def test_get_executive_risk_scorecard(live_env, call):
    assert_ok(call("get_executive_risk_scorecard"))


def test_get_week_over_week_delta(live_env, call):
    assert_ok(call("get_week_over_week_delta", weeks=2), allow_empty=True)


def test_get_top_findings_by_occurrence(live_env, call):
    assert_ok(call("get_top_findings_by_occurrence", page_size=5), allow_empty=True)


@pytest.mark.live
def test_get_security_posture(live_env, call):
    response = call("get_security_posture")
    assert_ok(response)
