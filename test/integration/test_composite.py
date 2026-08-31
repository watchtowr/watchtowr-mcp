"""Live-API tests for the 13 Composite & Triage tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_get_attack_surface_summary(live_env, call):
    assert_ok(call("get_attack_surface_summary"))


def test_get_new_assets_since(live_env, call):
    assert_ok(call("get_new_assets_since", days=7), allow_empty=True)


def test_get_attack_surface_delta(live_env, call):
    assert_ok(call("get_attack_surface_delta", days=7), allow_empty=True)


def test_get_business_unit_posture(live_env, call, sample_bu_id):
    assert_ok(call("get_business_unit_posture", business_unit_id=str(sample_bu_id)))


def test_get_finding_with_asset_context(live_env, call, sample_finding_id):
    assert_ok(call("get_finding_with_asset_context", finding_id=sample_finding_id))


def test_get_expiring_certificates_with_services(live_env, call):
    resp = call("get_expiring_certificates_with_services", days=30)
    assert_ok(resp, allow_empty=True)
    # Certificate entries should include visible common-name or asset text,
    # rather than rendering as bare empty bullets.
    for line in resp.splitlines():
        if line.startswith("• "):
            assert line.strip() != "•", "expiring cert rendered with no common-name/asset (field drift)"


def test_get_hunt_remediation_list(live_env, call, sample_hunt_id):
    assert_ok(call("get_hunt_remediation_list", hunt_id=sample_hunt_id, page_size=5), allow_empty=True)


def test_get_critical_exposure_report(live_env, call):
    assert_ok(call("get_critical_exposure_report"))


def test_get_findings_by_asset(live_env, call, sample_domain_id):
    assert_ok(call("get_findings_by_asset", asset_type="domain", asset_id=sample_domain_id), allow_empty=True)


def test_get_stale_findings(live_env, call):
    assert_ok(call("get_stale_findings", days=30, page_size=5), allow_empty=True)


def test_get_unassigned_critical_findings(live_env, call):
    assert_ok(call("get_unassigned_critical_findings", page_size=5), allow_empty=True)


def test_get_asset_findings_count_by_type(live_env, call):
    assert_ok(call("get_asset_findings_count_by_type"))


def test_get_shadow_it_candidates(live_env, call):
    assert_ok(call("get_shadow_it_candidates", days=7), allow_empty=True)
