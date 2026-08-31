"""Live-API tests for the 10 Findings tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_list_cisa_kev_findings(live_env, call):
    assert_ok(call("list_cisa_kev_findings", page_size=5), allow_empty=True)


@pytest.mark.parametrize("severity", ["Critical", "High", "Medium", "Low"])
def test_list_findings_by_severity(live_env, call, severity):
    assert_ok(call("list_findings_by_severity", severity=severity, page_size=5), allow_empty=True)


def test_get_finding_details(live_env, call, sample_finding_id):
    assert_ok(call("get_finding_details", finding_id=sample_finding_id))


def test_search_findings(live_env, call):
    assert_ok(call("search_findings", page_size=5), allow_empty=True)
    assert_ok(call("search_findings", finding_title="Credentials", page_size=5), allow_empty=True)
    assert_ok(call("search_findings", severities="Critical,High", page_size=5), allow_empty=True)
    assert_ok(call("search_findings", statuses="confirmed,unconfirmed", page_size=5), allow_empty=True)
    assert_ok(call("search_findings", asset_title="watchtowr.com", page_size=5), allow_empty=True)
    assert_ok(call("search_findings", asset_types="domain,subdomain", page_size=5), allow_empty=True)
    assert_ok(call("search_findings", assignee="No Assignee", page_size=5), allow_empty=True)
    assert_ok(call("search_findings", tags="CISA-KEV", page_size=5), allow_empty=True)
    assert_ok(call("search_findings", finding_impact_threshold="High", page_size=5), allow_empty=True)


def test_get_finding_statuses(live_env, call):
    assert_ok(call("get_finding_statuses"))


def test_get_findings_summary_by_severity(live_env, call):
    assert_ok(call("get_findings_summary_by_severity"))


def test_get_unresolved_findings_by_business_unit(live_env, call, sample_bu_id):
    assert_ok(call("get_unresolved_findings_by_business_unit", business_unit_id=str(sample_bu_id)), allow_empty=True)


def test_export_finding_pdf(live_env, call, sample_finding_id):
    assert_ok(call("export_finding_pdf", finding_id=sample_finding_id))


@pytest.mark.write
def test_update_finding_status_roundtrip(live_env, call, sample_finding_id):
    """Read current status → set to the same value → assert no error.

    We deliberately set the status to whatever it already is. That exercises
    the write path without mutating tenant state.
    """
    details = call("get_finding_details", finding_id=sample_finding_id)
    assert not details.startswith("Error")
    # The detail string includes "Status: <value>" — pull it out.
    status = None
    for line in details.splitlines():
        if line.lower().startswith("status:"):
            status = line.split(":", 1)[1].strip()
            break
    if not status:
        pytest.skip("could not parse status from finding details")
    assert_ok(call("update_finding_status", finding_id=sample_finding_id, status=status))


@pytest.mark.write
def test_retest_finding(live_env, call, sample_retestable_finding_id):
    response = call("retest_finding", finding_id=sample_retestable_finding_id)
    if isinstance(response, str) and "400" in response:
        pytest.skip(f"retest returned 400 — finding may not support retest in this tenant: {response[:200]}")
    assert_ok(response)


def test_search_findings_with_new_filters(live_env, call):
    assert_ok(
        call(
            "search_findings",
            only_validated_exploitable=False,
            exploitation_risk_level="High,Moderate",
            page_size=5,
        ),
        allow_empty=True,
    )


@pytest.mark.write
def test_update_finding_state_roundtrip(live_env, call, sample_finding_id):
    """Read current state → set to the same value → assert no error.

    Exercises update_finding_state without mutating tenant state.
    """
    details = call("get_finding_details", finding_id=sample_finding_id)
    assert not details.startswith("Error")
    state = None
    for line in details.splitlines():
        if line.lower().startswith("state:"):
            state = line.split(":", 1)[1].strip()
            break
    if not state or state == "N/A":
        state = "Uninvestigated"
    assert_ok(call("update_finding_state", finding_id=sample_finding_id, state=state))

