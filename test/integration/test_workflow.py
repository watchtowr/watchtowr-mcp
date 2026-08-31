"""Live-API tests for the 6 Workflow & Automation tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_get_recent_remediations(live_env, call):
    assert_ok(call("get_recent_remediations", days=7, page_size=5), allow_empty=True)


def test_get_daily_digest(live_env, call):
    assert_ok(call("get_daily_digest"))


def test_get_actionable_findings_queue(live_env, call):
    assert_ok(call("get_actionable_findings_queue", page_size=5), allow_empty=True)


def test_get_findings_needing_assignment(live_env, call):
    assert_ok(call("get_findings_needing_assignment", page_size=5), allow_empty=True)


@pytest.mark.write
def test_bulk_retest_findings(live_env, call, sample_finding_id):
    assert_ok(call("bulk_retest_findings", finding_ids=str(sample_finding_id)))


@pytest.mark.write
def test_bulk_update_finding_status_roundtrip(live_env, call, sample_finding_id):
    """Read current status from get_finding_details, then bulk-update to the
    same value to exercise the write path without mutating state."""
    details = call("get_finding_details", finding_id=sample_finding_id)
    if details.startswith("Error"):
        pytest.skip(f"could not read finding to learn current status: {details}")
    status = None
    for line in details.splitlines():
        if line.lower().startswith("status:"):
            status = line.split(":", 1)[1].strip()
            break
    if not status:
        pytest.skip("could not parse status from finding details")
    assert_ok(call("bulk_update_finding_status", finding_ids=str(sample_finding_id), status=status))
