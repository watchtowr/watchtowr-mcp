"""Live-API tests for the 6 Hunt tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_list_recent_hunts(live_env, call):
    assert_ok(call("list_recent_hunts", page_size=5), allow_empty=True)


def test_get_hunt_details(live_env, call, sample_hunt_id):
    assert_ok(call("get_hunt_details", hunt_id=sample_hunt_id))


def test_list_findings_by_hunt(live_env, call, sample_hunt_id):
    assert_ok(call("list_findings_by_hunt", hunt_id=sample_hunt_id, page_size=5), allow_empty=True)


def test_list_assets_by_hunt(live_env, call, sample_hunt_id):
    result = call("list_assets_by_hunt", hunt_id=sample_hunt_id, page_size=5)
    assert_ok(result, allow_empty=True)


def test_search_hunts(live_env, call):
    assert_ok(call("search_hunts", page_size=5), allow_empty=True)
    assert_ok(call("search_hunts", statuses="received,in-progress", page_size=5), allow_empty=True)
    assert_ok(call("search_hunts", types="bespoke,proactive", page_size=5), allow_empty=True)
    assert_ok(call("search_hunts", only_resolved=False, page_size=5), allow_empty=True)
    assert_ok(call("search_hunts", resource_filter="hasFindings", page_size=5), allow_empty=True)


def test_get_hunt_impact_summary(live_env, call, sample_hunt_id):
    assert_ok(call("get_hunt_impact_summary", hunt_id=sample_hunt_id))

