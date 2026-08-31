"""Live-API tests for the 5 Organisation tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_get_watchtowr_source_ips(live_env, call):
    assert_ok(call("get_watchtowr_source_ips"))


def test_get_activity_logs(live_env, call):
    assert_ok(call("get_activity_logs", page_size=5), allow_empty=True)


def test_search_activity_logs(live_env, call):
    assert_ok(call("search_activity_logs", page_size=5), allow_empty=True)


def test_search_activity_logs_with_type_filter(live_env, call):
    resp = call("search_activity_logs", types="Successful Login", page_size=5)
    assert_ok(resp, allow_empty=True)


def test_list_business_units(live_env, call):
    assert_ok(call("list_business_units"), allow_empty=True)


def test_get_business_unit_details(live_env, call, sample_bu_id):
    assert_ok(call("get_business_unit_details", business_unit_id=sample_bu_id))
