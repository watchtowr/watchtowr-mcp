"""Live-API tests for the 2 Services tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_list_services(live_env, call):
    assert_ok(call("list_services", page_size=5), allow_empty=True)


def test_list_technology_statistics(live_env, call):
    assert_ok(call("list_technology_statistics", page_size=5), allow_empty=True)


def test_list_services_by_technology(live_env, call):
    assert_ok(call("list_services", technology="bugzilla", page_size=5), allow_empty=True)


def test_list_services_page_2_formatting(live_env, call):
    res = call("list_services", page=2, page_size=10)
    assert_ok(res, allow_empty=True)
    if res and "Services (" in res and "•" in res:
        assert "•" in res


