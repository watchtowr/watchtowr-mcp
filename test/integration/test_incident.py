"""Live-API tests for the 5 Incident Response tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_search_assets_by_country(live_env, call):
    assert_ok(call("search_assets_by_country", country_code="US", page_size=5), allow_empty=True)


def test_get_internet_facing_services_summary(live_env, call):
    assert_ok(call("get_internet_facing_services_summary"))


def test_get_assets_by_technology(live_env, call):
    assert_ok(call("get_assets_by_technology", technology_search="http", page_size=5), allow_empty=True)


def test_get_cisa_kev_remediation_status(live_env, call):
    assert_ok(call("get_cisa_kev_remediation_status"))


def test_find_related_assets(live_env, call, sample_domain_id):
    assert_ok(call("find_related_assets", asset_id=sample_domain_id, asset_type="domain"))
