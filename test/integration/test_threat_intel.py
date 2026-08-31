"""Live-API tests for the 6 Threat Intelligence tools."""
from __future__ import annotations

import pytest

from ._helpers import assert_ok


pytestmark = pytest.mark.live


def test_list_suspicious_domains(live_env, call):
    assert_ok(call("list_suspicious_domains", page_size=5), allow_empty=True)


def test_get_suspicious_domain_details(live_env, call, sample_susp_domain_id):
    assert_ok(call("get_suspicious_domain_details", domain_id=sample_susp_domain_id))


def test_list_points_of_interest(live_env, call):
    assert_ok(call("list_points_of_interest", page_size=5), allow_empty=True)


def test_list_points_of_interest_with_type_filter(live_env, call):
    resp = call("list_points_of_interest", types="Leaked Credential", page_size=5)
    assert_ok(resp, allow_empty=True)


def test_list_points_of_interest_with_has_finding_filter(live_env, call):
    resp = call("list_points_of_interest", has_finding=True, page_size=5)
    assert_ok(resp, allow_empty=True)


def test_list_certificates(live_env, call):
    assert_ok(call("list_certificates", page_size=5), allow_empty=True)


def test_get_certificate_details(live_env, call, sample_cert_id):
    assert_ok(call("get_certificate_details", certificate_id=sample_cert_id))


def test_get_expiring_certificates(live_env, call):
    assert_ok(call("get_expiring_certificates", days=30, page_size=5), allow_empty=True)


def test_search_pending_domains(live_env, call):
    assert_ok(call("search_pending_domains", page_size=5), allow_empty=True)


def test_search_pending_domains_with_filter(live_env, call):
    assert_ok(call("search_pending_domains", source="dns", page_size=5), allow_empty=True)
