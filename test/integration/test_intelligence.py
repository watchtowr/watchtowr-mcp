"""Integration tests for intelligence tools."""
import pytest
from ._helpers import assert_ok

pytestmark = pytest.mark.live


def test_list_vulnerability_intelligence(live_env, call):
    assert_ok(call("list_vulnerability_intelligence", page_size=5), allow_empty=True)


def test_get_vulnerability_intelligence_details(live_env, call):
    response = call("get_vulnerability_intelligence_details", identifier="CVE-2024-3400")
    assert isinstance(response, str) and response, "tool returned no usable response"
    if response.startswith("Error"):
        assert "(404)" in response, f"unexpected error (not a 404 not-found): {response[:200]}"


def test_list_adversary_intelligence(live_env, call):
    assert_ok(call("list_adversary_intelligence", page_size=5), allow_empty=True)


# def test_list_compromised_endpoints(live_env, call):
#     assert_ok(call("list_compromised_endpoints", page_size=5), allow_empty=True)


# def test_list_credential_attempt_logs(live_env, call):
#     assert_ok(call("list_credential_attempt_logs", page_size=5), allow_empty=True)


def test_list_finding_retest_history(live_env, call):
    assert_ok(call("list_finding_retest_history", page_size=5), allow_empty=True)


@pytest.mark.parametrize("result", ["resolved", "unresolved"])
def test_list_finding_retest_history_by_result(live_env, call, result):
    assert_ok(
        call("list_finding_retest_history", retest_result_statuses=result, page_size=5),
        allow_empty=True,
    )


@pytest.mark.live
def test_search_active_defense_library(live_env, call):
    response = call("search_active_defense_library", page_size=5)
    assert_ok(response)


@pytest.mark.live
def test_search_active_defense_library_with_query(live_env, call):
    response = call("search_active_defense_library", search="sql", page_size=5)
    assert_ok(response)


@pytest.mark.live
def test_search_capabilities(live_env, call, sample_hunt_title):
    response = call("search_capabilities", query=sample_hunt_title)
    assert_ok(response)


@pytest.mark.live
def test_search_capabilities_cve(live_env, call):
    response = call("search_capabilities", query="CVE-2021")
    assert_ok(response)


def test_get_adversary_intelligence_details(live_env, call, sample_adversary_id):
    response = call("get_adversary_intelligence_details", attacker_id=sample_adversary_id)
    assert_ok(response)


# def test_get_compromised_endpoint_credentials(live_env, call, sample_compromised_endpoint_id):
#     assert_ok(
#         call("get_compromised_endpoint_credentials", endpoint_id=sample_compromised_endpoint_id, page_size=5),
#         allow_empty=True,
#     )


def test_get_finding_retest_history_details(live_env, call, sample_finding_id):
    assert_ok(
        call("get_finding_retest_history_details", finding_id=sample_finding_id),
        allow_empty=True,
    )
