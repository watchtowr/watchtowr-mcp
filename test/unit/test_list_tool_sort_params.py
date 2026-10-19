from __future__ import annotations

import inspect
from typing import get_args
from urllib.parse import parse_qsl, urlsplit

import pytest
from fastmcp.exceptions import ToolError

from test.unit.test_tool_error_path import OfflineTransport, transport_calls


REQUIRED_ARGS = {
    "list_compromised_endpoints": {},
    "get_compromised_endpoint_credentials": {"endpoint_id": 1},
    "list_credential_attempt_logs": {},
    "list_finding_retest_history": {},
    "get_asset_dns_records": {"asset_name": "example.com"},
    "list_points_of_interest": {},
    "get_assets_by_technology": {"technology_search": "nginx"},
    "search_assets_by_country": {"country_code": "us"},
}

QUERY_WITHOUT_SORT_PARAMS = {
    "list_compromised_endpoints": [("page", "1.0"), ("pageSize", "30.0")],
    "get_compromised_endpoint_credentials": [("page", "1.0"), ("pageSize", "30.0")],
    "list_credential_attempt_logs": [("page", "1.0"), ("pageSize", "30.0")],
    "list_finding_retest_history": [("page", "1.0"), ("pageSize", "30.0")],
    "get_asset_dns_records": [("assetName", "example.com"), ("page", "1.0"), ("pageSize", "20.0")],
    "list_points_of_interest": [("page", "1.0"), ("pageSize", "30.0")],
    "get_assets_by_technology": [("page", "1.0"), ("pageSize", "30.0"), ("technology", "nginx")],
    "search_assets_by_country": [("countries", "US"), ("page", "1.0"), ("pageSize", "30.0")],
}

SORT_ARGS_AND_QUERY = {
    "list_compromised_endpoints": (
        {"sort_by": "created_at", "sort_order": "ASC"},
        {"sortBy": "created_at", "sortOrder": "ASC"},
    ),
    "get_compromised_endpoint_credentials": (
        {"sort_by": "username", "sort_order": "ASC"},
        {"sortBy": "username", "sortOrder": "ASC"},
    ),
    "list_credential_attempt_logs": (
        {"sort_by": "attempted_at", "sort_order": "ASC"},
        {"sortBy": "attempted_at", "sortOrder": "ASC"},
    ),
    "list_finding_retest_history": (
        {"sort_by": "updated_at", "sort_order": "ASC"},
        {"sortBy": "updated_at", "sortOrder": "ASC"},
    ),
    "get_asset_dns_records": (
        {"sort_by": "createdAt", "sort_order": "ASC", "start_date": "2026-01-01", "end_date": "2026-01-31"},
        {"sortBy": "createdAt", "sortOrder": "ASC", "startDate": "2026-01-01T00:00:00", "endDate": "2026-01-31T00:00:00"},
    ),
    "list_points_of_interest": (
        {"discovered_date_order": "ASC"},
        {"discoveredDateOrder": "ASC"},
    ),
    "get_assets_by_technology": (
        {"sort_by": "suppressed_at", "order_by": "ASC"},
        {"sortBy": "suppressed_at", "orderBy": "ASC"},
    ),
    "search_assets_by_country": (
        {"sort_by": "suppressed_at", "order_by": "ASC"},
        {"sortBy": "suppressed_at", "orderBy": "ASC"},
    ),
}

VALID_SORT_VALUES = {
    "list_compromised_endpoints": {"sort_by": ("date_compromised", "created_at"), "sort_order": ("ASC", "DESC")},
    "get_compromised_endpoint_credentials": {"sort_by": ("username",), "sort_order": ("ASC", "DESC")},
    "list_credential_attempt_logs": {"sort_by": ("attempted_at",), "sort_order": ("ASC", "DESC")},
    "list_finding_retest_history": {"sort_by": ("created_at", "updated_at"), "sort_order": ("ASC", "DESC")},
    "get_asset_dns_records": {"sort_by": ("createdAt",), "sort_order": ("ASC", "DESC")},
    "search_dns_records": {"sort_by": ("createdAt",), "sort_order": ("ASC", "DESC")},
    "list_points_of_interest": {"discovered_date_order": ("ASC", "DESC")},
    "get_assets_by_technology": {"sort_by": ("last_seen", "suppressed_at"), "order_by": ("ASC", "DESC")},
    "search_assets_by_country": {"sort_by": ("last_seen", "suppressed_at"), "order_by": ("ASC", "DESC")},
    "list_services": {"sort_by": ("last_seen", "suppressed_at"), "order_by": ("ASC", "DESC")},
    "search_pending_domains": {"sort_by": ("name", "created_at"), "sort_order": ("ASC", "DESC")},
}

FINDINGS_LIST_ORDER = "Results are ordered newest first (highest finding ID first)."

DEFAULT_ORDER_SENTENCES = {
    "search_findings": FINDINGS_LIST_ORDER,
    "list_cisa_kev_findings": FINDINGS_LIST_ORDER,
    "list_findings_by_severity": FINDINGS_LIST_ORDER,
    "get_unresolved_findings_by_business_unit": FINDINGS_LIST_ORDER,
    "get_findings_by_asset": FINDINGS_LIST_ORDER,
    "get_stale_findings": FINDINGS_LIST_ORDER + " Page 1 holds the findings just past the cutoff; the oldest stale findings are on the last page.",
    "list_asset_ips": "Results are ordered newest first (highest IP address ID first).",
    "list_vulnerability_intelligence": "Results are ordered by EPSS score, highest first.",
    "search_active_defense_library": "Results are ordered by creation date, newest first.",
    "list_points_of_interest": "Results are ordered by discovery date, newest first; set discovered_date_order to ASC for oldest first.",
}


def _sent_query(transport_calls) -> list[tuple[str, str]]:
    return sorted(parse_qsl(urlsplit(transport_calls[0][1]).query))


def _arg_description(fn, arg_name: str) -> str:
    prefix = f"{arg_name}:"
    for line in inspect.getdoc(fn).splitlines():
        if line.strip().startswith(prefix):
            return line
    raise AssertionError(f"{fn.__name__} documents no {arg_name} argument")


@pytest.mark.parametrize("tool_name", sorted(QUERY_WITHOUT_SORT_PARAMS))
def test_tool_without_sort_params_sends_the_same_query_as_before(tool_name, tools, transport_calls):
    with pytest.raises((OfflineTransport, ToolError)):
        tools[tool_name](**REQUIRED_ARGS[tool_name])

    assert _sent_query(transport_calls) == QUERY_WITHOUT_SORT_PARAMS[tool_name]


@pytest.mark.parametrize("tool_name", sorted(SORT_ARGS_AND_QUERY))
def test_tool_passes_sort_params_to_the_sdk(tool_name, tools, transport_calls):
    sort_args, expected_query = SORT_ARGS_AND_QUERY[tool_name]

    with pytest.raises((OfflineTransport, ToolError)):
        tools[tool_name](**REQUIRED_ARGS[tool_name], **sort_args)

    assert _sent_query(transport_calls) == sorted(QUERY_WITHOUT_SORT_PARAMS[tool_name] + list(expected_query.items()))


@pytest.mark.parametrize("tool_name", sorted(VALID_SORT_VALUES))
def test_sort_params_take_only_their_valid_values(tool_name, tools):
    fn = tools[tool_name]
    for arg_name, valid_values in VALID_SORT_VALUES[tool_name].items():
        parameter = inspect.signature(fn, eval_str=True).parameters[arg_name]
        assert parameter.default is None
        assert set(get_args(parameter.annotation)) == set(valid_values), f"{tool_name}.{arg_name} is not a Literal of its valid values"
        description = _arg_description(fn, arg_name)
        for value in valid_values:
            assert value in description, f"{tool_name}.{arg_name} description omits {value!r}"


@pytest.mark.parametrize("tool_name", sorted(DEFAULT_ORDER_SENTENCES))
def test_list_tool_description_states_the_default_order(tool_name, tools):
    assert DEFAULT_ORDER_SENTENCES[tool_name] in inspect.getdoc(tools[tool_name])
