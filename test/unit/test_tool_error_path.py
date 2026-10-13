from __future__ import annotations

import inspect
import types
import typing
from urllib.parse import parse_qs, urlsplit

import pytest
from fastmcp.exceptions import ToolError
from watchtowr_api_sdk.configuration import Configuration

import watchtowr_mcp_server.client as client_module
from watchtowr_mcp_server.client import SecureApiClient
from watchtowr_mcp_server.constants import MAX_BULK_FINDING_IDS


SENTINEL = "offline-transport-sentinel"

REQUIRED_ARG_OVERRIDES: dict[str, dict] = {
    "add_seed_asset": {"asset_type": "domain", "asset_value": "example.invalid"},
    "bulk_retest_findings": {"finding_ids": "1"},
    "bulk_update_finding_status": {"finding_ids": "1", "status": "confirmed"},
    "get_business_unit_posture": {"business_unit_id": 1},
    "manage_asset_business_units": {"asset_type": "domain", "action": "assign", "business_unit_ids": [1]},
    "manage_asset_custom_property": {"asset_type": "domain", "action": "list"},
    "manage_asset_notes": {"asset_type": "domain", "action": "list"},
    "manage_engine_settings": {"asset_type": "domain"},
    "find_related_assets": {"asset_type": "domain"},
    "get_asset_changelog": {"asset_type": "domain"},
    "update_asset_status": {"asset_type": "domain", "status": "verified"},
    "get_findings_by_asset": {"asset_type": "domain"},
    "set_asset_criticality": {"asset_type": "domain", "criticality": "High"},
    "update_finding_state": {"state": "Completed"},
    "update_finding_status": {"status": "confirmed"},
}


class OfflineTransport(Exception):
    pass


@pytest.fixture
def transport_calls(monkeypatch) -> list:
    calls: list = []

    def record_and_raise(*args, **kwargs):
        calls.append(args)
        raise OfflineTransport(SENTINEL)

    configuration = Configuration()
    configuration.host = "https://offline.invalid"
    api_client = SecureApiClient(configuration)
    monkeypatch.setattr(api_client, "call_api", record_and_raise)
    monkeypatch.setattr(client_module, "_api_client", api_client)
    return calls


def _placeholder(annotation):
    origin = typing.get_origin(annotation)
    if origin is typing.Union or isinstance(annotation, types.UnionType):
        annotation = [a for a in typing.get_args(annotation) if a is not type(None)][0]
        origin = typing.get_origin(annotation)
    if annotation is int:
        return 1
    if annotation is float:
        return 1.0
    if annotation is bool:
        return False
    if origin in (list, typing.List) or annotation is list:
        return []
    if origin in (dict, typing.Dict) or annotation is dict:
        return {}
    return "placeholder"


def _minimal_args(fn, name: str) -> dict:
    args = {
        p.name: _placeholder(p.annotation)
        for p in inspect.signature(fn).parameters.values()
        if p.default is inspect.Parameter.empty
    }
    args.update(REQUIRED_ARG_OVERRIDES.get(name, {}))
    return args


def _tool_names() -> list[str]:
    from test.conftest import ToolCapture
    from watchtowr_mcp_server.tools import register_all_tools

    capture = ToolCapture()
    register_all_tools(capture)
    return sorted(capture.tools)


@pytest.mark.parametrize("tool_name", _tool_names())
def test_tool_reaches_sdk_transport(tool_name, tools, transport_calls):
    fn = tools[tool_name]
    with pytest.raises((OfflineTransport, ToolError)):
        fn(**_minimal_args(fn, tool_name))
    assert transport_calls, f"{tool_name} did not reach the SDK transport"


DATE_FILTER_SUFFIXES = ("_from", "_to", "_since", "_after", "_before")


def _date_filter_params(fn) -> list[str]:
    return [
        p.name for p in inspect.signature(fn).parameters.values()
        if p.name.endswith(DATE_FILTER_SUFFIXES) and p.annotation is str
    ]


def _tools_with_date_filters() -> list[str]:
    from test.conftest import ToolCapture
    from watchtowr_mcp_server.tools import register_all_tools

    capture = ToolCapture()
    register_all_tools(capture)
    return sorted(name for name, fn in capture.tools.items() if _date_filter_params(fn))


@pytest.mark.parametrize("tool_name", _tools_with_date_filters())
def test_tool_date_filters_reach_sdk_transport(tool_name, tools, transport_calls):
    fn = tools[tool_name]
    args = _minimal_args(fn, tool_name)
    args.update({name: "2026-01-01" for name in _date_filter_params(fn)})
    with pytest.raises((OfflineTransport, ToolError)):
        fn(**args)
    assert transport_calls, f"{tool_name} did not reach the SDK transport with date filters"


@pytest.mark.parametrize(
    ("arguments", "expected_resolved"),
    [
        ({"only_resolved": True}, ["true"]),
        ({"only_resolved": False}, ["false"]),
        ({"resolved": False, "only_resolved": True}, ["false"]),
    ],
)
def test_search_hunts_sends_only_resolved_as_resolved(arguments, expected_resolved, tools, transport_calls):
    with pytest.raises(OfflineTransport):
        tools["search_hunts"](**arguments)
    query = parse_qs(urlsplit(transport_calls[0][1]).query)
    assert query.get("resolved") == expected_resolved
    assert "only_resolved" not in query and "onlyResolved" not in query


BULK_WRITE_TOOLS = ("bulk_retest_findings", "bulk_update_finding_status")


def _call_bulk(tools, tool_name: str, ids) -> str:
    args = {**REQUIRED_ARG_OVERRIDES[tool_name], "finding_ids": ",".join(str(i) for i in ids)}
    return tools[tool_name](**args)


@pytest.mark.parametrize("tool_name", BULK_WRITE_TOOLS)
def test_bulk_write_at_the_cap_processes_every_id(tool_name, tools, transport_calls):
    with pytest.raises(ToolError):
        _call_bulk(tools, tool_name, range(1, MAX_BULK_FINDING_IDS + 1))
    assert len(transport_calls) == MAX_BULK_FINDING_IDS


@pytest.mark.parametrize("tool_name", BULK_WRITE_TOOLS)
def test_bulk_write_over_the_cap_sends_nothing_and_names_the_cap(tool_name, tools, transport_calls):
    with pytest.raises(ToolError) as exc:
        _call_bulk(tools, tool_name, range(1, MAX_BULK_FINDING_IDS + 2))
    result = str(exc.value)
    assert not transport_calls
    assert f"max {MAX_BULK_FINDING_IDS} per call" in result
    assert "batch" not in result.lower() and "split" not in result.lower()


@pytest.mark.parametrize("tool_name", BULK_WRITE_TOOLS)
def test_bulk_write_counts_duplicate_ids_once(tool_name, tools, transport_calls):
    ids = list(range(1, MAX_BULK_FINDING_IDS + 1))
    with pytest.raises(ToolError):
        _call_bulk(tools, tool_name, ids + ids[:5])
    assert len(transport_calls) == MAX_BULK_FINDING_IDS


@pytest.mark.parametrize("tool_name", BULK_WRITE_TOOLS)
def test_bulk_write_description_states_the_cap(tool_name, tools):
    assert f"at most {MAX_BULK_FINDING_IDS} unique IDs" in tools[tool_name].__doc__
