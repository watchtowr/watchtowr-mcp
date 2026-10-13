from __future__ import annotations

import asyncio

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.api_client import ApiClient
from watchtowr_api_sdk.configuration import Configuration

from watchtowr_mcp_server import client as client_module
from watchtowr_mcp_server.client import (
    ReadOnlyModeError,
    SecureApiClient,
    read_only_mode_enabled,
)
from watchtowr_mcp_server.mcp import create_server


WRITE_ONLY_TOOLS = {
    "update_finding_status",
    "retest_finding",
    "update_finding_state",
    "bulk_retest_findings",
    "bulk_update_finding_status",
    "set_asset_criticality",
    "manage_asset_business_units",
    "update_asset_status",
    "add_seed_asset",
}


class RequestReachedCallApi(Exception):
    pass


@pytest.fixture
def set_read_only(monkeypatch):
    def _set(value: str | None):
        if value is None:
            monkeypatch.delenv("WATCHTOWR_MCP_READ_ONLY", raising=False)
        else:
            monkeypatch.setenv("WATCHTOWR_MCP_READ_ONLY", value)
        read_only_mode_enabled.cache_clear()
    yield _set
    read_only_mode_enabled.cache_clear()


@pytest.fixture
def call_api_requests(monkeypatch):
    requests: list[tuple[str, str]] = []
    api_client = SecureApiClient(Configuration(host="https://example.com"))

    def record_call_api(method, url, *args, **kwargs):
        requests.append((method, url))
        raise RequestReachedCallApi(f"{method} {url}")

    monkeypatch.setattr(api_client, "call_api", record_call_api)
    monkeypatch.setattr(client_module, "_api_client", api_client)
    return requests


def _list_tool_names() -> set[str]:
    async def _list():
        async with Client(create_server()) as mcp_client:
            return {tool.name for tool in await mcp_client.list_tools()}
    return asyncio.run(_list())


def _serialize(api_client: ApiClient, method: str):
    return api_client.param_serialize(
        method,
        "/api/client/findings/show/{id}",
        path_params={"id": 1},
        query_params=[("page", 1)],
        body={"status": "confirmed"} if method != "GET" else None,
    )


@pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "yes", "YES", "Yes", " true ", '"true"', "'yes'"])
def test_read_only_mode_is_on_for_accepted_values(set_read_only, value):
    set_read_only(value)
    assert read_only_mode_enabled() is True


@pytest.mark.parametrize("value", [None, "", "false", "FALSE", "0", "no", "No", " false ", '"no"'])
def test_read_only_mode_is_off_for_off_values(set_read_only, value):
    set_read_only(value)
    assert read_only_mode_enabled() is False


@pytest.mark.parametrize("value", ["on", "y", "enabled", "2", "off", "true # read-only"])
def test_read_only_mode_is_on_for_unrecognised_values(set_read_only, value):
    set_read_only(value)
    assert read_only_mode_enabled() is True


@pytest.mark.parametrize("value", ["on", "y", "enabled", "2", "off", "true # read-only"])
def test_server_start_warns_that_an_unrecognised_value_turns_read_only_mode_on(set_read_only, caplog, value):
    set_read_only(value)
    create_server()
    assert f"WATCHTOWR_MCP_READ_ONLY={value!r} is not one of 0, 1, false, no, true, yes" in caplog.text
    assert "read-only mode is on and write tools are disabled" in caplog.text


def test_unrecognised_value_hides_write_only_tools(set_read_only, tools):
    set_read_only("enabled")
    assert _list_tool_names() == set(tools) - WRITE_ONLY_TOOLS


@pytest.mark.parametrize("value", [None, "", "false", "no", "true", '"true"'])
def test_server_start_does_not_warn_about_a_recognised_value(set_read_only, caplog, value):
    set_read_only(value)
    create_server()
    assert "WATCHTOWR_MCP_READ_ONLY" not in caplog.text


def test_read_only_mode_serializes_get(set_read_only):
    set_read_only("true")
    api_client = SecureApiClient(Configuration(host="https://example.com"))
    method, url, *_ = _serialize(api_client, "GET")
    assert method == "GET"
    assert url == "https://example.com/api/client/findings/show/1?page=1"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post", "delete"])
def test_read_only_mode_refuses_non_get_serialization(set_read_only, method):
    set_read_only("true")
    api_client = SecureApiClient(Configuration(host="https://example.com"))
    with pytest.raises(ReadOnlyModeError, match="WATCHTOWR_MCP_READ_ONLY"):
        _serialize(api_client, method)


def test_read_only_mode_lets_sdk_get_reach_call_api(set_read_only, call_api_requests):
    set_read_only("true")
    with pytest.raises(RequestReachedCallApi):
        FindingsApi(client_module._api_client).get_finding_details(id=1)
    [(method, url)] = call_api_requests
    assert method == "GET"
    assert url.startswith("https://example.com/api/client/findings/show/1")


@pytest.mark.parametrize("send_write", [
    lambda api: api.start_specific_finding_retest(finding_id=1),
    lambda api: api.delete_finding_note(id=1, note_id=2),
], ids=["POST", "DELETE"])
def test_read_only_mode_stops_sdk_writes_before_call_api(set_read_only, call_api_requests, send_write):
    set_read_only("true")
    with pytest.raises(ReadOnlyModeError, match="WATCHTOWR_MCP_READ_ONLY"):
        send_write(FindingsApi(client_module._api_client))
    assert call_api_requests == []


@pytest.mark.parametrize("value", [None, "false"])
@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_writes_serialize_as_before_when_read_only_mode_is_off(set_read_only, value, method):
    set_read_only(value)
    configuration = Configuration(host="https://example.com")
    secure_client = SecureApiClient(configuration)
    base_client = ApiClient(configuration)
    base_client.user_agent = secure_client.user_agent
    assert _serialize(secure_client, method) == _serialize(base_client, method)


@pytest.mark.parametrize("value", [None, "false"])
def test_sdk_writes_reach_call_api_when_read_only_mode_is_off(set_read_only, call_api_requests, value):
    set_read_only(value)
    with pytest.raises(RequestReachedCallApi):
        FindingsApi(client_module._api_client).start_specific_finding_retest(finding_id=1)
    [(method, url)] = call_api_requests
    assert method == "POST"
    assert url.startswith("https://example.com/api/client/findings/retest/1")


def test_write_tag_marks_exactly_the_write_only_tools(set_read_only):
    set_read_only(None)
    tools = asyncio.run(create_server().list_tools())
    tagged = {tool.name for tool in tools if "write" in tool.tags}
    assert tagged == WRITE_ONLY_TOOLS


def test_read_only_mode_hides_write_only_tools_from_listing(set_read_only, tools):
    set_read_only("true")
    assert _list_tool_names() == set(tools) - WRITE_ONLY_TOOLS


@pytest.mark.parametrize("tool_name", sorted(WRITE_ONLY_TOOLS))
def test_read_only_mode_makes_write_only_tools_uncallable(set_read_only, call_api_requests, tool_name):
    set_read_only("true")

    async def call_hidden_tool():
        async with Client(create_server()) as mcp_client:
            await mcp_client.call_tool(tool_name, {})

    with pytest.raises(ToolError, match="Unknown tool"):
        asyncio.run(call_hidden_tool())
    assert call_api_requests == []


@pytest.mark.parametrize("value", [None, "false"])
def test_all_tools_are_listed_when_read_only_mode_is_off(set_read_only, tools, value):
    set_read_only(value)
    assert _list_tool_names() == set(tools)


MIXED_TOOL_WRITE_CALLS = [
    ("manage_engine_settings", {"asset_type": "domain", "asset_id": 1, "action": "update", "rapid_reaction_enabled": True}),
    ("manage_asset_custom_property", {"asset_type": "domain", "asset_id": 1, "action": "create", "key": "owner", "value": "example"}),
    ("manage_asset_custom_property", {"asset_type": "domain", "asset_id": 1, "action": "update", "custom_property_id": 2, "key": "owner", "value": "example"}),
    ("manage_asset_custom_property", {"asset_type": "domain", "asset_id": 1, "action": "delete", "custom_property_id": 2}),
    ("manage_asset_notes", {"asset_type": "domain", "asset_id": 1, "action": "create", "note": "example note"}),
    ("manage_asset_notes", {"asset_type": "domain", "asset_id": 1, "action": "update", "note_id": 2, "note": "example note"}),
    ("manage_asset_notes", {"asset_type": "domain", "asset_id": 1, "action": "delete", "note_id": 2}),
]

MIXED_TOOL_READ_CALLS = [
    ("manage_engine_settings", {"asset_type": "domain", "asset_id": 1, "action": "get"}),
    ("manage_asset_custom_property", {"asset_type": "domain", "asset_id": 1, "action": "list"}),
    ("manage_asset_notes", {"asset_type": "domain", "asset_id": 1, "action": "list"}),
]


@pytest.mark.parametrize("tool_name,kwargs", MIXED_TOOL_WRITE_CALLS)
def test_read_only_mode_rejects_mixed_tool_writes_without_a_request(
    set_read_only, call_api_requests, call, tool_name, kwargs,
):
    set_read_only("true")
    with pytest.raises(ToolError, match="WATCHTOWR_MCP_READ_ONLY"):
        call(tool_name, **kwargs)
    assert call_api_requests == []


@pytest.mark.parametrize("tool_name,kwargs", MIXED_TOOL_READ_CALLS)
def test_read_only_mode_lets_mixed_tool_reads_reach_the_sdk(
    set_read_only, call_api_requests, call, tool_name, kwargs,
):
    set_read_only("true")
    with pytest.raises(RequestReachedCallApi):
        call(tool_name, **kwargs)
    assert len(call_api_requests) == 1
    assert call_api_requests[0][0] == "GET"


@pytest.mark.parametrize("tool_name,kwargs", MIXED_TOOL_WRITE_CALLS)
def test_every_mixed_tool_refuses_a_write_with_the_same_wording(set_read_only, call_api_requests, call, tool_name, kwargs):
    set_read_only("true")
    with pytest.raises(ToolError) as raised:
        call(tool_name, **kwargs)
    assert str(raised.value) == (
        f"action {kwargs['action']!r} is refused because WATCHTOWR_MCP_READ_ONLY is on; "
        "the MCP server only reads from the watchTowr Platform in read-only mode."
    )
