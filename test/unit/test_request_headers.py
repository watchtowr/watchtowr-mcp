from __future__ import annotations

import asyncio
import importlib.metadata
import re
from pathlib import Path
from typing import NamedTuple

import pytest
import urllib3
from fastmcp import Client, FastMCP
from mcp.server.session import ServerSession
from mcp.types import Implementation
from watchtowr_api_sdk.api.source_ip_addresses_api import SourceIPAddressesApi
from watchtowr_api_sdk.rest import RESTClientObject, RESTResponse

import watchtowr_mcp_server
from watchtowr_mcp_server import client as client_module
from watchtowr_mcp_server.mcp import create_server
from watchtowr_mcp_server.middleware import MAX_MCP_CLIENT_HEADER_LENGTH


PACKAGE_VERSION = importlib.metadata.version("watchtowr-mcp")
TOOL_NAME = "get_watchtowr_source_ips"
BULK_RETEST_TOOL_NAME = "bulk_retest_findings"
NO_SOURCE_IPS = "No source IP addresses found."


class SentRequest(NamedTuple):
    method: str
    url: str
    headers: dict[str, str]


@pytest.fixture
def sent_requests(monkeypatch) -> list[SentRequest]:
    monkeypatch.setenv("WATCHTOWR_API_KEY", "test-api-key")
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", "https://platform.example.com")
    monkeypatch.setattr(client_module, "_api_client", None)
    requests: list[SentRequest] = []

    def record_request(self, method, url, headers=None, body=None,
                       post_params=None, _request_timeout=None):
        requests.append(SentRequest(method, url, dict(headers or {})))
        return RESTResponse(urllib3.HTTPResponse(
            body=b'{"data": []}',
            status=200,
            headers={"Content-Type": "application/json"},
        ))

    monkeypatch.setattr(RESTClientObject, "request", record_request)
    return requests


@pytest.fixture
def server() -> FastMCP:
    return create_server()


def call_tool(server: FastMCP, client_info: Implementation | None = None,
              tool_name: str = TOOL_NAME, arguments: dict | None = None):
    async def run():
        async with Client(server, client_info=client_info) as mcp_client:
            return await mcp_client.call_tool(tool_name, arguments or {}, raise_on_error=False)
    return asyncio.run(run())


def list_source_ips_outside_a_tool_call():
    return SourceIPAddressesApi(client_module.get_api_client()).get_list_source_ip_addresses()


def test_package_version_matches_pyproject():
    pyproject = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text()
    assert watchtowr_mcp_server.__version__ == re.search(r'^version = "(.+)"$', pyproject, re.MULTILINE).group(1)


def test_sdk_request_outside_a_tool_call_sends_only_the_mcp_user_agent(sent_requests):
    list_source_ips_outside_a_tool_call()

    assert sent_requests[0].headers["User-Agent"] == f"watchtowr-mcp/{PACKAGE_VERSION}"
    assert "X-Watchtowr-MCP-Tool" not in sent_requests[0].headers
    assert "X-Watchtowr-MCP-Client" not in sent_requests[0].headers


def test_every_request_of_one_tool_call_carries_tool_name(sent_requests, server):
    call_tool(server, tool_name=BULK_RETEST_TOOL_NAME, arguments={"finding_ids": "1,2"})

    assert len(sent_requests) == 2
    assert all(r.headers["X-Watchtowr-MCP-Tool"] == BULK_RETEST_TOOL_NAME for r in sent_requests)


def test_concurrent_tool_calls_each_send_their_own_tool_name(sent_requests, server):
    async def run():
        async with Client(server) as mcp_client:
            await asyncio.gather(
                mcp_client.call_tool(TOOL_NAME, {}),
                mcp_client.call_tool(BULK_RETEST_TOOL_NAME, {"finding_ids": "1,2,3"}, raise_on_error=False),
            )
    asyncio.run(run())

    tool_per_request = {
        (r.method, r.url.split("/api/client/")[1]): r.headers["X-Watchtowr-MCP-Tool"]
        for r in sent_requests
    }
    assert tool_per_request == {
        ("GET", "testing-infrastructure"): TOOL_NAME,
        ("POST", "findings/retest/1.0"): BULK_RETEST_TOOL_NAME,
        ("POST", "findings/retest/2.0"): BULK_RETEST_TOOL_NAME,
        ("POST", "findings/retest/3.0"): BULK_RETEST_TOOL_NAME,
    }


def test_tool_call_request_carries_mcp_client_name_and_version(sent_requests, server):
    call_tool(server, client_info=Implementation(name="example-client", version="1.2.3"))

    assert sent_requests[0].headers["X-Watchtowr-MCP-Client"] == "example-client/1.2.3"


def test_tool_call_sends_client_header_at_the_length_limit(sent_requests, server):
    version = "1.2.3"
    name = "c" * (MAX_MCP_CLIENT_HEADER_LENGTH - len(version) - 1)

    call_tool(server, client_info=Implementation(name=name, version=version))

    assert sent_requests[0].headers["X-Watchtowr-MCP-Client"] == f"{name}/{version}"


def test_tool_call_without_client_params_omits_client_header(sent_requests, server, monkeypatch):
    monkeypatch.setattr(ServerSession, "client_params", property(lambda self: None))

    result = call_tool(server)

    assert result.data == NO_SOURCE_IPS
    assert sent_requests[0].headers["X-Watchtowr-MCP-Tool"] == TOOL_NAME
    assert "X-Watchtowr-MCP-Client" not in sent_requests[0].headers


@pytest.mark.parametrize("client_name", [
    "example\r\nclient",
    "exämple-client",
    "例子-client",
    "c" * MAX_MCP_CLIENT_HEADER_LENGTH,
])
def test_tool_call_with_unsendable_client_name_omits_client_header(sent_requests, server, client_name):
    result = call_tool(server, client_info=Implementation(name=client_name, version="1.2.3"))

    assert result.data == NO_SOURCE_IPS
    assert sent_requests[0].headers["X-Watchtowr-MCP-Tool"] == TOOL_NAME
    assert "X-Watchtowr-MCP-Client" not in sent_requests[0].headers
