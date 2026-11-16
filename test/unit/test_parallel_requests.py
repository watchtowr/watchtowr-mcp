from __future__ import annotations

import json
import threading
import time

import pytest
import urllib3
from watchtowr_api_sdk.rest import RESTClientObject, RESTResponse

from test.unit.conftest import page_of
from test.unit.test_request_headers import call_tool
from watchtowr_mcp_server import client as client_module
from watchtowr_mcp_server.client import PARALLEL_REQUESTS_PER_TOOL_CALL
from watchtowr_mcp_server.mcp import create_server

REQUEST_SECONDS = 0.2


@pytest.mark.parametrize(
    ("tool_name", "arguments", "requests", "most_seconds"),
    [
        ("get_attack_surface_summary", {}, 17, 1.5),
        ("get_week_over_week_delta", {"weeks": 4}, 56, 3.0),
        ("get_finding_status_timeline", {"days": 56}, 16, 1.5),
    ],
)
def test_composite_tools_send_their_requests_a_few_at_a_time(tool_name, arguments, requests, most_seconds, monkeypatch):
    monkeypatch.setenv("WATCHTOWR_API_KEY", "test-api-key")
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", "https://platform.example.com")
    monkeypatch.setattr(client_module, "_api_client", None)
    lock = threading.Lock()
    in_flight = 0
    most_in_flight = 0
    tool_headers: list[str | None] = []

    def slow_request(self, method, url, headers=None, body=None, post_params=None, _request_timeout=None):
        nonlocal in_flight, most_in_flight
        with lock:
            in_flight += 1
            most_in_flight = max(most_in_flight, in_flight)
            tool_headers.append((headers or {}).get("X-Watchtowr-MCP-Tool"))
        time.sleep(REQUEST_SECONDS)
        with lock:
            in_flight -= 1
        return RESTResponse(urllib3.HTTPResponse(
            body=json.dumps(page_of([])).encode(), status=200, headers={"Content-Type": "application/json"},
        ))

    monkeypatch.setattr(RESTClientObject, "request", slow_request)

    server = create_server()
    started = time.monotonic()
    result = call_tool(server, tool_name=tool_name, arguments=arguments)
    elapsed = time.monotonic() - started

    assert not result.is_error, result.content[0].text
    assert tool_headers == [tool_name] * requests
    assert 2 <= most_in_flight <= PARALLEL_REQUESTS_PER_TOOL_CALL
    assert elapsed < most_seconds, f"took {elapsed:.2f}s"
