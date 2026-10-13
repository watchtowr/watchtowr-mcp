from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time

import pytest
import urllib3
from fastmcp import Client
from fastmcp.exceptions import ToolError
from watchtowr_api_sdk.api.findings_api import FindingsApi

import watchtowr_mcp_server.client as client_module
from watchtowr_mcp_server.client import (
    DEFAULT_REQUEST_TIMEOUT,
    UNREACHABLE_HINT,
    api_error_summary,
    request_timeout,
)
from test.unit.test_tool_error_path import _minimal_args, _tool_names
from test.unit.test_tool_errors import _call_tool_over_mcp
from watchtowr_mcp_server.mcp import create_server


class OfflineTransport(Exception):
    pass


@pytest.fixture
def sent_timeouts(monkeypatch) -> list:
    timeouts: list = []

    def record_and_raise(*args, _request_timeout=None, **kwargs):
        timeouts.append(_request_timeout)
        raise OfflineTransport()

    api_client = client_module._client_for("offline-key", "https://offline.invalid")
    monkeypatch.setattr(api_client.rest_client, "request", record_and_raise)
    monkeypatch.setattr(client_module, "_api_client", api_client)
    return timeouts


@pytest.mark.parametrize("tool_name", _tool_names())
def test_every_tool_request_carries_the_default_timeout(tool_name, tools, sent_timeouts):
    fn = tools[tool_name]
    with contextlib.suppress(OfflineTransport, ToolError):
        fn(**_minimal_args(fn, tool_name))
    assert sent_timeouts, f"{tool_name} sent no request"
    assert set(sent_timeouts) == {DEFAULT_REQUEST_TIMEOUT}


def test_env_var_overrides_the_default_timeout(monkeypatch, sent_timeouts):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "7.5")
    with pytest.raises(OfflineTransport):
        FindingsApi(client_module.get_api_client()).get_available_finding_statuses()
    assert sent_timeouts == [7.5]


def test_explicit_per_call_timeout_is_kept(sent_timeouts):
    with pytest.raises(OfflineTransport):
        FindingsApi(client_module.get_api_client()).get_available_finding_statuses(_request_timeout=3)
    assert sent_timeouts == [3]


@pytest.mark.parametrize("value", ["abc", "0", "-5", "nan", "inf", "1e10", "601"])
def test_invalid_timeout_names_the_env_var(monkeypatch, value):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", value)
    with pytest.raises(ToolError, match="WATCHTOWR_MCP_REQUEST_TIMEOUT"):
        request_timeout()


@pytest.mark.parametrize("value", ['"7.5"', "'7.5'", " 7.5 "])
def test_quotes_around_the_timeout_are_ignored(monkeypatch, value):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", value)
    assert request_timeout() == 7.5


def test_the_longest_accepted_timeout_is_600_seconds(monkeypatch):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "600")
    assert request_timeout() == 600


@pytest.fixture
def silent_server():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    yield f"http://127.0.0.1:{server.getsockname()[1]}"
    server.close()


@contextlib.contextmanager
def _serve(answer_request):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()

    def accept_forever():
        while True:
            try:
                connection, _ = server.accept()
            except OSError:
                return
            request = b""
            while b"\r\n\r\n" not in request:
                request += connection.recv(65536)
            answer_request(connection)

    threading.Thread(target=accept_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.getsockname()[1]}"
    finally:
        server.close()


@pytest.fixture
def headers_then_stalled_body_server():
    def answer(connection):
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")

    with _serve(answer) as url:
        yield url


@pytest.fixture
def slow_drip_body_server():
    def answer(connection):
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n")
        with contextlib.suppress(OSError):
            for _ in range(100):
                time.sleep(0.05)
                connection.sendall(b" ")

    with _serve(answer) as url:
        yield url


@pytest.fixture
def closes_without_answering_server():
    attempts: list[int] = []

    def close(connection):
        attempts.append(1)
        connection.close()

    with _serve(close) as url:
        yield url, attempts


@pytest.fixture
def rate_limited_server():
    answered: list[float] = []

    def answer(connection):
        answered.append(time.monotonic())
        connection.sendall(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Length: 0\r\n\r\n")

    with _serve(answer) as url:
        yield url, answered


def test_tool_returns_timeout_error_when_the_platform_never_answers(monkeypatch, tools, silent_server):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "0.5")
    monkeypatch.setattr(client_module, "_api_client", client_module._client_for("offline-key", silent_server))

    started = time.monotonic()
    with pytest.raises(ToolError, match="no answer from the watchTowr Platform within 0.5 seconds - try a narrower query"):
        tools["get_finding_statuses"]()
    elapsed = time.monotonic() - started

    assert elapsed < 2, f"took {elapsed:.1f}s, the timeout was retried"


@pytest.mark.parametrize(
    "error",
    [urllib3.exceptions.ConnectTimeoutError(None, "connect timed out"),
     urllib3.exceptions.ReadTimeoutError(None, "/api", "read timed out")],
)
def test_timeouts_are_not_retried(error):
    retries = client_module._client_for("offline-key", "https://offline.invalid").configuration.retries
    with pytest.raises(type(error)):
        retries.increment("GET", "/api", error=error)


@pytest.mark.parametrize(
    "error",
    [urllib3.exceptions.ProtocolError("Connection aborted.", ConnectionResetError()),
     urllib3.exceptions.NewConnectionError(None, "connection refused")],
)
def test_dropped_and_refused_connections_keep_the_default_retries(error):
    retries = client_module._client_for("offline-key", "https://offline.invalid").configuration.retries
    assert retries.increment("GET", "/api", error=error).total == urllib3.Retry.DEFAULT.total - 1


def test_connect_timeout_tells_the_model_to_check_the_host():
    assert api_error_summary(urllib3.exceptions.ConnectTimeoutError(None, "connect timed out")) == UNREACHABLE_HINT


def test_write_timeout_says_the_change_may_already_have_been_made(monkeypatch, silent_server):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "0.5")
    api_client = client_module._client_for("offline-key", silent_server)

    with pytest.raises(urllib3.exceptions.ReadTimeoutError) as raised:
        FindingsApi(api_client).start_specific_finding_retest(finding_id=1)

    assert api_error_summary(raised.value) == (
        "no answer from the watchTowr Platform within 0.5 seconds - "
        "the change may already have been made, check its current state before retrying"
    )


def test_write_whose_body_stalls_says_the_change_may_already_have_been_made(monkeypatch, headers_then_stalled_body_server):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "0.5")
    api_client = client_module._client_for("offline-key", headers_then_stalled_body_server)

    with pytest.raises(urllib3.exceptions.ReadTimeoutError) as raised:
        FindingsApi(api_client).start_specific_finding_retest(finding_id=1)

    assert "the change may already have been made" in api_error_summary(raised.value)
    assert str(raised.value).count("HTTPConnectionPool") == 1


def test_write_whose_connection_drops_says_the_change_may_already_have_been_made(closes_without_answering_server):
    url, _ = closes_without_answering_server
    api_client = client_module._client_for("offline-key", url)

    with pytest.raises(urllib3.exceptions.ProtocolError) as raised:
        FindingsApi(api_client).start_specific_finding_retest(finding_id=1)

    assert api_error_summary(raised.value) == (
        "the watchTowr Platform closed the connection without answering - "
        "the change may already have been made, check its current state before retrying"
    )


def test_read_whose_connection_drops_is_retried_and_reported_as_closed(closes_without_answering_server):
    url, attempts = closes_without_answering_server
    api_client = client_module._client_for("offline-key", url)

    with pytest.raises(urllib3.exceptions.MaxRetryError) as raised:
        FindingsApi(api_client).get_available_finding_statuses()

    assert len(attempts) == urllib3.Retry.DEFAULT.total + 1
    assert api_error_summary(raised.value) == (
        "the watchTowr Platform closed the connection before the response was complete - retry"
    )


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "POST"])
def test_a_dropped_write_is_sent_once_and_says_the_change_may_already_have_been_made(method, closes_without_answering_server):
    url, attempts = closes_without_answering_server
    api_client = client_module._client_for("offline-key", url)

    with pytest.raises(urllib3.exceptions.ProtocolError) as raised:
        api_client.call_api(method, f"{url}/api/client/assets/domain/1", header_params={})

    assert len(attempts) == 1
    assert api_error_summary(raised.value) == (
        "the watchTowr Platform closed the connection without answering - "
        "the change may already have been made, check its current state before retrying"
    )


def test_a_truncated_read_body_says_the_connection_closed_mid_response():
    def answer(connection):
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"data\": [")
        connection.close()

    with _serve(answer) as url:
        api_client = client_module._client_for("offline-key", url)
        with pytest.raises(urllib3.exceptions.ProtocolError) as raised:
            FindingsApi(api_client).get_available_finding_statuses()

    assert api_error_summary(raised.value) == (
        "the watchTowr Platform closed the connection before the response was complete - retry"
    )


def test_retry_after_is_not_waited_for(rate_limited_server):
    url, answered = rate_limited_server
    api_client = client_module._client_for("offline-key", url)

    started = time.monotonic()
    with pytest.raises(client_module.ApiException) as raised:
        FindingsApi(api_client).get_available_finding_statuses()

    assert raised.value.status == 429
    assert time.monotonic() - started < 2
    assert len(answered) == 1


def test_callers_share_one_connection_pool_per_platform_host():
    first = client_module._client_for("key-a", "https://offline.invalid")
    second = client_module._client_for("key-b", "https://offline.invalid")

    assert first.configuration.access_token == "key-a"
    assert second.configuration.access_token == "key-b"
    assert first.rest_client is second.rest_client


def test_a_body_that_keeps_trickling_in_still_times_out(monkeypatch, slow_drip_body_server):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "0.5")
    api_client = client_module._client_for("offline-key", slow_drip_body_server)

    started = time.monotonic()
    with pytest.raises(urllib3.exceptions.ReadTimeoutError) as raised:
        FindingsApi(api_client).get_available_finding_statuses()

    assert time.monotonic() - started < 2
    assert api_error_summary(raised.value).endswith("try a narrower query, or raise WATCHTOWR_MCP_REQUEST_TIMEOUT")


def test_after_one_request_gets_no_answer_the_rest_of_the_tool_call_is_skipped(monkeypatch, silent_server):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "0.3")
    monkeypatch.setattr(client_module, "_api_client", client_module._client_for("offline-key", silent_server))

    started = time.monotonic()
    result = _call_tool_over_mcp("get_new_assets_since", {"days": 7})
    elapsed = time.monotonic() - started

    text = result.content[0].text
    assert result.is_error
    assert "IP Addresses failed: no answer from the watchTowr Platform within 0.3 seconds" in text
    assert "Domains failed: skipped because an earlier request in this tool call got no answer" in text
    assert elapsed < 1.5, f"took {elapsed:.1f}s"


@pytest.mark.parametrize(("status_line", "rest_of_call_skipped"), [
    (b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60", True),
    (b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 60", True),
    (b"HTTP/1.1 503 Service Unavailable", False),
])
def test_the_rest_of_the_tool_call_is_skipped_only_when_the_platform_asks_to_back_off(
    monkeypatch, status_line, rest_of_call_skipped,
):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "0.5")
    answered: list[int] = []

    def answer(connection):
        answered.append(1)
        connection.sendall(status_line + b"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        connection.close()

    with _serve(answer) as url:
        monkeypatch.setattr(client_module, "_api_client", client_module._client_for("offline-key", url))
        result = _call_tool_over_mcp("get_new_assets_since", {"days": 7})

    text = result.content[0].text
    skipped = "Domains failed: skipped because the watchTowr Platform rate limited an earlier request in this tool call"
    assert (skipped in text) == rest_of_call_skipped
    assert (len(answered) == 1) == rest_of_call_skipped


def test_the_next_tool_call_tries_the_platform_again(monkeypatch, silent_server):
    monkeypatch.setenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", "0.3")
    monkeypatch.setattr(client_module, "_api_client", client_module._client_for("offline-key", silent_server))

    async def call_twice():
        async with Client(create_server()) as mcp_client:
            return [
                await mcp_client.call_tool("get_finding_statuses", {}, raise_on_error=False)
                for _ in range(2)
            ]

    for result in asyncio.run(call_twice()):
        assert "no answer from the watchTowr Platform within 0.3 seconds" in result.content[0].text
