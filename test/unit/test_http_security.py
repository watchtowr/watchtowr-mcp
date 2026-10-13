"""streamable-http lockdown: loopback bind by default, Host/Origin
validation, and per-request caller API keys. stdio must keep using the env key."""
from __future__ import annotations

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from watchtowr_mcp_server import client as client_module
from watchtowr_mcp_server import mcp as mcp_module
from watchtowr_mcp_server.client import get_api_client
from watchtowr_mcp_server.http_security import build_http_middleware

CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "whoami", "arguments": {}},
}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("WATCHTOWR_API_KEY", "env-key")
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", "https://tenant.example.watchtowr.io")
    monkeypatch.delenv("MCP_HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("MCP_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setattr(client_module, "_api_client", None)
    client_module._client_for.cache_clear()


@pytest.fixture
def http(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    yield from _whoami_http_app()


@pytest.fixture
def http_without_transport_env():
    yield from _whoami_http_app()


def _whoami_http_app():
    calls: list[str] = []
    server = FastMCP("test")

    @server.tool()
    def whoami() -> str:
        token = get_api_client().configuration.access_token
        calls.append(token)
        return token

    app = server.http_app(
        path="/mcp", middleware=build_http_middleware(), stateless_http=True, json_response=True
    )
    with TestClient(app, base_url="http://localhost:8080") as test_client:
        yield test_client, calls


def _call(test_client, **headers):
    return test_client.post("/mcp", json=CALL, headers={**HEADERS, **headers})


def test_missing_credentials_rejected(http):
    test_client, calls = http
    response = _call(test_client)
    assert response.status_code == 401
    assert calls == []


def test_non_bearer_authorization_rejected(http):
    test_client, calls = http
    assert _call(test_client, Authorization="Basic abc").status_code == 401
    assert calls == []


def test_disallowed_host_rejected(http):
    test_client, calls = http
    response = _call(test_client, Authorization="Bearer key-a", Host="evil.example")
    assert response.status_code == 421
    assert calls == []


def test_disallowed_origin_rejected(http):
    test_client, calls = http
    response = _call(test_client, Authorization="Bearer key-a", Origin="http://evil.example")
    assert response.status_code == 403
    assert calls == []


def test_each_caller_uses_own_key(http):
    test_client, calls = http
    for key in ("key-a", "key-b", "key-a"):
        response = _call(test_client, Authorization=f"Bearer {key}")
        assert response.status_code == 200
        assert response.json()["result"]["content"][0]["text"] == key
    assert calls == ["key-a", "key-b", "key-a"]


def test_allow_lists_configurable(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "mcp.internal")
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", "https://app.internal")
    server = FastMCP("test")
    server.tool(name="whoami")(lambda: "ok")
    app = server.http_app(
        path="/mcp", middleware=build_http_middleware(), stateless_http=True, json_response=True
    )
    with TestClient(app, base_url="http://mcp.internal") as test_client:
        auth = {"Authorization": "Bearer key-a"}
        assert _call(test_client, **auth, Origin="https://app.internal").status_code == 200
        assert _call(test_client, **auth, Host="localhost:8080").status_code == 421


def test_http_binds_loopback_by_default(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    captured: dict = {}
    monkeypatch.setattr(FastMCP, "run", lambda self, **kwargs: captured.update(kwargs))
    mcp_module.main()
    assert captured["host"] == "127.0.0.1"
    assert captured["middleware"]


def test_quoted_allow_lists_are_unquoted(monkeypatch):
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", '"mcp.internal"')
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", "'https://app.internal'")
    server = FastMCP("test")
    server.tool(name="whoami")(lambda: "ok")
    app = server.http_app(
        path="/mcp", middleware=build_http_middleware(), stateless_http=True, json_response=True
    )
    with TestClient(app, base_url="http://mcp.internal") as test_client:
        auth = {"Authorization": "Bearer key-a"}
        assert _call(test_client, **auth, Origin="https://app.internal").status_code == 200


def test_quoted_http_host_and_port_are_unquoted(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_HOST", '"127.0.0.1"')
    monkeypatch.setenv("PORT", '"9090"')
    captured: dict = {}
    monkeypatch.setattr(FastMCP, "run", lambda self, **kwargs: captured.update(kwargs))
    mcp_module.main()
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9090


@pytest.mark.parametrize("port", ["http", "0", "65536"])
def test_invalid_port_names_the_variable(port, monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("PORT", port)
    monkeypatch.setattr(FastMCP, "run", lambda self, **kwargs: None)
    with pytest.raises(ValueError, match="PORT must be a whole number from 1 to 65535"):
        mcp_module.main()


def test_http_served_without_main_still_uses_each_callers_key(http_without_transport_env):
    test_client, calls = http_without_transport_env
    response = _call(test_client, Authorization="Bearer key-a")
    assert response.json()["result"]["content"][0]["text"] == "key-a"
    assert calls == ["key-a"]


def test_quoted_env_key_and_host_are_unquoted(monkeypatch):
    monkeypatch.setenv("WATCHTOWR_API_KEY", '"env-key"')
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", "'https://tenant.example.watchtowr.io'")
    configuration = get_api_client().configuration
    assert configuration.access_token == "env-key"
    assert configuration.host == "https://tenant.example.watchtowr.io"


def test_stdio_uses_env_key(monkeypatch):
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    assert get_api_client().configuration.access_token == "env-key"
