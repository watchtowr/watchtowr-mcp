import json
import re
from typing import NamedTuple
from urllib.parse import urlsplit

import pytest
import urllib3
from watchtowr_api_sdk.configuration import Configuration
from watchtowr_api_sdk.rest import RESTResponse

import watchtowr_mcp_server.client as client_module
from watchtowr_mcp_server.client import SecureApiClient, read_only_mode_enabled, request_timeout


@pytest.fixture(autouse=True)
def read_only_mode_off_unless_a_test_turns_it_on(monkeypatch):
    monkeypatch.delenv("WATCHTOWR_MCP_READ_ONLY", raising=False)
    read_only_mode_enabled.cache_clear()
    yield
    read_only_mode_enabled.cache_clear()


@pytest.fixture(autouse=True)
def stdio_transport_unless_a_test_sets_one(monkeypatch):
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)


@pytest.fixture(autouse=True)
def no_platform_host_unless_a_test_sets_one(monkeypatch):
    monkeypatch.delenv("WATCHTOWR_PLATFORM_HOST", raising=False)


@pytest.fixture(autouse=True)
def default_request_timeout_unless_a_test_sets_one(monkeypatch):
    monkeypatch.delenv("WATCHTOWR_MCP_REQUEST_TIMEOUT", raising=False)
    request_timeout.cache_clear()
    yield
    request_timeout.cache_clear()


class JsonReply(NamedTuple):
    body: object
    status: int = 200

    def as_rest_response(self) -> RESTResponse:
        return RESTResponse(urllib3.HTTPResponse(
            body=json.dumps(self.body).encode(),
            status=self.status,
            headers={"Content-Type": "application/json"},
        ))


def page_of(items: list) -> dict:
    return {
        "data": items,
        "meta": {
            "pagination": {
                "total": len(items),
                "count": len(items),
                "per_page": 30,
                "current_page": 1,
                "total_pages": 1 if items else 0,
                "links": {"previous": None, "next": None},
            }
        },
    }


class FakePlatform:
    def __init__(self):
        self.requested_urls: list[str] = []
        self._routes: list[tuple[re.Pattern, str, JsonReply | BaseException]] = []
        self._failing_call: tuple[int, JsonReply | BaseException] | None = None

    def route(self, path_pattern: str, outcome: JsonReply | BaseException, query_contains: str = "") -> None:
        self._routes.insert(0, (re.compile(path_pattern), query_contains, outcome))

    def fail_call(self, call_number: int, outcome: JsonReply | BaseException) -> None:
        self._failing_call = (call_number, outcome)

    def call_api(self, method, url, *args, **kwargs) -> RESTResponse:
        self.requested_urls.append(url)
        if self._failing_call and self._failing_call[0] == len(self.requested_urls):
            failure = self._failing_call[1]
            if isinstance(failure, BaseException):
                raise failure
            return failure.as_rest_response()
        parts = urlsplit(url)
        outcome = next(
            (
                outcome for pattern, query_contains, outcome in self._routes
                if pattern.search(parts.path) and query_contains in parts.query
            ),
            None,
        )
        if outcome is None:
            raise LookupError(f"no fake platform route for {parts.path}")
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome.as_rest_response()


@pytest.fixture
def fake_platform(monkeypatch) -> FakePlatform:
    platform = FakePlatform()
    api_client = SecureApiClient(Configuration(host="https://platform.example.com"))
    monkeypatch.setattr(api_client, "call_api", platform.call_api)
    monkeypatch.setattr(client_module, "_api_client", api_client)
    return platform
