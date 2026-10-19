"""Replay recorded Client API responses through the SDK calls the MCP server makes.

A response the SDK models reject fails here instead of in a customer's tool call.
Refresh the fixtures with test/record_client_api_responses.py.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import watchtowr_api_sdk.api as sdk_apis
from watchtowr_api_sdk.configuration import Configuration

from test.unit.conftest import JsonReply
from test.unit.test_sdk_compat import PAGINATION_META, _hunt_payload
from test.unit.test_sdk_surface import SDK_CALLS
from watchtowr_mcp_server.client import SecureApiClient, UnexpectedPlatformResponseError
from watchtowr_mcp_server.sdk_compat import apply_watchtowr_sdk_compat_patches

FIXTURES = sorted((Path(__file__).parent / "client_api_responses").glob("*.json"))
LIST_HUNTS = {"api": "HuntsApi", "method": "get_client_hunts", "kwargs": {}}


@pytest.fixture(scope="module", autouse=True)
def _patches_applied_as_the_server_applies_them():
    apply_watchtowr_sdk_compat_patches()


def replay(fixture: dict):
    api_client = SecureApiClient(Configuration(host="https://platform.example.com"))
    api_client.call_api = lambda *args, **kwargs: JsonReply(fixture["response"]).as_rest_response()
    api = getattr(sdk_apis, fixture["api"])(api_client)
    return getattr(api, fixture["method"])(**fixture["kwargs"])


@pytest.mark.parametrize("path", FIXTURES, ids=[path.stem for path in FIXTURES])
def test_sdk_accepts_the_recorded_response(path):
    assert replay(json.loads(path.read_text())) is not None


def test_every_fixture_names_the_sdk_call_that_returns_it():
    calls = {(cls, method) for _, cls, method in SDK_CALLS}
    for path in FIXTURES:
        fixture = json.loads(path.read_text())
        assert (fixture["api"], fixture["method"]) in calls, path.name
        assert path.stem == fixture["method"], path.name


def test_a_key_the_sdk_does_not_define_fails_the_replay():
    hunt = {**_hunt_payload("Misconfig"), "key_the_sdk_does_not_define": True}

    with pytest.raises(UnexpectedPlatformResponseError, match="key_the_sdk_does_not_define"):
        replay({**LIST_HUNTS, "response": {"data": [hunt], "meta": PAGINATION_META}})


def test_a_null_required_field_fails_the_replay():
    hunt = {**_hunt_payload("Misconfig"), "title": None}

    with pytest.raises(UnexpectedPlatformResponseError, match="title"):
        replay({**LIST_HUNTS, "response": {"data": [hunt], "meta": PAGINATION_META}})


def test_a_well_formed_response_passes_the_replay():
    hunts = replay({**LIST_HUNTS, "response": {"data": [_hunt_payload("Misconfig")], "meta": PAGINATION_META}})

    assert hunts.data[0].title == "Example hunt"
