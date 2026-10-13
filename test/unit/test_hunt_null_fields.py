from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import urllib3
from watchtowr_api_sdk.api.domains_api import DomainsApi
from watchtowr_api_sdk.configuration import Configuration
from watchtowr_api_sdk.rest import RESTResponse

import watchtowr_mcp_server.client as client_module
from watchtowr_mcp_server.client import SecureApiClient
from test.unit.test_sdk_compat import PAGINATION_META, _hunt_detail_payload, _hunt_payload


@pytest.fixture
def platform_response_body(monkeypatch):
    body: dict = {}

    def return_canned_response(*args, **kwargs):
        return RESTResponse(urllib3.HTTPResponse(
            body=json.dumps(body).encode(),
            status=200,
            headers={"content-type": "application/json"},
            preload_content=True,
        ))

    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    configuration = Configuration()
    configuration.host = "https://offline.invalid"
    api_client = SecureApiClient(configuration)
    monkeypatch.setattr(api_client, "call_api", return_canned_response)
    monkeypatch.setattr(client_module, "_api_client", api_client)
    return body


def test_list_recent_hunts_returns_a_hunt_with_null_hunt_request_type(tools, platform_response_body):
    platform_response_body.update({
        "data": [{**_hunt_payload("Misconfig"), "id": 43}, _hunt_payload(None)],
        "meta": PAGINATION_META,
    })

    output = tools["list_recent_hunts"]()

    assert "[ID:42.0] Example hunt - completed (bespoke) " in output
    assert "[ID:43.0] Example hunt - completed (bespoke, Misconfig) " in output
    assert "None" not in output


def test_get_hunt_details_returns_a_hunt_with_null_hunt_request_type(tools, platform_response_body):
    platform_response_body.update({"data": _hunt_detail_payload(None)})

    output = tools["get_hunt_details"](hunt_id=42)

    assert output.startswith("Hunt #42.0\nTitle: Example hunt\n")
    assert "Request Type:" not in output
    assert "None" not in output


def test_engine_settings_update_keeps_a_null_setting_disabled(tools, monkeypatch):
    current = SimpleNamespace(
        adversary_sight_enabled=True, dns_bruteforcing_enabled=True, automated_red_teaming_enabled=False,
        intrusive_http_checks_enabled=None, credential_stuffing_enabled=False, rapid_reaction_enabled=True,
    )
    sent = []
    monkeypatch.setattr(client_module, "_api_client", object())
    monkeypatch.setattr(DomainsApi, "get_asset_domain_engine_settings", lambda *a, **k: SimpleNamespace(data=current))

    def update(self, id, update_client_engine_settings_dto):
        sent.append(update_client_engine_settings_dto)
        return SimpleNamespace(data=update_client_engine_settings_dto)

    monkeypatch.setattr(DomainsApi, "update_asset_domain_engine_settings", update)

    tools["manage_engine_settings"](asset_type="domain", asset_id=1, action="update", adversary_sight_enabled=False)

    assert sent[0].intrusive_http_checks_enabled is False
    assert sent[0].adversary_sight_enabled is False
    assert sent[0].rapid_reaction_enabled is True
