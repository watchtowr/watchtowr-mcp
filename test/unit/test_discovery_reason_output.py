from __future__ import annotations

import json
import re
import typing
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from fastmcp.exceptions import ToolError

from test.unit.conftest import JsonReply
from watchtowr_mcp_server.tools.assets.core import AssetType

ROUTE = r"/assets/[^/]+/show/[^/]+/discovery-reason$"

# The golden c01.externalRest response, as the recorded-response fixture holds it.
C01_EXTERNAL_REST = json.loads(
    (Path(__file__).parent / "client_api_responses" / "get_asset_discovery_reason.json").read_text()
)["response"]

# The golden c16.externalRest response: a reason that carries a platform.
C16_EXTERNAL_REST = {
    "technique": "container_registries",
    "sub_technique": "registry_keyword",
    "value": "acme",
    "technique_label": "Container Registry Search",
    "sub_technique_label": "Keyword",
    "icon_key": "container",
    "group": "Code and software supply chain",
    "value_kind": "text",
    "platform": "docker_hub",
    "platform_label": "Docker Hub",
    "module": "module-adversarysight-containers-dockerhub-discovery",
    "observed_at": "2026-11-18T10:00:00.123Z",
    "origin": "emitted",
    "evidence": None,
}

# externalAssetTypes in app-server's discoveryReason.contract.manifest.json: the 12 path segments of the
# endpoint. They include cloudAsset and exclude port.
EXTERNAL_ASSET_TYPES = [
    "domain", "subdomain", "ip", "ipRange", "repository", "container", "mobileApp", "cloudStorage",
    "cloudAsset", "saasPlatform", "packageManager", "apiDocumentation",
]


def test_asset_type_is_the_endpoint_path_segments():
    assert sorted(typing.get_args(AssetType)) == sorted(EXTERNAL_ASSET_TYPES)


@pytest.mark.parametrize("asset_type", EXTERNAL_ASSET_TYPES)
def test_the_asset_type_is_the_path_segment(asset_type, tools, fake_platform):
    fake_platform.route(ROUTE, JsonReply(C01_EXTERNAL_REST))

    tools["get_asset_discovery_reason"](asset_type=asset_type, asset_id=1)

    assert urlsplit(fake_platform.requested_urls[0]).path.endswith(f"/assets/{asset_type}/show/1/discovery-reason")


def test_prints_the_labels_and_fences_the_value(tools, fake_platform):
    fake_platform.route(ROUTE, JsonReply(C01_EXTERNAL_REST))

    out = tools["get_asset_discovery_reason"](asset_type="domain", asset_id=109)
    lines = out.splitlines()

    assert lines[0] == "Discovery reason for domain #109"
    assert re.fullmatch(
        r"Found via: Reverse WHOIS · Entity name · <(untrusted-data-[0-9a-f]+)>Acme Corp</\1>",
        lines[1],
    )
    assert "Module: module-adversarysight-reversewhois-entity-enumeration" in lines
    assert any(line.startswith("Reason recorded: 2026-11-18") for line in lines)
    assert "Origin: emitted" in lines
    assert "Evidence type: whois" in lines
    assert not any(line.startswith("Platform:") for line in lines)
    assert "First found" not in out
    assert "reverse_whois" not in out
    assert "registrant_org" not in out


def test_prints_the_platform_label_never_the_code(tools, fake_platform):
    fake_platform.route(ROUTE, JsonReply(C16_EXTERNAL_REST))

    out = tools["get_asset_discovery_reason"](asset_type="container", asset_id=7)

    assert "Platform: Docker Hub" in out.splitlines()
    assert "docker_hub" not in out
    assert "Evidence type" not in out


@pytest.mark.parametrize("override", [
    {"technique_label": None, "sub_technique_label": None},
    {"technique": "unknown", "sub_technique": None, "technique_label": None, "sub_technique_label": None},
])
def test_an_unknown_code_or_missing_label_falls_back_to_the_module(override, tools, fake_platform):
    fake_platform.route(ROUTE, JsonReply({**C01_EXTERNAL_REST, **override}))

    out = tools["get_asset_discovery_reason"](asset_type="domain", asset_id=109)

    assert out.splitlines()[1] == "Found via: Other · Module · module-adversarysight-reversewhois-entity-enumeration"
    assert "reverse_whois" not in out
    assert "unknown" not in out


def test_not_found_says_no_reason_is_available(tools, fake_platform):
    fake_platform.route(ROUTE, JsonReply({"statusCode": 404, "message": "Not Found"}, status=404))

    out = tools["get_asset_discovery_reason"](asset_type="ip", asset_id=5)

    assert out == "No discovery reason available for ip #5."


def test_a_platform_error_is_a_tool_error(tools, fake_platform):
    fake_platform.route(ROUTE, JsonReply({"statusCode": 500, "message": "Internal Server Error"}, status=500))

    with pytest.raises(ToolError, match="retrieving the asset discovery reason"):
        tools["get_asset_discovery_reason"](asset_type="ip", asset_id=5)


def test_portal_link_points_at_the_asset(tools, fake_platform, monkeypatch):
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", "https://tenant.example.com")
    fake_platform.route(ROUTE, JsonReply(C01_EXTERNAL_REST))

    out = tools["get_asset_discovery_reason"](asset_type="ipRange", asset_id=3)

    assert "Portal: https://tenant.example.com/assets/ip-range/3/overview" in out.splitlines()
