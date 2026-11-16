"""Findings on a port: the API puts the protocol (TCP/UDP) in `affected.data.type`."""
from __future__ import annotations

import pytest

from test.unit.conftest import JsonReply, finding_json, page_of, port_json

HOST = "https://tenant.example.io"
PORT_AFFECTED = {
    "type": "TCP", "status": "verified", "id": "9", "ip": "192.0.2.1", "ip_id": 4, "port": 443,
    "service": "https", "banner": "nginx", "state": "open", "businessUnits": [], "metadata": {},
}
# A port on a domain or subdomain: the API leaves out `ip` and `ip_id`.
DOMAIN_PORT_AFFECTED = {"type": "TCP", "status": "verified", "id": "9", "port": 443, "businessUnits": [], "metadata": {}}


@pytest.fixture(autouse=True)
def platform_host(monkeypatch):
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", HOST)


def test_finding_with_asset_context_shows_port_details(tools, fake_platform):
    fake_platform.route(r"/findings/show/5(\.0)?$", JsonReply({"data": finding_json(5, PORT_AFFECTED)}))
    fake_platform.route(r"/assets/ip/port/show/[^/]+$", JsonReply({"data": {**port_json(), "banner": "nginx"}}))

    out = tools["get_finding_with_asset_context"](finding_id=5)

    assert "Unknown asset type" not in out
    assert "Asset Type: port" in out
    assert "Asset Name: 192.0.2.1:443" in out
    assert f"{HOST}/assets/ip/4/ports" in out
    for line in ("Ip: 192.0.2.1", "Port: 443", "Service:", "Banner:"):
        assert line in out, out


def test_finding_list_shows_ip_and_port(tools, fake_platform):
    fake_platform.route(r"/findings/list$", JsonReply(page_of([finding_json(5, PORT_AFFECTED)])))

    out = tools["search_findings"]()

    assert "192.0.2.1:443 [port] (ID:9)" in out, out
    assert "[TCP]" not in out


def test_port_without_an_ip_is_still_a_port(tools, fake_platform):
    fake_platform.route(r"/findings/list$", JsonReply(page_of([finding_json(5, DOMAIN_PORT_AFFECTED)])))

    out = tools["search_findings"]()

    assert "Unknown:443 [port] (ID:9)" in out, out
    assert HOST + "/assets" not in out


def test_ip_id_alone_does_not_make_a_port(tools, fake_platform):
    affected = {"type": "domain", "id": "3", "name": "example.com", "ip_id": None}
    fake_platform.route(r"/findings/list$", JsonReply(page_of([finding_json(5, affected)])))

    out = tools["search_findings"]()

    assert "example.com [domain] (ID:3)" in out, out


def test_ip_id_without_a_port_number_is_still_a_port(tools, fake_platform):
    affected = {"type": "TCP", "status": "verified", "id": "9", "ip": "192.0.2.1", "ip_id": 4, "port": None}
    fake_platform.route(r"/findings/list$", JsonReply(page_of([finding_json(5, affected)])))

    out = tools["search_findings"]()

    assert "192.0.2.1 [port] (ID:9)" in out, out
    assert "[TCP]" not in out


def test_a_malformed_port_number_does_not_break_the_list(tools, fake_platform):
    affected = {**DOMAIN_PORT_AFFECTED, "port": "443/tcp"}
    fake_platform.route(r"/findings/list$", JsonReply(page_of([finding_json(5, affected), finding_json(6)])))

    out = tools["search_findings"]()

    assert "Unknown:443/tcp [port] (ID:9)" in out, out
    assert "example.com [domain] (ID:3)" in out
