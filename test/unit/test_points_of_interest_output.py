from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace as NS

from watchtowr_api_sdk.api.points_of_interest_api import PointsOfInterestApi

import watchtowr_mcp_server.client as client_module
from test.unit.conftest import JsonReply, page_of


def _list_points_of_interest(tools, monkeypatch, **point):
    monkeypatch.setattr(client_module, "_api_client", object())
    response = NS(data=[NS(id=1, name="installer-page", **point)])
    monkeypatch.setattr(PointsOfInterestApi, "get_list_points_of_interest", lambda *a, **k: response)
    return tools["list_points_of_interest"]()


def test_each_point_of_interest_shows_its_discovery_date(tools, monkeypatch):
    discovered = datetime(2024, 4, 8, 15, 40, 26, tzinfo=timezone.utc)
    out = _list_points_of_interest(tools, monkeypatch, discovery_date=discovered)
    assert f"  Discovered: {discovered}" in out.splitlines()


def test_point_of_interest_without_a_discovery_date_has_no_discovered_line(tools, monkeypatch):
    out = _list_points_of_interest(tools, monkeypatch, discovery_date=None)
    assert "Discovered:" not in out


def _point_json(point_id: float) -> dict:
    return {
        "id": point_id, "name": "installer-page", "type": "file", "url": "https://example.com/setup.exe",
        "discoveryDate": "2024-04-08T15:40:26Z", "assetId": None, "assetName": None, "assetType": None,
        "businessUnits": [], "isConcerning": True, "suppressed": False,
    }


def test_header_counts_points_not_output_lines(tools, fake_platform):
    fake_platform.route(r"/points-of-interest/list$", JsonReply(page_of([_point_json(n) for n in (1.0, 2.0, 3.0)])))

    out = tools["list_points_of_interest"]()

    assert out.splitlines()[0] == "Points of Interest (3 of 3):"
