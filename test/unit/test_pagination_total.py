from __future__ import annotations

from types import SimpleNamespace

from watchtowr_api_sdk.models.meta import Meta

from watchtowr_mcp_server.client import get_total
from watchtowr_mcp_server.constants import SUMMARY_SEVERITIES
from watchtowr_mcp_server.tools import composite


def _paginated_response(total: int) -> SimpleNamespace:
    meta = Meta.from_dict({
        "pagination": {
            "total": total,
            "count": 1,
            "per_page": 1,
            "current_page": 1,
            "total_pages": total,
            "links": {"previous": None, "next": None},
        }
    })
    return SimpleNamespace(meta=meta, data=[object()])


def _list_api_returning(total: int):
    class ListApi:
        def __init__(self, client):
            pass

        def get_list(self, page_size=None, severities=None):
            return _paginated_response(total)

        get_list_findings = get_list

    return ListApi


def test_get_total_returns_the_pagination_total_as_an_int():
    total = get_total(_paginated_response(366))

    assert total == 366
    assert type(total) is int


def test_get_total_returns_none_when_the_response_has_no_pagination():
    assert get_total(SimpleNamespace(meta=None)) is None


def test_attack_surface_summary_adds_up_the_asset_and_finding_totals(tools, monkeypatch):
    monkeypatch.setattr(composite, "get_api_client", lambda: None)
    monkeypatch.setattr(composite, "_ASSET_API_MAP", [
        ("IP Addresses", _list_api_returning(78189), "get_list"),
        ("Domains", _list_api_returning(586), "get_list"),
    ])
    monkeypatch.setattr(composite, "FindingsApi", _list_api_returning(10))

    summary = tools["get_attack_surface_summary"]()

    assert "Assets (Total: 78775):" in summary
    assert "IP Addresses: 78189\n" in summary
    assert f"Findings (Total: {10 * len(SUMMARY_SEVERITIES)}):" in summary
