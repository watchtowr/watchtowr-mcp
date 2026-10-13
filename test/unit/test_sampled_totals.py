from __future__ import annotations

from types import SimpleNamespace as NS

from watchtowr_api_sdk.api.certificates_api import CertificatesApi
from watchtowr_api_sdk.api.service_discovery_api import ServiceDiscoveryApi

import watchtowr_mcp_server.client as client_module
from watchtowr_mcp_server.tools.composite import _ASSET_API_MAP


def _page(items: list, total: int) -> NS:
    return NS(data=items, meta=NS(pagination=NS(total=total)))


def _serve_asset_lists(monkeypatch, total: int):
    monkeypatch.setattr(client_module, "_api_client", object())
    for _, api_cls, method_name in _ASSET_API_MAP:
        monkeypatch.setattr(
            api_cls, method_name,
            lambda *a, **k: _page([NS(name="example.com", ip="192.0.2.1", port=443, business_units=[])], total),
        )


def test_shadow_it_total_is_a_lower_bound_when_a_type_has_more_than_one_page(tools, monkeypatch):
    _serve_asset_lists(monkeypatch, total=45)

    out = tools["get_shadow_it_candidates"](days=7)

    assert f"Total Candidates: at least {len(_ASSET_API_MAP)} (only the first 30 new assets were checked for " in out


def test_shadow_it_total_is_exact_when_every_type_fits_in_one_page(tools, monkeypatch):
    _serve_asset_lists(monkeypatch, total=1)

    out = tools["get_shadow_it_candidates"](days=7)

    assert f"Total Candidates: {len(_ASSET_API_MAP)}\n" in out


def test_services_summary_says_it_counted_only_the_first_page(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    monkeypatch.setattr(
        ServiceDiscoveryApi, "get_list_service_listing",
        lambda *a, **k: _page([NS(service="https"), NS(service="ssh")], 120),
    )

    out = tools["get_internet_facing_services_summary"]()

    assert out.startswith("Internet-Facing Services Summary (first 2 of 120 services only):")


def test_expiring_certificates_say_how_many_services_were_matched(tools, monkeypatch):
    monkeypatch.setattr(client_module, "_api_client", object())
    certificate = NS(subject_common_name="example.com", issuer_organisation="", status="")
    monkeypatch.setattr(
        CertificatesApi, "get_list_certificates",
        lambda *a, **k: _page([NS(certificate=certificate, asset=None)], 1),
    )
    monkeypatch.setattr(
        ServiceDiscoveryApi, "get_list_service_listing",
        lambda *a, **k: _page([NS(hostname="other.example.net", ip="192.0.2.1")], 75),
    )

    out = tools["get_expiring_certificates_with_services"]()

    assert "(Checked the first 1 of 75 services only.)" in out
    assert "No matching services found for expiring cert hosts in the 1 services checked." in out
