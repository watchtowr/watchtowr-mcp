from __future__ import annotations

import functools
from types import SimpleNamespace as NS
from urllib.parse import parse_qs, urlsplit

from watchtowr_api_sdk.api.certificates_api import CertificatesApi
from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.api.hunts_api import HuntsApi
from watchtowr_api_sdk.api.security_posture_dashboard_api import SecurityPostureDashboardApi
from watchtowr_api_sdk.api.service_discovery_api import ServiceDiscoveryApi
from watchtowr_api_sdk.models.security_posture_dashboard_dto import SecurityPostureDashboardDto

import watchtowr_mcp_server.client as client_module
from test.unit.conftest import JsonReply, page_of
from watchtowr_mcp_server.tools.composite import ASSET_TYPES


def _page(items: list, total: int | None = None) -> NS:
    return NS(data=items, meta=NS(pagination=NS(total=len(items) if total is None else total)))


def _serve(monkeypatch, api_cls, method_name: str, reply) -> list[dict]:
    """Replace an SDK method, keeping its signature so supported_kwargs sees the real parameters."""
    monkeypatch.setattr(client_module, "_api_client", object())
    calls = []
    original = getattr(api_cls, method_name)

    @functools.wraps(original)
    def fake(self, *args, **kwargs):
        calls.append(kwargs)
        return reply(kwargs) if callable(reply) else reply

    monkeypatch.setattr(api_cls, method_name, fake)
    return calls


def _finding(fid: int) -> NS:
    return NS(id=fid, severity="high", title=f"Finding {fid}", status="confirmed")


def test_cisa_kev_status_counts_remediated_findings(tools, monkeypatch):
    def findings(kwargs):
        if kwargs.get("statuses") == "remediated":
            return _page([], 3)
        if kwargs.get("statuses") in (None, "confirmed"):
            return _page([_finding(1)])
        return _page([])
    _serve(monkeypatch, FindingsApi, "get_list_findings", findings)

    out = tools["get_cisa_kev_remediation_status"]()

    assert "CISA-KEV Remediation Status (4 findings):" in out
    assert "  • remediated: 3" in out
    assert "[ID:1] [High] Finding 1" in out


def test_cisa_kev_open_findings_say_when_only_the_first_page_is_listed(tools, monkeypatch):
    _serve(monkeypatch, FindingsApi, "get_list_findings", lambda kwargs: _page([_finding(1)], 45))

    out = tools["get_cisa_kev_remediation_status"]()

    assert "Open (confirmed) (first 1 of 45):" in out


def test_recent_remediations_filter_by_last_update_and_say_so(tools, monkeypatch):
    calls = _serve(monkeypatch, FindingsApi, "get_list_findings", _page([_finding(1)]))

    out = tools["get_recent_remediations"](days=7)

    assert "updated_from" in calls[0] and "created_from" not in calls[0]
    assert "placed by their last update" in out


def test_status_timeline_counts_remediations_by_last_update(tools, monkeypatch):
    calls = _serve(monkeypatch, FindingsApi, "get_list_findings", _page([], 2))

    out = tools["get_finding_status_timeline"](days=7)

    remediated_calls = [c for c in calls if c.get("statuses") == "remediated"]
    assert remediated_calls and all("updated_from" in c and "created_from" not in c for c in remediated_calls)
    assert "placed by their last update" in out


def test_attack_surface_summary_includes_cloud_assets_api_docs_and_package_managers(tools, monkeypatch):
    for asset_type in ASSET_TYPES:
        _serve(monkeypatch, asset_type.list_api, asset_type.list_method, _page([], 1))
    _serve(monkeypatch, FindingsApi, "get_list_findings", _page([], 0))

    out = tools["get_attack_surface_summary"]()

    assert f"Assets (Total: {len(ASSET_TYPES)}):" in out
    for label in ("Cloud Assets", "API Documentation", "Package Managers"):
        assert f"  • {label}: 1" in out


def test_findings_count_by_type_counts_port_findings_once(tools, monkeypatch):
    # The Client API adds port findings to every query for ip findings.
    per_type = {"ip": 5, "port": 2}
    _serve(
        monkeypatch, FindingsApi, "get_list_findings",
        lambda kwargs: _page([], per_type.get(kwargs.get("asset_types"), 0)),
    )

    out = tools["get_asset_findings_count_by_type"]()

    assert "  • IP Addresses: 3" in out
    assert "  • Ports: 2" in out
    assert "Total: 5\n" in out


def _expiring_certificate(common_name: str) -> NS:
    certificate = NS(subject_common_name=common_name, issuer_organisation="", status="")
    return NS(certificate=certificate, asset=None)


def test_expiring_certificates_match_service_hosts_exactly(tools, monkeypatch):
    _serve(monkeypatch, CertificatesApi, "get_list_certificates", _page([_expiring_certificate("example.com")]))
    _serve(monkeypatch, ServiceDiscoveryApi, "get_list_service_listing", _page([
        NS(hostname="notexample.com", ip="192.0.2.1", port=443, service="https", technologies=[]),
        NS(hostname="example.com", ip="192.0.2.2", port=8443, service="https", technologies=[]),
    ]))

    out = tools["get_expiring_certificates_with_services"]()

    assert "• example.com:8443 (" in out
    assert "notexample.com" not in out


def test_wildcard_certificate_matches_one_subdomain_level_only(tools, monkeypatch):
    _serve(monkeypatch, CertificatesApi, "get_list_certificates", _page([_expiring_certificate("*.example.com")]))
    _serve(monkeypatch, ServiceDiscoveryApi, "get_list_service_listing", _page([
        NS(hostname="www.example.com", ip="192.0.2.1", port=443, service="https", technologies=[]),
        NS(hostname="a.b.example.com", ip="192.0.2.2", port=443, service="https", technologies=[]),
        NS(hostname="example.com", ip="192.0.2.3", port=443, service="https", technologies=[]),
    ]))

    out = tools["get_expiring_certificates_with_services"]()

    assert "• www.example.com:443 (" in out
    assert "a.b.example.com:443" not in out
    assert "• example.com:443" not in out


def test_hunt_impact_summary_says_its_severities_come_from_the_first_page(tools, monkeypatch):
    _serve(monkeypatch, HuntsApi, "show_the_detail_hunt", NS(data=NS(
        title="Example hunt", status="completed", total_findings=120, total_assets=50, hypothesis=None,
    )))
    _serve(monkeypatch, HuntsApi, "get_list_finding_by_hunt", _page([NS(severity="critical")] * 30, 120))
    _serve(monkeypatch, HuntsApi, "get_list_asset_by_hunt", _page([NS(name="example.com", type="domain")] * 30, 50))

    out = tools["get_hunt_impact_summary"](hunt_id=1)

    assert "Findings by Severity (first 30 of 120 findings):" in out
    assert "... and 40 more" in out


def test_findings_needing_assignment_counts_the_rest_from_the_rows_shown(tools, monkeypatch):
    _serve(monkeypatch, FindingsApi, "get_list_findings", _page([_finding(i) for i in range(5)], 20))

    out = tools["get_findings_needing_assignment"](page_size=5)

    assert "  ... and 15 more" in out.splitlines()


def test_verified_count_uses_the_platforms_verified_set(tools, fake_platform):
    fake_platform.route(r".", JsonReply(page_of([])))

    tools["get_verified_vs_unverified_assets"]()

    verified_filters = {
        tuple(query["statuses"])
        for query in (parse_qs(urlsplit(url).query) for url in fake_platform.requested_urls)
        if "statuses" in query
    }
    assert verified_filters == {("verified", "VerifiedReducedAttack", "Tracked")}


def test_security_posture_prints_the_dashboard_fields(tools, monkeypatch):
    monkeypatch.setenv("WATCHTOWR_PLATFORM_HOST", "https://tenant.example.io")
    dashboard = SecurityPostureDashboardDto.from_dict({
        "requiredActions": {"activelyExploitedFindings": 4, "unresolvedRapidReactionHunts": 2},
        "huntOverview": {"totalHuntsExecuted": 9, "totalUnresolvedHunts": 2, "latestExecutedHunts": [{
            "id": "42", "title": "Example hunt", "status": "completed", "totalFindings": 3, "totalAssets": 2,
            "needInvestigation": False, "requestType": "Misconfig", "resolvedStatus": False,
            "acknowledgement": {"isAcknowledged": False, "numberOfSeen": 0}, "threatActors": [],
        }]},
        "attackSurfaceResiliency": {
            "concerningServices": 7, "concerningPointsOfInterest": 1, "validCredentials": 0, "openFindings": 33,
        },
        "organizationSummary": {
            "attackSurface": {
                "totalVerifiedAssets": 120, "totalPointsOfInterest": 5,
                "totalNetworkServices": 80, "totalCertificates": 40,
            },
            "openFindings": {"critical": 1, "high": 2, "medium": 10, "low": 15, "info": 5, "total": 33},
            "mttrMetrics": {"mttr": 36.5, "mttrae": 12},
            "findingsSummary": {
                "totalResolvedFindings": 200, "oldCriticalHighFindings": 1, "unacknowledgedCriticalHighFindings": 0,
            },
        },
    })
    _serve(monkeypatch, SecurityPostureDashboardApi, "get_security_posture_dashboard", NS(data=dashboard))

    out = tools["get_security_posture"]()

    assert "Actively Exploited Findings: 4" in out
    assert "Verified Assets: 120" in out
    assert "Open Findings: 33 (1 Critical, 2 High, 10 Medium, 15 Low, 5 Info)" in out
    assert "Mean Time To Remediate: 36.5 hours" in out
    assert "Executed: 9" in out
    assert "[ID:42] Example hunt - completed [3 findings, 2 assets] — https://tenant.example.io/hunts/42/overview" in out
    assert "model_fields" not in out


def test_country_search_says_it_found_no_services_not_no_assets(tools, monkeypatch):
    _serve(monkeypatch, ServiceDiscoveryApi, "get_list_service_listing", _page([]))

    out = tools["search_assets_by_country"](country_code="us")

    assert out == "No services found in country US."
