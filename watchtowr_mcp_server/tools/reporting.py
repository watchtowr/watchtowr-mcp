from datetime import datetime, timedelta

from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.api.business_unit_api import BusinessUnitApi
from watchtowr_api_sdk.api.certificates_api import CertificatesApi
from watchtowr_api_sdk.api.service_discovery_api import ServiceDiscoveryApi
from watchtowr_api_sdk.api.ip_addresses_api import IPAddressesApi
from watchtowr_api_sdk.api.domains_api import DomainsApi
from watchtowr_api_sdk.api.subdomains_api import SubdomainsApi
from watchtowr_api_sdk.api.ports_api import PortsApi
from watchtowr_api_sdk.api.ip_ranges_api import IPRangesApi
from watchtowr_api_sdk.api.cloud_storage_api import CloudStorageApi
from watchtowr_api_sdk.api.repositories_api import RepositoriesApi
from watchtowr_api_sdk.api.containers_api import ContainersApi
from watchtowr_api_sdk.api.saa_s_platforms_api import SaaSPlatformsApi
from watchtowr_api_sdk.api.mobile_applications_api import MobileApplicationsApi
from watchtowr_api_sdk.api.security_posture_dashboard_api import SecurityPostureDashboardApi

from ..client import get_api_client, get_total, parse_date, severity_display, supported_kwargs
from ..constants import SUMMARY_SEVERITIES

_ASSET_API_MAP = [
    ("IP Addresses", IPAddressesApi, "get_list_asset_ips"),
    ("Domains", DomainsApi, "get_list_asset_domains"),
    ("Subdomains", SubdomainsApi, "get_list_asset_subdomains"),
    ("Ports", PortsApi, "get_list_asset_ports"),
    ("IP Ranges", IPRangesApi, "get_list_asset_ipranges"),
    ("Cloud Storage", CloudStorageApi, "get_list_asset_cloud_storages"),
    ("Repositories", RepositoriesApi, "get_list_asset_repositories"),
    ("Containers", ContainersApi, "get_list_asset_container"),
    ("SaaS Platforms", SaaSPlatformsApi, "get_list_asset_saas_platforms"),
    ("Mobile Apps", MobileApplicationsApi, "get_list_asset_mobile_apps"),
]


def _count(api_instance, method_name, **kwargs):
    method = getattr(api_instance, method_name)
    kwargs.pop("page_size", None)
    safe = supported_kwargs(method, kwargs)
    response = method(page_size=1, **safe)
    return get_total(response) or (len(response.data) if hasattr(response, 'data') and response.data else 0)


def register_reporting_tools(mcp):

    # ── Compliance & Audit ────────────────────────────────────────

    @mcp.tool()
    def get_asset_inventory_by_business_unit(business_unit_id: str) -> str:
        """Full asset inventory for a business unit with counts and sample assets per type.

        Args:
            business_unit_id: The business unit ID.
        """
        try:
            client = get_api_client()

            bu_name = business_unit_id
            try:
                bu_api = BusinessUnitApi(client)
                bu_resp = bu_api.get_business_unit_details(id=int(business_unit_id))
                bu = bu_resp.data if hasattr(bu_resp, 'data') else bu_resp
                if bu:
                    bu_name = getattr(bu, 'name', business_unit_id)
            except Exception:
                pass

            lines = [f"Asset Inventory: {bu_name} (BU ID: {business_unit_id})", ""]
            total_assets = 0

            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    api = api_cls(client)
                    method = getattr(api, method_name)
                    response = method(**supported_kwargs(
                        method, {"business_unit_ids": business_unit_id, "page_size": 5}
                    ))
                    count = get_total(response) or (len(response.data) if hasattr(response, 'data') and response.data else 0)

                    if count > 0:
                        total_assets += count
                        lines.append(f"{label} ({count}):")
                        if hasattr(response, 'data') and response.data:
                            for a in response.data:
                                name = getattr(a, 'name', None) or getattr(a, 'iprange', None) or getattr(a, 'url', 'Unknown')
                                status = getattr(a, 'status', '')
                                lines.append(f"  • {name} ({status})")
                            if count > 5:
                                lines.append(f"  ... and {count - 5} more")
                        lines.append("")
                except Exception:
                    lines.append(f"{label}: error")
                    lines.append("")

            lines.insert(1, f"Total Assets: {total_assets}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error generating asset inventory: {e}"

    @mcp.tool()
    def get_out_of_scope_assets() -> str:
        """List all assets marked as out of scope or incorrect identification across all types."""
        try:
            client = get_api_client()
            lines = ["Out of Scope / Excluded Assets:", ""]
            total = 0

            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    api = api_cls(client)
                    method = getattr(api, method_name)
                    response = method(**supported_kwargs(
                        method, {"statuses": "verifiedOutOfScope,incorrect identification", "page_size": 10}
                    ))
                    count = get_total(response) or (len(response.data) if hasattr(response, 'data') and response.data else 0)

                    if count > 0:
                        total += count
                        lines.append(f"{label} ({count}):")
                        if hasattr(response, 'data') and response.data:
                            for a in response.data[:5]:
                                name = getattr(a, 'name', None) or getattr(a, 'iprange', None) or getattr(a, 'url', 'Unknown')
                                status = getattr(a, 'status', '')
                                lines.append(f"  • {name} ({status})")
                            if count > 5:
                                lines.append(f"  ... and {count - 5} more")
                        lines.append("")
                except Exception:
                    pass

            if total == 0:
                return "No out-of-scope or excluded assets found."

            lines.insert(1, f"Total: {total}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving out of scope assets: {e}"

    @mcp.tool()
    def get_verified_vs_unverified_assets() -> str:
        """Breakdown of asset verification status across all types (verified vs unverified counts)."""
        try:
            client = get_api_client()
            lines = ["Asset Verification Status:", ""]

            total_verified = 0
            total_all = 0

            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    api = api_cls(client)
                    all_count = _count(api, method_name)
                    verified_count = _count(api, method_name, statuses="verified")

                    total_all += all_count
                    total_verified += verified_count

                    pct = f" ({verified_count * 100 // all_count}%)" if all_count > 0 else ""
                    lines.append(f"  • {label}: {verified_count}/{all_count} verified{pct}")
                except Exception:
                    lines.append(f"  • {label}: error")

            pct_total = f" ({total_verified * 100 // total_all}%)" if total_all > 0 else ""
            lines.insert(1, f"Overall: {total_verified}/{total_all} verified{pct_total}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error generating verification breakdown: {e}"

    @mcp.tool()
    def get_finding_age_distribution() -> str:
        """Bucket open findings by age (0-7d, 7-30d, 30-90d, 90d+) and severity."""
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            now = datetime.now()

            buckets = [
                ("0-7 days", now - timedelta(days=7), None),
                ("7-30 days", now - timedelta(days=30), now - timedelta(days=7)),
                ("30-90 days", now - timedelta(days=90), now - timedelta(days=30)),
                ("90+ days", None, now - timedelta(days=90)),
            ]

            lines = ["Finding Age Distribution (Open/Unresolved):", ""]

            for label, created_from, created_to in buckets:
                kwargs = {"statuses": "confirmed", "page_size": 1}
                if created_from and not created_to:
                    kwargs["created_from"] = created_from
                elif created_to and not created_from:
                    kwargs["created_to"] = created_to
                elif created_from and created_to:
                    kwargs["created_from"] = created_from
                    kwargs["created_to"] = created_to

                try:
                    count = _count(findings_api, "get_list_findings", **kwargs)
                except Exception:
                    count = "error"

                severity_breakdown = []
                for sev in SUMMARY_SEVERITIES:
                    try:
                        sev_count = _count(
                            findings_api, "get_list_findings", **{**kwargs, "severities": sev}
                        )
                        if sev_count > 0:
                            severity_breakdown.append(f"{sev[0].upper()}:{sev_count}")
                    except Exception:
                        pass

                sev_str = f" ({', '.join(severity_breakdown)})" if severity_breakdown else ""
                lines.append(f"  • {label}: {count}{sev_str}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating finding age distribution: {e}"

    @mcp.tool()
    def get_finding_status_timeline(days: int = 30) -> str:
        """Show how many findings were opened vs remediated per week over the last N days.

        Args:
            days: Number of days to look back (default 30).
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            now = datetime.now()

            lines = [f"Finding Status Timeline (Last {days} Days):", ""]
            weeks = max(1, days // 7)

            for w in range(weeks):
                week_end = now - timedelta(days=w * 7)
                week_start = now - timedelta(days=(w + 1) * 7)

                try:
                    new_count = _count(
                        findings_api, "get_list_findings",
                        created_from=week_start, created_to=week_end,
                    )
                except Exception:
                    new_count = "error"

                try:
                    remediated_count = _count(
                        findings_api, "get_list_findings",
                        statuses="remediated",
                        created_from=week_start, created_to=week_end,
                    )
                except Exception:
                    remediated_count = "error"

                week_label = week_start.strftime("%b %d") + " - " + week_end.strftime("%b %d")
                lines.append(f"  {week_label}: +{new_count} opened, {remediated_count} remediated")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating finding status timeline: {e}"

    # ── DevSecOps & Engineering ───────────────────────────────────

    @mcp.tool()
    def get_open_ports_summary(page_size: int = 30) -> str:
        """Summarize the most common open ports across the attack surface with counts.

        Args:
            page_size: Number of services to sample (max 30).
        """
        try:
            client = get_api_client()
            svc_api = ServiceDiscoveryApi(client)

            resp = svc_api.get_list_service_listing(page_size=min(page_size, 30))
            total = get_total(resp)

            if not hasattr(resp, 'data') or not resp.data:
                return "No services found."

            port_counts = {}
            for s in resp.data:
                port = getattr(s, 'port', 'unknown')
                service = getattr(s, 'service', '')
                key = f"{port}" + (f" ({service})" if service else "")
                port_counts[key] = port_counts.get(key, 0) + 1

            sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)

            lines = [f"Open Ports Summary (sampled from {total or len(resp.data)} services):", ""]
            for port, count in sorted_ports:
                lines.append(f"  • Port {port}: {count} services")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating open ports summary: {e}"

    @mcp.tool()
    def get_assets_without_findings() -> str:
        """List asset types that have assets but zero unresolved findings — potential coverage gaps."""
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)

            asset_types_map = {
                "domain": "Domains",
                "subdomain": "Subdomains",
                "ip_address": "IP Addresses",
                "port": "Ports",
                "ip_range": "IP Ranges",
                "cloud_storage": "Cloud Storage",
                "repository": "Repositories",
                "container": "Containers",
                "saas_platform": "SaaS Platforms",
                "mobile_app": "Mobile Apps",
            }

            lines = ["Assets Without Unresolved Findings:", ""]

            for at, label in asset_types_map.items():
                try:
                    total_findings = _count(
                        findings_api, "get_list_findings",
                        asset_types=at,
                        statuses="confirmed",
                    )

                    matching_asset_api = None
                    for api_label, api_cls, method_name in _ASSET_API_MAP:
                        if api_label == label:
                            matching_asset_api = (api_cls, method_name)
                            break

                    total_assets = 0
                    if matching_asset_api:
                        total_assets = _count(matching_asset_api[0](client), matching_asset_api[1])

                    if total_assets > 0 and total_findings == 0:
                        lines.append(f"  • {label}: {total_assets} assets, 0 findings")
                except Exception:
                    pass

            if len(lines) == 2:
                return "All asset types with assets also have findings."

            return "\n".join(lines)
        except Exception as e:
            return f"Error checking assets without findings: {e}"

    @mcp.tool()
    def get_certificate_health_report() -> str:
        """Certificates grouped by health: expired, expiring within 7 days, expiring within 30 days, and valid."""
        try:
            client = get_api_client()
            cert_api = CertificatesApi(client)
            now = datetime.now()

            total_certs = _count(cert_api, "get_list_certificates")

            try:
                expired = _count(cert_api, "get_list_certificates", not_after_to=now)
            except Exception:
                expired = "error"

            try:
                exp_7d = _count(cert_api, "get_list_certificates",
                                not_after_from=now, not_after_to=now + timedelta(days=7))
            except Exception:
                exp_7d = "error"

            try:
                exp_30d = _count(cert_api, "get_list_certificates",
                                 not_after_from=now + timedelta(days=7), not_after_to=now + timedelta(days=30))
            except Exception:
                exp_30d = "error"

            lines = [
                f"Certificate Health Report (Total: {total_certs})",
                "",
                f"  • Expired: {expired}",
                f"  • Expiring within 7 days: {exp_7d}",
                f"  • Expiring within 8-30 days: {exp_30d}",
            ]

            valid = total_certs
            for v in [expired, exp_7d, exp_30d]:
                if isinstance(v, int):
                    valid -= v
            if isinstance(valid, int) and valid >= 0:
                lines.append(f"  • Valid (30+ days): {valid}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating certificate health report: {e}"

    # ── Executive & Reporting ─────────────────────────────────────

    @mcp.tool()
    def get_executive_risk_scorecard() -> str:
        """Single-call executive risk dashboard: total assets, findings by severity, CISA-KEV, mean finding age, expiring certs, and newest finding."""
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            cert_api = CertificatesApi(client)

            lines = ["Executive Risk Scorecard", "=" * 30, ""]

            total_assets = 0
            for _, api_cls, method_name in _ASSET_API_MAP:
                try:
                    total_assets += _count(api_cls(client), method_name)
                except Exception:
                    pass
            lines.append(f"Total Assets: {total_assets}")

            lines.append("\nFindings:")
            total_findings = 0
            for sev in SUMMARY_SEVERITIES:
                try:
                    c = _count(findings_api, "get_list_findings", severities=sev, statuses="confirmed")
                    total_findings += c
                    lines.append(f"  • {severity_display(sev)}: {c}")
                except Exception:
                    lines.append(f"  • {severity_display(sev)}: error")
            lines.append(f"  Total Open: {total_findings}")

            try:
                kev = _count(findings_api, "get_list_findings", tags="CISA-KEV", statuses="confirmed")
                lines.append(f"\nCISA-KEV (Open): {kev}")
            except Exception:
                pass

            try:
                resp = findings_api.get_list_findings(statuses="confirmed", page_size=30)
                if hasattr(resp, 'data') and resp.data:
                    ages = []
                    for f in resp.data:
                        created = getattr(f, 'created_at', None)
                        if created:
                            try:
                                dt = parse_date(str(created))
                                if dt:
                                    age = (datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()) - dt
                                    ages.append(age.days)
                            except Exception:
                                pass
                    if ages:
                        avg_age = sum(ages) // len(ages)
                        max_age = max(ages)
                        lines.append(f"Mean Finding Age: {avg_age} days (oldest: {max_age} days)")
            except Exception:
                pass

            try:
                now = datetime.now()
                exp = _count(cert_api, "get_list_certificates",
                             not_after_from=now, not_after_to=now + timedelta(days=30))
                lines.append(f"Certificates Expiring (30d): {exp}")
            except Exception:
                pass

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating executive risk scorecard: {e}"

    @mcp.tool()
    def get_week_over_week_delta(weeks: int = 4) -> str:
        """Weekly trend report: new assets and new findings per week.

        Args:
            weeks: Number of weeks to include (default 4).
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            now = datetime.now()

            lines = [f"Week-over-Week Delta ({weeks} Weeks):", ""]

            for w in range(weeks):
                week_end = now - timedelta(days=w * 7)
                week_start = now - timedelta(days=(w + 1) * 7)
                label = week_start.strftime("%b %d") + " - " + week_end.strftime("%b %d")

                try:
                    new_findings = _count(
                        findings_api, "get_list_findings",
                        created_from=week_start, created_to=week_end,
                    )
                except Exception:
                    new_findings = "error"

                new_assets = 0
                for _, api_cls, method_name in _ASSET_API_MAP:
                    try:
                        new_assets += _count(api_cls(client), method_name, created_from=week_start, created_to=week_end)
                    except Exception:
                        pass

                lines.append(f"  {label}: +{new_assets} assets, +{new_findings} findings")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating week-over-week delta: {e}"

    @mcp.tool()
    def get_security_posture() -> str:
        """Get the security posture dashboard — overall score, coverage metrics, and trends.

        Returns a summary of monitored assets, active hunts, open findings by severity,
        and recent trends (new findings, resolved, mean time to resolve).
        """
        try:
            api = SecurityPostureDashboardApi(get_api_client())
            response = api.get_security_posture_dashboard()

            data = response.data if hasattr(response, "data") else response
            if not data:
                return "Security posture data not available."

            lines = ["Security Posture Dashboard:"]
            lines.append("")

            score = getattr(data, "score", None) or getattr(data, "overall_score", None)
            if score is not None:
                lines.append(f"Overall Score: {score}")
                lines.append("")

            lines.append("Coverage:")
            assets = getattr(data, "total_assets", None) or getattr(data, "assets_monitored", None)
            if assets is not None:
                lines.append(f"  Assets Monitored: {assets}")

            hunts = getattr(data, "active_hunts", None) or getattr(data, "total_hunts", None)
            if hunts is not None:
                lines.append(f"  Active Hunts: {hunts}")

            findings = getattr(data, "findings", None) or getattr(data, "open_findings", None)
            if findings is not None:
                if isinstance(findings, dict):
                    total_f = findings.get("total", 0)
                    critical = findings.get("critical", 0)
                    high = findings.get("high", 0)
                    lines.append(f"  Open Findings: {total_f} ({critical} Critical, {high} High)")
                else:
                    lines.append(f"  Open Findings: {findings}")

            trends = getattr(data, "trends", None)
            if trends:
                lines.append("")
                lines.append("Trends (30d):")
                new_f = getattr(trends, "new_findings", None)
                resolved = getattr(trends, "resolved", None)
                mttr = getattr(trends, "mean_time_to_resolve", None)
                if new_f is not None:
                    lines.append(f"  New Findings: {new_f}")
                if resolved is not None:
                    lines.append(f"  Resolved: {resolved}")
                if mttr is not None:
                    lines.append(f"  Mean Time to Resolve: {mttr}")

            # Fallback: if we matched nothing useful, dump all non-None attributes
            if len(lines) <= 3:
                lines.append("")
                for attr in dir(data):
                    if not attr.startswith("_") and attr not in (
                        "to_dict",
                        "to_str",
                        "attribute_map",
                        "model_fields",
                        "model_config",
                    ):
                        val = getattr(data, attr, None)
                        if val is not None and not callable(val):
                            lines.append(f"  {attr}: {val}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"

    @mcp.tool()
    def get_top_findings_by_occurrence(page_size: int = 30) -> str:
        """Most frequently occurring finding titles across the attack surface — reveals systemic issues.

        Args:
            page_size: Number of findings to sample (max 30).
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)

            resp = findings_api.get_list_findings(
                statuses="confirmed",
                page_size=min(page_size, 30),
            )

            if not hasattr(resp, 'data') or not resp.data:
                return "No open findings found."

            total = get_total(resp)
            title_data = {}
            for f in resp.data:
                title = getattr(f, 'title', 'Unknown')
                sev = severity_display(getattr(f, 'severity', None))
                if title not in title_data:
                    title_data[title] = {"count": 0, "severity": sev}
                title_data[title]["count"] += 1

            sorted_titles = sorted(title_data.items(), key=lambda x: x[1]["count"], reverse=True)

            lines = [f"Top Findings by Occurrence (sampled from {total or len(resp.data)} open findings):", ""]
            for title, data in sorted_titles[:15]:
                lines.append(f"  • ({data['count']}x) [{data['severity']}] {title}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating top findings: {e}"
