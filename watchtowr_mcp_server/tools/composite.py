from datetime import datetime, timedelta

from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.api.hunts_api import HuntsApi
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
from watchtowr_api_sdk.api.points_of_interest_api import PointsOfInterestApi

from ..client import get_api_client, get_total, parse_date, format_bus, severity_display, supported_kwargs
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
    """Call a list method with page_size=1 and extract the total count."""
    method = getattr(api_instance, method_name)
    kwargs.pop("page_size", None)
    safe = supported_kwargs(method, kwargs)
    response = method(page_size=1, **safe)
    return get_total(response) or (len(response.data) if hasattr(response, 'data') and response.data else 0)


def register_composite_tools(mcp):

    @mcp.tool()
    def get_attack_surface_summary() -> str:
        """Get an overview of the entire attack surface with asset counts by type and finding counts by severity."""
        try:
            client = get_api_client()

            asset_counts = {}
            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    asset_counts[label] = _count(api_cls(client), method_name)
                except Exception:
                    asset_counts[label] = "error"

            findings_api = FindingsApi(client)
            finding_counts = {}
            for severity in SUMMARY_SEVERITIES:
                try:
                    finding_counts[severity] = _count(
                        findings_api, "get_list_findings", severities=severity
                    )
                except Exception:
                    finding_counts[severity] = "error"

            total_assets = sum(v for v in asset_counts.values() if isinstance(v, int))
            total_findings = sum(v for v in finding_counts.values() if isinstance(v, int))

            lines = [
                f"Attack Surface Summary",
                f"",
                f"Assets (Total: {total_assets}):",
            ]
            for label, count in asset_counts.items():
                lines.append(f"  • {label}: {count}")

            lines.append(f"\nFindings (Total: {total_findings}):")
            for severity, count in finding_counts.items():
                lines.append(f"  • {severity_display(severity)}: {count}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating attack surface summary: {e}"

    @mcp.tool()
    def get_new_assets_since(days: int = 7) -> str:
        """List all newly discovered assets across every type within a given number of days.

        Args:
            days: Number of days to look back (default 7).
        """
        try:
            client = get_api_client()
            since = datetime.now() - timedelta(days=days)

            lines = [f"New Assets Discovered (Last {days} Days):", ""]
            total_new = 0

            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    api = api_cls(client)
                    method = getattr(api, method_name)
                    response = method(**supported_kwargs(
                        method, {"created_from": since, "page_size": 30}
                    ))

                    count = get_total(response) or (
                        len(response.data) if hasattr(response, 'data') and response.data else 0
                    )

                    if count > 0:
                        total_new += count
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
                    lines.append(f"{label}: error fetching data")
                    lines.append("")

            if total_new == 0:
                return f"No new assets discovered in the last {days} days."

            lines.insert(0, f"Total New Assets: {total_new}\n")
            return "\n".join(lines)
        except Exception as e:
            return f"Error listing new assets: {e}"

    @mcp.tool()
    def get_attack_surface_delta(days: int = 7) -> str:
        """Get a combined view of new assets AND new findings discovered within a time window.

        Answers "what changed this week" in a single call.

        Args:
            days: Number of days to look back (default 7).
        """
        try:
            client = get_api_client()
            since = datetime.now() - timedelta(days=days)

            lines = [f"Attack Surface Delta (Last {days} Days)", ""]

            # New assets
            total_new_assets = 0
            asset_lines = []
            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    count = _count(api_cls(client), method_name, created_from=since)
                    if count > 0:
                        total_new_assets += count
                        asset_lines.append(f"  • {label}: +{count}")
                except Exception:
                    asset_lines.append(f"  • {label}: error")

            lines.append(f"New Assets ({total_new_assets}):")
            lines.extend(asset_lines)
            lines.append("")

            # New findings
            findings_api = FindingsApi(client)
            total_new_findings = 0
            findings_lines = []
            for severity in SUMMARY_SEVERITIES:
                try:
                    count = _count(
                        findings_api, "get_list_findings",
                        severities=severity, created_from=since,
                    )
                    if count > 0:
                        total_new_findings += count
                    findings_lines.append(f"  • {severity_display(severity)}: +{count}")
                except Exception:
                    findings_lines.append(f"  • {severity_display(severity)}: error")

            lines.append(f"New Findings ({total_new_findings}):")
            lines.extend(findings_lines)

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating attack surface delta: {e}"

    @mcp.tool()
    def get_business_unit_posture(business_unit_id: str) -> str:
        """Get a full security posture overview for a business unit: details, unresolved findings, asset counts, services, certificates, and points of interest.

        Args:
            business_unit_id: The business unit ID.
        """
        try:
            client = get_api_client()
            lines = []

            # BU details
            try:
                bu_api = BusinessUnitApi(client)
                bu_resp = bu_api.get_business_unit_details(id=int(business_unit_id))
                bu = bu_resp.data if hasattr(bu_resp, 'data') else bu_resp
                if bu:
                    lines.append(f"Business Unit: {getattr(bu, 'name', 'N/A')} (ID: {business_unit_id})")
                    desc = getattr(bu, 'description', '')
                    if desc:
                        lines.append(f"Description: {desc}")
            except Exception:
                lines.append(f"Business Unit ID: {business_unit_id}")
            lines.append("")

            # Unresolved findings by severity
            lines.append("Unresolved Findings:")
            findings_api = FindingsApi(client)
            total_findings = 0
            for severity in SUMMARY_SEVERITIES:
                try:
                    count = _count(
                        findings_api, "get_list_findings",
                        severities=severity,
                        business_unit_ids=business_unit_id,
                        statuses="confirmed",
                    )
                    total_findings += count
                    lines.append(f"  • {severity_display(severity)}: {count}")
                except Exception:
                    lines.append(f"  • {severity_display(severity)}: error")
            lines.append(f"  Total: {total_findings}")
            lines.append("")

            # Asset counts
            lines.append("Assets:")
            total_assets = 0
            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    count = _count(
                        api_cls(client), method_name,
                        business_unit_ids=business_unit_id,
                    )
                    total_assets += count
                    if count > 0:
                        lines.append(f"  • {label}: {count}")
                except Exception:
                    pass
            lines.append(f"  Total: {total_assets}")
            lines.append("")

            # Services
            try:
                svc_api = ServiceDiscoveryApi(client)
                svc_count = _count(
                    svc_api, "get_list_service_listing",
                    business_unit_ids=business_unit_id,
                )
                lines.append(f"Services: {svc_count}")
            except Exception:
                lines.append("Services: error")

            # Certificates
            try:
                cert_api = CertificatesApi(client)
                cert_count = _count(
                    cert_api, "get_list_certificates",
                    business_unit_ids=business_unit_id,
                )
                lines.append(f"Certificates: {cert_count}")
            except Exception:
                lines.append("Certificates: error")

            # Points of interest
            try:
                poi_api = PointsOfInterestApi(client)
                poi_count = _count(
                    poi_api, "get_list_points_of_interest",
                    business_unit_ids=business_unit_id,
                )
                lines.append(f"Points of Interest: {poi_count}")
            except Exception:
                lines.append("Points of Interest: error")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating business unit posture: {e}"

    @mcp.tool()
    def get_finding_with_asset_context(finding_id: int) -> str:
        """Get finding details enriched with the related asset's full details.

        Fetches the finding, identifies the associated asset type and ID, then
        fetches that asset's details for a complete triage view.

        Args:
            finding_id: The finding ID.
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            response = findings_api.get_finding_details(id=finding_id)

            f = response.data if hasattr(response, 'data') else response
            if not f:
                return f"Finding {finding_id} not found."

            lines = [
                f"Finding #{getattr(f, 'id', finding_id)}",
                f"Title: {getattr(f, 'title', 'N/A')}",
                f"Severity: {severity_display(getattr(f, 'severity', None))}",
                f"Status: {getattr(f, 'status', 'N/A')}",
                f"Created: {getattr(f, 'created_at', 'N/A')}",
            ]
            finding_impact = getattr(f, 'finding_impact', None)
            if finding_impact:
                lines.append(f"Finding Impact: {finding_impact}")

            description = getattr(f, 'description', '')
            if description:
                lines.append(f"\nDescription:\n{description}")

            recommendation = getattr(f, 'recommendation', '')
            if recommendation:
                lines.append(f"\nRecommendation:\n{recommendation}")

            # Try to extract asset context. ClientFinding exposes the related
            # asset under `affected` shaped as {"data": {type, name, id, ...}}.
            affected = getattr(f, 'affected', None)
            data = None
            if isinstance(affected, dict):
                data = affected.get('data')
            elif affected is not None:
                data = getattr(affected, 'data', None)

            if isinstance(data, dict) and (data.get('id') or data.get('name') or data.get('type')):
                lines.append("\n--- Associated Asset ---")
                asset_type = data.get('type', '')
                asset_name = data.get('name') or data.get('url') or data.get('iprange') or ''
                asset_id = data.get('id')
                lines.append(f"Asset Type: {asset_type}")
                lines.append(f"Asset Name: {asset_name}")
                lines.append(f"Asset ID: {asset_id}")

                if asset_id and asset_type:
                    try:
                        detail_lines = _fetch_asset_detail(client, asset_type, asset_id)
                        if detail_lines:
                            lines.extend(detail_lines)
                    except Exception:
                        pass

            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving finding with context: {e}"

    @mcp.tool()
    def get_expiring_certificates_with_services(days: int = 30) -> str:
        """List certificates expiring within N days, cross-referenced with exposed services on the same hosts.

        Args:
            days: Number of days to look ahead for expiring certificates (default 30).
        """
        try:
            client = get_api_client()
            cert_api = CertificatesApi(client)
            svc_api = ServiceDiscoveryApi(client)

            now = datetime.now()
            expiry_cutoff = now + timedelta(days=days)
            cert_response = cert_api.get_list_certificates(
                not_after_from=now,
                not_after_to=expiry_cutoff,
                page_size=30,
            )

            if not hasattr(cert_response, 'data') or not cert_response.data:
                return f"No certificates expiring within {days} days."

            cert_total = get_total(cert_response)
            lines = [f"Certificates Expiring Within {days} Days ({cert_total or len(cert_response.data)}):", ""]

            # Collect hostnames from certs for service cross-reference.
            # The list item is ServiceInformationResponse: cert fields are nested
            # under .certificate, the owning asset under .asset.
            cert_hosts = set()
            for item in cert_response.data:
                cert = getattr(item, 'certificate', None)
                asset = getattr(item, 'asset', None)
                cn = (getattr(cert, 'subject_common_name', '') if cert else '') or ''
                issuer = (getattr(cert, 'issuer_organisation', '') if cert else '') or ''
                asset_name = (getattr(asset, 'name', '') if asset else '') or ''
                bus = format_bus(getattr(asset, 'business_units', []) if asset else [])
                cert_status = (getattr(cert, 'status', '') if cert else '') or ''

                lines.append(f"• {cn or asset_name or 'Unknown'}")
                if cert_status:
                    lines.append(f"  Status: {cert_status}")
                if issuer:
                    lines.append(f"  Issuer: {issuer}")
                if asset_name:
                    lines.append(f"  Asset: {asset_name}")
                if bus:
                    lines.append(f"  {bus}")
                lines.append("")

                if cn:
                    cert_hosts.add(cn.lstrip("*."))
                if asset_name:
                    cert_hosts.add(asset_name.lstrip("*."))

            # Cross-reference with services
            if cert_hosts:
                lines.append("--- Related Services ---")
                try:
                    svc_response = svc_api.get_list_service_listing(page_size=30)
                    if hasattr(svc_response, 'data') and svc_response.data:
                        matched = []
                        for svc in svc_response.data:
                            svc_host = getattr(svc, 'hostname', '') or ''
                            svc_ip = getattr(svc, 'ip', '') or ''
                            haystack = f"{svc_host} {svc_ip}"
                            if any(h and h in haystack for h in cert_hosts):
                                service = getattr(svc, 'service', '') or ''
                                port = getattr(svc, 'port', '')
                                techs = getattr(svc, 'technologies', []) or []
                                tech_names = [
                                    getattr(t, 'display_name', getattr(t, 'name', '')) for t in techs
                                ]
                                tech_str = f" [{', '.join(tn for tn in tech_names if tn)}]" if tech_names else ""
                                label_host = svc_host or svc_ip
                                matched.append(f"• {label_host}:{port} ({service}){tech_str}")
                        if matched:
                            lines.extend(matched)
                        else:
                            lines.append("No matching services found for expiring cert hosts.")
                    else:
                        lines.append("No services data available.")
                except Exception:
                    lines.append("Error fetching services for cross-reference.")

            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving expiring certificates: {e}"

    @mcp.tool()
    def get_hunt_remediation_list(hunt_id: int, page_size: int = 30) -> str:
        """Get expanded finding details for a hunt, formatted for remediation handoff.

        Includes full finding details, severity breakdown, and remediation guidance per finding.

        Args:
            hunt_id: The hunt ID.
            page_size: Number of findings to include (max 30).
        """
        try:
            client = get_api_client()
            hunts_api = HuntsApi(client)
            findings_api = FindingsApi(client)

            # Hunt detail
            hunt_resp = hunts_api.show_the_detail_hunt(id=hunt_id)
            hunt = hunt_resp.data if hasattr(hunt_resp, 'data') else hunt_resp
            hunt_title = getattr(hunt, 'title', f'Hunt #{hunt_id}') if hunt else f'Hunt #{hunt_id}'
            hunt_status = getattr(hunt, 'status', 'N/A') if hunt else 'N/A'

            lines = [
                f"Remediation List: {hunt_title}",
                f"Status: {hunt_status}",
                "",
            ]

            # Findings for this hunt
            findings_resp = hunts_api.get_list_finding_by_hunt(
                id=hunt_id, page_size=min(page_size, 30)
            )

            if not hasattr(findings_resp, 'data') or not findings_resp.data:
                lines.append("No findings for this hunt.")
                return "\n".join(lines)

            total = get_total(findings_resp) or len(findings_resp.data)
            severity_counts = {}

            for idx, finding in enumerate(findings_resp.data, 1):
                fid = getattr(finding, 'id', '')
                title = getattr(finding, 'title', 'N/A')
                raw_severity = getattr(finding, 'severity', None)
                severity = severity_display(raw_severity) if raw_severity else 'N/A'
                status = getattr(finding, 'status', 'N/A')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

                lines.append(f"{idx}. [{severity}] {title}")
                lines.append(f"   ID: {fid} | Status: {status}")

                # Attempt to get full detail with remediation
                try:
                    detail_resp = findings_api.get_finding_details(id=fid)
                    fd = detail_resp.data if hasattr(detail_resp, 'data') else detail_resp
                    if fd:
                        recommendation = getattr(fd, 'recommendation', '')
                        affected = getattr(fd, 'affected', None)
                        data = None
                        if isinstance(affected, dict):
                            data = affected.get('data')
                        elif affected is not None:
                            data = getattr(affected, 'data', None)
                        if isinstance(data, dict):
                            asset_name = data.get('name') or data.get('url') or data.get('iprange') or ''
                            if asset_name:
                                lines.append(f"   Asset: {asset_name}")
                        if recommendation:
                            rem_preview = recommendation[:200].replace('\n', ' ')
                            lines.append(f"   Remediation: {rem_preview}")
                except Exception:
                    pass

                lines.append("")

            # Summary
            lines.append("--- Summary ---")
            lines.append(f"Total Findings: {total}")
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                if sev in severity_counts:
                    lines.append(f"  • {sev}: {severity_counts[sev]}")

            if total > len(findings_resp.data):
                lines.append(f"\nShowing {len(findings_resp.data)} of {total}. Use list_findings_by_hunt for pagination.")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating hunt remediation list: {e}"


    # ── Triage & Prioritization ─────────────────────────────────

    @mcp.tool()
    def get_critical_exposure_report() -> str:
        """Executive-level exposure summary: critical/high finding counts, CISA-KEV count, expiring certificates, and top recurring finding titles."""
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            cert_api = CertificatesApi(client)
            lines = ["Critical Exposure Report", ""]

            severity_counts = {}
            for severity in SUMMARY_SEVERITIES:
                try:
                    severity_counts[severity] = _count(findings_api, "get_list_findings", severities=severity)
                except Exception:
                    severity_counts[severity] = "error"
            lines.append("Findings by Severity:")
            for sev, count in severity_counts.items():
                lines.append(f"  • {severity_display(sev)}: {count}")
            lines.append("")

            try:
                kev_count = _count(findings_api, "get_list_findings", tags="CISA-KEV")
                lines.append(f"CISA-KEV Findings: {kev_count}")
            except Exception:
                lines.append("CISA-KEV Findings: error")

            try:
                expiry_cutoff = datetime.now() + timedelta(days=30)
                exp_count = _count(cert_api, "get_list_certificates", not_after_from=datetime.now(), not_after_to=expiry_cutoff)
                lines.append(f"Certificates Expiring (30 days): {exp_count}")
            except Exception:
                lines.append("Certificates Expiring (30 days): error")
            lines.append("")

            try:
                resp = findings_api.get_list_findings(severities="critical,high", page_size=30)
                if hasattr(resp, 'data') and resp.data:
                    title_counts = {}
                    for f in resp.data:
                        t = getattr(f, 'title', 'Unknown')
                        title_counts[t] = title_counts.get(t, 0) + 1
                    top = sorted(title_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                    lines.append("Top Recurring Critical/High Findings:")
                    for title, count in top:
                        lines.append(f"  • ({count}x) {title}")
            except Exception:
                lines.append("Top Recurring Findings: error")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating critical exposure report: {e}"

    @mcp.tool()
    def get_findings_by_asset(asset_type: str, asset_id: int) -> str:
        """Search findings associated with a specific asset by looking up the asset name first.

        Args:
            asset_type: Asset type (e.g. domain, ip, subdomain, port).
            asset_id: The asset ID.
        """
        try:
            client = get_api_client()

            detail_lines = _fetch_asset_detail(client, asset_type, asset_id)
            asset_name = None
            for line in detail_lines:
                if "Name:" in line or "Iprange:" in line or "Url:" in line or "Ip:" in line:
                    asset_name = line.split(":", 1)[1].strip()
                    break

            if not asset_name:
                return f"Could not resolve name for {asset_type} {asset_id}."

            findings_api = FindingsApi(client)
            resp = findings_api.get_list_findings(asset_title=asset_name, page_size=30)

            if not hasattr(resp, 'data') or not resp.data:
                return f"No findings found for {asset_type} '{asset_name}' (ID: {asset_id})."

            total = get_total(resp)
            lines = [f"Findings for {asset_type} '{asset_name}' (ID: {asset_id}):", ""]
            for f in resp.data:
                fid = getattr(f, 'id', '')
                sev = severity_display(getattr(f, 'severity', None))
                title = getattr(f, 'title', 'No title')
                status = getattr(f, 'status', 'Unknown')
                lines.append(f"• [ID:{fid}] [{sev}] {title} ({status})")

            if total and total > len(resp.data):
                lines.append(f"\nShowing {len(resp.data)} of {total}.")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving findings by asset: {e}"

    @mcp.tool()
    def get_stale_findings(days: int = 30, page_size: int = 30) -> str:
        """List findings that have been open/unresolved for more than N days.

        Args:
            days: Minimum age in days for a finding to be considered stale (default 30).
            page_size: Results per page (max 30).
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)
            cutoff = datetime.now() - timedelta(days=days)

            resp = findings_api.get_list_findings(
                statuses="confirmed",
                created_to=cutoff,
                page_size=min(page_size, 30),
            )

            if not hasattr(resp, 'data') or not resp.data:
                return f"No findings older than {days} days."

            total = get_total(resp)
            lines = [f"Stale Findings (Open > {days} Days):", ""]
            for f in resp.data:
                fid = getattr(f, 'id', '')
                sev = severity_display(getattr(f, 'severity', None))
                title = getattr(f, 'title', 'No title')
                status = getattr(f, 'status', 'Unknown')
                created = getattr(f, 'created_at', '')
                lines.append(f"• [ID:{fid}] [{sev}] {title} ({status}) - Created: {created}")

            if total:
                lines.insert(1, f"Total: {total}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving stale findings: {e}"

    @mcp.tool()
    def get_unassigned_critical_findings(page_size: int = 30) -> str:
        """List critical and high severity findings that have no assignee.

        Args:
            page_size: Results per page (max 30).
        """
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)

            lines = ["Unassigned Critical/High Findings:", ""]
            total_unassigned = 0

            for severity in SUMMARY_SEVERITIES[:2]:  # critical, high
                resp = findings_api.get_list_findings(
                    severities=severity,
                    statuses="confirmed",
                    assignee="No Assignee",
                    page_size=min(page_size, 30),
                )
                count = get_total(resp) or (len(resp.data) if hasattr(resp, 'data') and resp.data else 0)
                total_unassigned += count

                if hasattr(resp, 'data') and resp.data:
                    lines.append(f"{severity_display(severity)} ({count}):")
                    for f in resp.data:
                        fid = getattr(f, 'id', '')
                        title = getattr(f, 'title', 'No title')
                        status = getattr(f, 'status', 'Unknown')
                        lines.append(f"  • [ID:{fid}] {title} ({status})")
                    lines.append("")

            lines.insert(1, f"Total: {total_unassigned}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving unassigned findings: {e}"

    # ── Asset Intelligence ────────────────────────────────────────

    @mcp.tool()
    def get_asset_findings_count_by_type() -> str:
        """Get a count of unresolved findings broken down by asset type."""
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)

            asset_types = {
                "domain": "Domain",
                "subdomain": "Subdomain",
                "ip": "IP Address",
                "port": "Port",
                "ipRange": "IP Range",
                "cloudStorage": "Cloud Storage",
                "repository": "Repository",
                "container": "Container",
                "saasPlatform": "SaaS Platform",
                "mobileApp": "Mobile App"
            }

            lines = ["Unresolved Findings by Asset Type:", ""]
            total = 0
            for at, label in asset_types.items():
                try:
                    count = _count(
                        findings_api, "get_list_findings",
                        asset_types=at,
                        statuses="confirmed",
                    )
                    total += count
                    if count > 0:
                        lines.append(f"  • {label}: {count}")
                except Exception:
                    lines.append(f"  • {label}: error")

            lines.insert(1, f"Total: {total}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error counting findings by asset type: {e}"

    @mcp.tool()
    def get_shadow_it_candidates(days: int = 7) -> str:
        """List newly discovered assets that are not assigned to any business unit.

        Args:
            days: Number of days to look back (default 7).
        """
        try:
            client = get_api_client()
            since = datetime.now() - timedelta(days=days)

            lines = [f"Potential Shadow IT - New Assets Without Business Unit (Last {days} Days):", ""]
            total_candidates = 0

            for label, api_cls, method_name in _ASSET_API_MAP:
                try:
                    api = api_cls(client)
                    method = getattr(api, method_name)
                    response = method(**supported_kwargs(
                        method, {"created_from": since, "page_size": 30}
                    ))

                    if hasattr(response, 'data') and response.data:
                        no_bu = []
                        for a in response.data:
                            bus = getattr(a, 'business_units', None)
                            if not bus or (isinstance(bus, list) and len(bus) == 0):
                                name = getattr(a, 'name', None) or getattr(a, 'iprange', None) or getattr(a, 'url', 'Unknown')
                                no_bu.append(name)
                        if no_bu:
                            total_candidates += len(no_bu)
                            lines.append(f"{label} ({len(no_bu)}):")
                            for name in no_bu[:5]:
                                lines.append(f"  • {name}")
                            if len(no_bu) > 5:
                                lines.append(f"  ... and {len(no_bu) - 5} more")
                            lines.append("")
                except Exception:
                    pass

            if total_candidates == 0:
                return f"No unassigned new assets found in the last {days} days."

            lines.insert(1, f"Total Candidates: {total_candidates}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error finding shadow IT candidates: {e}"


def _fetch_asset_detail(client, asset_type: str, asset_id) -> list[str]:
    """Fetch detailed info for an asset given its type, returning formatted lines."""
    dispatch = {
        "ip": (IPAddressesApi, "get_asset_ip_details", ["name", "status", "country", "live", "source"]),
        "ip_address": (IPAddressesApi, "get_asset_ip_details", ["name", "status", "country", "live", "source"]),
        "domain": (DomainsApi, "get_asset_domain_details", ["name", "status", "live", "source"]),
        "subdomain": (SubdomainsApi, "get_asset_subdomain_details", ["name", "status", "live", "source"]),
        "port": (PortsApi, "get_asset_port_details", ["ip", "port", "service", "banner", "status"]),
        "ip_range": (IPRangesApi, "get_asset_iprange_details", ["iprange", "asn", "desc", "country", "status"]),
        "cloud_storage": (CloudStorageApi, "get_asset_cloud_storage_details", ["name", "platform", "url", "status"]),
        "repository": (RepositoriesApi, "get_asset_repository_details", ["name", "owner", "provider", "status"]),
        "container": (ContainersApi, "get_asset_container_details", ["name", "owner", "platform", "url", "status"]),
        "saas_platform": (SaaSPlatformsApi, "get_asset_saas_platform_details", ["url", "provider", "status"]),
        "mobile_app": (MobileApplicationsApi, "get_asset_mobile_app_details", ["name", "publisher", "platform", "url", "status"]),
    }

    
    def _normalize(t) -> str:
        return str(t).lower().replace(" ", "").replace("_", "")

    lookup = {_normalize(k): k for k in dispatch}
    key = lookup.get(_normalize(asset_type))
    if key is None:
        return [f"(Unknown asset type: {asset_type})"]

    lines = []
    api_cls, method_name, fields = dispatch[key]
    api = api_cls(client)
    method = getattr(api, method_name)

    kwargs = {"id": int(asset_id)}
    response = method(**kwargs)
    data = response.data if hasattr(response, 'data') else response

    if not data:
        return [f"(Asset {asset_id} not found)"]

    for field in fields:
        val = getattr(data, field, None)
        if val is not None and val != '':
            lines.append(f"  {field.replace('_', ' ').title()}: {val}")

    bus = format_bus(getattr(data, 'business_units', []))
    if bus:
        lines.append(f"  {bus}")

    return lines
