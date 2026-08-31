from watchtowr_api_sdk.api.findings_api import FindingsApi
from watchtowr_api_sdk.api.service_discovery_api import ServiceDiscoveryApi
from watchtowr_api_sdk.api.ip_addresses_api import IPAddressesApi
from watchtowr_api_sdk.api.domains_api import DomainsApi
from watchtowr_api_sdk.api.subdomains_api import SubdomainsApi

from ..client import get_api_client, get_total, severity_display


def register_incident_tools(mcp):

    @mcp.tool()
    def search_assets_by_country(country_code: str, page_size: int = 30) -> str:
        """Find services located in a specific country.

        Args:
            country_code: Two-letter country code (e.g. "US", "CN", "RU").
            page_size: Results per page (max 30).
        """
        try:
            client = get_api_client()
            lines = [f"Assets in Country: {country_code.upper()}", ""]

            svc_api = ServiceDiscoveryApi(client)
            svc_resp = svc_api.get_list_service_listing(countries=country_code.upper(), page_size=min(page_size, 30))
            svc_total = get_total(svc_resp) or (len(svc_resp.data) if hasattr(svc_resp, 'data') and svc_resp.data else 0)

            if hasattr(svc_resp, 'data') and svc_resp.data:
                lines.append(f"Services ({svc_total}):")
                for s in svc_resp.data:
                    ip = getattr(s, 'ip', None) or getattr(s, 'hostname', None) or 'Unknown'
                    port = getattr(s, 'port', '?')
                    service = getattr(s, 'service', '')
                    svc_str = f" ({service})" if service else ""
                    lines.append(f"  • {ip}:{port}{svc_str}")
                if svc_total > len(svc_resp.data):
                    lines.append(f"  ... and {svc_total - len(svc_resp.data)} more")

            if svc_total == 0:
                return f"No assets found in country {country_code.upper()}."

            return "\n".join(lines)
        except Exception as e:
            return f"Error searching assets by country: {e}"

    @mcp.tool()
    def get_internet_facing_services_summary() -> str:
        """Aggregate view of exposed services grouped by service type with counts."""
        try:
            client = get_api_client()
            svc_api = ServiceDiscoveryApi(client)

            resp = svc_api.get_list_service_listing(page_size=30)
            total = get_total(resp)

            if not hasattr(resp, 'data') or not resp.data:
                return "No services found."

            service_counts = {}
            for s in resp.data:
                service = getattr(s, 'service', 'unknown') or 'unknown'
                service_counts[service] = service_counts.get(service, 0) + 1

            sorted_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)

            lines = [f"Internet-Facing Services Summary (from {total or len(resp.data)} total):", ""]
            for svc, count in sorted_services:
                lines.append(f"  • {svc}: {count}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error generating services summary: {e}"

    @mcp.tool()
    def get_assets_by_technology(technology_search: str, page_size: int = 30) -> str:
        """Find all services running a specific technology (e.g. Apache, nginx, Exchange).

        Args:
            technology_search: Technology name to search for.
            page_size: Results per page (max 30).
        """
        try:
            client = get_api_client()
            svc_api = ServiceDiscoveryApi(client)

            resp = svc_api.get_list_service_listing(technology=technology_search, page_size=min(page_size, 30))
            total = get_total(resp)

            if not hasattr(resp, 'data') or not resp.data:
                return f"No services found matching technology '{technology_search}'."

            lines = [f"Services Running '{technology_search}' ({total or len(resp.data)} total):", ""]
            for s in resp.data:
                ip = getattr(s, 'ip', None) or getattr(s, 'hostname', None) or 'Unknown'
                port = getattr(s, 'port', '?')
                service = getattr(s, 'service', '')
                country = getattr(s, 'country', '')
                techs = getattr(s, 'technologies', [])
                tech_names = [getattr(t, 'display_name', getattr(t, 'name', '')) for t in techs] if techs else []
                tech_str = f" [{', '.join(tech_names)}]" if tech_names else ""
                svc_str = f" ({service})" if service else ""
                country_str = f" [{country}]" if country else ""
                lines.append(f"  • {ip}:{port}{svc_str}{tech_str}{country_str}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error searching by technology: {e}"

    @mcp.tool()
    def get_cisa_kev_remediation_status() -> str:
        """CISA-KEV tagged findings grouped by status to show KEV compliance posture."""
        try:
            client = get_api_client()
            findings_api = FindingsApi(client)

            resp = findings_api.get_list_findings(tags="CISA-KEV", page_size=30)
            total = get_total(resp)

            if not hasattr(resp, 'data') or not resp.data:
                return "No CISA-KEV findings found."

            status_groups = {}
            for f in resp.data:
                status = getattr(f, 'status', 'Unknown')
                if status not in status_groups:
                    status_groups[status] = []
                sev = severity_display(getattr(f, 'severity', None))
                title = getattr(f, 'title', 'No title')
                fid = getattr(f, 'id', '')
                status_groups[status].append(f"[ID:{fid}] [{sev}] {title}")

            lines = [f"CISA-KEV Remediation Status ({total or len(resp.data)} findings):", ""]

            # Display in canonical status order (API statuses are lowercase).
            for status in ["unconfirmed", "confirmed", "remediated",
                           "risk-accepted", "closed", "asset-no-longer-tracked"]:
                findings = status_groups.pop(status, [])
                if not findings:
                    continue
                lines.append(f"{status} ({len(findings)}):")
                for f in findings:
                    lines.append(f"  • {f}")
                lines.append("")

            for status, findings in status_groups.items():
                lines.append(f"{status} ({len(findings)}):")
                for f in findings:
                    lines.append(f"  • {f}")
                lines.append("")

            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving CISA-KEV status: {e}"

    @mcp.tool()
    def find_related_assets(asset_id: int, asset_type: str) -> str:
        """Find assets related to a given asset — subdomains under a domain, ports on an IP, etc.

        Args:
            asset_id: The asset ID to find relations for.
            asset_type: The asset type (domain, ip, subdomain).
        """
        try:
            client = get_api_client()
            asset_type_lower = asset_type.lower().replace(" ", "_")
            lines = [f"Related Assets for {asset_type} ID {asset_id}:", ""]

            if asset_type_lower in ("domain",):
                try:
                    domain_api = DomainsApi(client)
                    domain_resp = domain_api.get_asset_domain_details(id=asset_id)
                    domain = domain_resp.data if hasattr(domain_resp, 'data') else domain_resp
                    domain_name = getattr(domain, 'name', '') if domain else ''

                    if domain_name:
                        lines.append(f"Domain: {domain_name}")
                        lines.append("")

                        sub_api = SubdomainsApi(client)
                        sub_resp = sub_api.get_list_asset_subdomains(asset_name=domain_name, page_size=30)
                        sub_total = get_total(sub_resp) or (len(sub_resp.data) if hasattr(sub_resp, 'data') and sub_resp.data else 0)
                        if hasattr(sub_resp, 'data') and sub_resp.data:
                            lines.append(f"Subdomains ({sub_total}):")
                            for s in sub_resp.data[:10]:
                                lines.append(f"  • {getattr(s, 'name', 'Unknown')} ({getattr(s, 'status', '')})")
                            if sub_total > 10:
                                lines.append(f"  ... and {sub_total - 10} more")
                except Exception as e:
                    lines.append(f"Error fetching domain relations: {e}")

            elif asset_type_lower in ("ip", "ip_address"):
                try:
                    ip_api = IPAddressesApi(client)
                    ip_resp = ip_api.get_asset_ip_details(id=asset_id)
                    ip = ip_resp.data if hasattr(ip_resp, 'data') else ip_resp
                    ip_name = getattr(ip, 'name', '') if ip else ''

                    if ip_name:
                        lines.append(f"IP Address: {ip_name}")
                        lines.append("")

                        port_resp = ip_api.get_asset_ip_ports(id=asset_id, page_size=30)
                        port_total = get_total(port_resp) or (len(port_resp.data) if hasattr(port_resp, 'data') and port_resp.data else 0)
                        if hasattr(port_resp, 'data') and port_resp.data:
                            lines.append(f"Ports ({port_total}):")
                            for p in port_resp.data[:15]:
                                port_num = getattr(p, 'port', '?')
                                service = getattr(p, 'service', '')
                                svc_str = f" ({service})" if service else ""
                                lines.append(f"  • :{port_num}{svc_str}")
                            if port_total > 15:
                                lines.append(f"  ... and {port_total - 15} more")
                        lines.append("")

                    svc_api = ServiceDiscoveryApi(client)
                    svc_resp = svc_api.get_list_service_listing(search=ip_name, page_size=10)
                    if hasattr(svc_resp, 'data') and svc_resp.data:
                        lines.append(f"Services on {ip_name}:")
                        for s in svc_resp.data:
                            port = getattr(s, 'port', '?')
                            service = getattr(s, 'service', '')
                            techs = getattr(s, 'technologies', [])
                            tech_names = [getattr(t, 'display_name', getattr(t, 'name', '')) for t in techs] if techs else []
                            tech_str = f" [{', '.join(tech_names)}]" if tech_names else ""
                            lines.append(f"  • :{port} ({service}){tech_str}")

                    findings_api = FindingsApi(client)
                    f_resp = findings_api.get_list_findings(asset_title=ip_name, page_size=10)
                    f_total = get_total(f_resp) or (len(f_resp.data) if hasattr(f_resp, 'data') and f_resp.data else 0)
                    if hasattr(f_resp, 'data') and f_resp.data:
                        lines.append(f"\nFindings ({f_total}):")
                        for f in f_resp.data:
                            fid = getattr(f, 'id', '')
                            sev = severity_display(getattr(f, 'severity', None))
                            title = getattr(f, 'title', 'No title')
                            lines.append(f"  • [ID:{fid}] [{sev}] {title}")
                except Exception as e:
                    lines.append(f"Error fetching IP relations: {e}")

            elif asset_type_lower in ("subdomain",):
                try:
                    sub_api = SubdomainsApi(client)
                    sub_resp = sub_api.get_asset_subdomain_details(id=asset_id)
                    sub = sub_resp.data if hasattr(sub_resp, 'data') else sub_resp
                    sub_name = getattr(sub, 'name', '') if sub else ''

                    if sub_name:
                        lines.append(f"Subdomain: {sub_name}")
                        lines.append("")

                        findings_api = FindingsApi(client)
                        f_resp = findings_api.get_list_findings(asset_title=sub_name, page_size=10)
                        f_total = get_total(f_resp) or (len(f_resp.data) if hasattr(f_resp, 'data') and f_resp.data else 0)
                        if hasattr(f_resp, 'data') and f_resp.data:
                            lines.append(f"Findings ({f_total}):")
                            for f in f_resp.data:
                                fid = getattr(f, 'id', '')
                                sev = severity_display(getattr(f, 'severity', None))
                                title = getattr(f, 'title', 'No title')
                                lines.append(f"  • [ID:{fid}] [{sev}] {title}")

                        svc_api = ServiceDiscoveryApi(client)
                        svc_resp = svc_api.get_list_service_listing(search=sub_name, page_size=10)
                        if hasattr(svc_resp, 'data') and svc_resp.data:
                            lines.append(f"\nServices:")
                            for s in svc_resp.data:
                                ip = getattr(s, 'ip', None) or getattr(s, 'hostname', None) or 'Unknown'
                                port = getattr(s, 'port', '?')
                                service = getattr(s, 'service', '')
                                lines.append(f"  • {ip}:{port} ({service})")
                except Exception as e:
                    lines.append(f"Error fetching subdomain relations: {e}")
            else:
                return f"Related asset lookup is supported for: domain, ip, subdomain. Got: {asset_type}"

            return "\n".join(lines)
        except Exception as e:
            return f"Error finding related assets: {e}"
