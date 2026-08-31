from datetime import datetime, timedelta

from watchtowr_api_sdk.api.suspicious_domains_api import SuspiciousDomainsApi
from watchtowr_api_sdk.api.points_of_interest_api import PointsOfInterestApi
from watchtowr_api_sdk.api.certificates_api import CertificatesApi
from watchtowr_api_sdk.api.pending_domains_api import PendingDomainsApi

from ..client import get_api_client, get_total, parse_date, format_bus


def register_threat_intel_tools(mcp):

    # ── Suspicious Domains ────────────────────────────────────────

    @mcp.tool()
    def list_suspicious_domains(
        search: str = None,
        discovery_reason: str = None,
        whois_search: str = None,
        statuses: str = None,
        created_from: str = None,
        created_to: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List domains flagged as suspicious (typosquatting, lookalikes, brand impersonation).

        Args:
            search: Search by domain name.
            discovery_reason: Filter by discovery reason.
            whois_search: Search within WHOIS data.
            statuses: Comma-separated status filters.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = SuspiciousDomainsApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search
            if discovery_reason:
                kwargs["discovery_reason"] = discovery_reason
            if whois_search:
                kwargs["whois_search"] = whois_search
            if statuses:
                kwargs["statuses"] = [s.strip() for s in statuses.split(",") if s.strip()]
            if created_from:
                kwargs["created_from"] = parse_date(created_from)
            if created_to:
                kwargs["created_to"] = parse_date(created_to)

            response = api.get_list_suspicious_domain(**kwargs)

            if not hasattr(response, 'data') or not response.data:
                return "No suspicious domains found."

            total = get_total(response)
            lines = []
            for d in response.data:
                did = getattr(d, 'id', '')
                name = getattr(d, 'name', 'Unknown')
                reason = getattr(d, 'discovery_reason', '')
                status = getattr(d, 'status', 'Unknown')
                reason_str = f" ({reason})" if reason else ""
                lines.append(f"• [ID:{did}] {name} - {status}{reason_str}")

            header = f"Suspicious Domains ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing suspicious domains: {e}"

    @mcp.tool()
    def get_suspicious_domain_details(domain_id: int) -> str:
        """Get full details for a suspicious domain including WHOIS data.

        Args:
            domain_id: The suspicious domain ID.
        """
        try:
            api = SuspiciousDomainsApi(get_api_client())
            response = api.get_suspicious_domain_details(id=domain_id)

            d = response.data if hasattr(response, 'data') else response
            if not d:
                return f"Suspicious domain {domain_id} not found."

            lines = [
                f"Suspicious Domain #{getattr(d, 'id', domain_id)}",
                f"Name: {getattr(d, 'name', 'N/A')}",
                f"Discovery Reason: {getattr(d, 'discovery_reason', 'N/A')}",
                f"Status: {getattr(d, 'status', 'N/A')}",
                f"Created: {getattr(d, 'created_at', 'N/A')}",
            ]

            whois_data = getattr(d, 'whois_data', [])
            if whois_data:
                lines.append("\nWHOIS Data:")
                for w in whois_data:
                    raw = getattr(w, 'raw', None)
                    if raw:
                        lines.append(f"  {raw[:500]}")
                    else:
                        data_obj = getattr(w, 'data', None)
                        if data_obj:
                            try:
                                lines.append(f"  {data_obj.to_json()[:500]}")
                            except Exception:
                                lines.append(f"  {data_obj}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving suspicious domain details: {e}"

    # ── Points of Interest ────────────────────────────────────────

    @mcp.tool()
    def list_points_of_interest(
        search: str = None,
        types: str = None,
        has_finding: bool = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List points of interest (leaked credentials, exposed configs, interesting endpoints).

        Args:
            search: Search keyword.
            types: Comma-separated POI types.
            has_finding: Filter to only POIs that have an associated finding.
            business_unit_ids: Comma-separated business unit IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = PointsOfInterestApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search
            if types:
                kwargs["types"] = [t.strip() for t in types.split(",") if t.strip()]
            if has_finding is not None:
                kwargs["has_finding"] = has_finding
            if business_unit_ids:
                kwargs["business_unit_ids"] = business_unit_ids
            if created_from:
                kwargs["created_from"] = parse_date(created_from)
            if created_to:
                kwargs["created_to"] = parse_date(created_to)

            response = api.get_list_points_of_interest(**kwargs)

            if not hasattr(response, 'data') or not response.data:
                return "No points of interest found."

            total = get_total(response)
            lines = []
            for p in response.data:
                pid = getattr(p, 'id', '')
                name = getattr(p, 'name', 'Unknown')
                poi_type = getattr(p, 'type', '')
                url = getattr(p, 'url', '')
                asset_name = getattr(p, 'asset_name', '')
                bus = format_bus(getattr(p, 'business_units', []))
                
                finding_id = getattr(p, 'finding_id', None) or getattr(p, 'findingId', None)
                is_perm_suppress = getattr(p, 'is_permanent_suppression', None) or getattr(p, 'isPermanentSuppression', None)
                
                type_str = f" [{poi_type}]" if poi_type else ""
                asset_str = f" on {asset_name}" if asset_name else ""
                url_str = f" - {url}" if url else ""
                finding_str = f" (Finding ID: {finding_id})" if finding_id else ""
                suppress_str = " [Permanently Suppressed]" if is_perm_suppress else ""
                
                lines.append(f"• [ID:{pid}] {name}{type_str}{asset_str}{url_str}{bus}{finding_str}{suppress_str}")

            header = f"Points of Interest ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing points of interest: {e}"

    # ── Certificates ──────────────────────────────────────────────

    @mcp.tool()
    def list_certificates(
        subject_common_name_search: str = None,
        subject_alt_name_search: str = None,
        subject_organisation_search: str = None,
        asset_name_search: str = None,
        statuses: str = None,
        business_unit_ids: str = None,
        not_after_from: str = None,
        not_after_to: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List SSL/TLS certificates with subject, issuer, and expiry information.

        Args:
            subject_common_name_search: Search by certificate common name.
            subject_alt_name_search: Search by subject alternative name.
            subject_organisation_search: Search by subject organisation.
            asset_name_search: Search by associated asset name.
            statuses: Comma-separated status filters.
            business_unit_ids: Comma-separated business unit IDs.
            not_after_from: Expiry range start date (YYYY-MM-DD).
            not_after_to: Expiry range end date (YYYY-MM-DD).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = CertificatesApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if subject_common_name_search:
                kwargs["subject_common_name_search"] = subject_common_name_search
            if subject_alt_name_search:
                kwargs["subject_alt_name_search"] = subject_alt_name_search
            if subject_organisation_search:
                kwargs["subject_organisation_search"] = subject_organisation_search
            if asset_name_search:
                kwargs["asset_name_search"] = asset_name_search
            if statuses:
                kwargs["statuses"] = statuses
            if business_unit_ids:
                kwargs["business_unit_ids"] = business_unit_ids
            if not_after_from:
                kwargs["not_after_from"] = parse_date(not_after_from)
            if not_after_to:
                kwargs["not_after_to"] = parse_date(not_after_to)

            response = api.get_list_certificates(**kwargs)

            if not hasattr(response, 'data') or not response.data:
                return "No certificates found."

            total = get_total(response)
            lines = []
            for c in response.data:
                cid = getattr(c, 'id', '')
                cert = getattr(c, 'certificate', None)
                asset = getattr(c, 'asset', None)
                cn = getattr(cert, 'subject_common_name', 'Unknown') if cert else 'Unknown'
                issuer = getattr(cert, 'issuer_organisation', '') if cert else ''
                status = getattr(cert, 'status', '') if cert else ''
                asset_name = getattr(asset, 'name', '') if asset else ''
                issuer_str = f" (issued by {issuer})" if issuer else ""
                asset_str = f" on {asset_name}" if asset_name else ""
                status_str = f" [{status}]" if status else ""
                lines.append(f"• [ID:{cid}] {cn}{issuer_str}{asset_str}{status_str}")

            header = f"Certificates ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing certificates: {e}"

    @mcp.tool()
    def get_certificate_details(certificate_id: int) -> str:
        """Get full details for a specific certificate including subject, issuer, SANs, and validity.

        Args:
            certificate_id: The certificate ID.
        """
        try:
            api = CertificatesApi(get_api_client())
            response = api.get_certificate_details(id=certificate_id)

            c = response.data if hasattr(response, 'data') else response
            if not c:
                return f"Certificate {certificate_id} not found."

            cert = getattr(c, 'certificate', None)
            asset = getattr(c, 'asset', None)

            lines = [f"Certificate #{getattr(c, 'id', certificate_id)}"]

            if cert:
                lines.extend([
                    f"Subject CN: {getattr(cert, 'subject_common_name', 'N/A')}",
                    f"Subject Org: {getattr(cert, 'subject_organisation', 'N/A')}",
                    f"Subject Country: {getattr(cert, 'subject_country', 'N/A')}",
                    f"Issuer CN: {getattr(cert, 'issuer_common_name', 'N/A')}",
                    f"Issuer Org: {getattr(cert, 'issuer_organisation', 'N/A')}",
                    f"Issuer Country: {getattr(cert, 'issuer_country', 'N/A')}",
                    f"Serial Number: {getattr(cert, 'serial_number', None) or getattr(cert, 'serialNumber', 'N/A')}",
                    f"Fingerprint: {getattr(cert, 'fingerprint', 'N/A')}",
                    f"Public Key: {getattr(cert, 'public_key_info_alg', '')} {getattr(cert, 'public_key_info_size', '')}",
                    f"Valid From: {getattr(cert, 'not_before', None) or getattr(cert, 'notBefore', 'N/A')}",
                    f"Valid Until: {getattr(cert, 'not_after', None) or getattr(cert, 'notAfter', 'N/A')}",
                    f"Last Seen: {getattr(cert, 'last_seen_at', None) or getattr(cert, 'lastSeenAt', 'N/A')}",
                    f"Status: {getattr(cert, 'status', 'N/A')}",
                    f"Created: {getattr(cert, 'created_at', 'N/A')}",
                ])
                updated_at = getattr(cert, 'updated_at', None) or getattr(cert, 'updatedAt', None)
                if updated_at:
                    lines.append(f"Updated: {updated_at}")
                sans = getattr(cert, 'subject_alt_names', [])
                if sans:
                    lines.append(f"SANs ({len(sans)}): {', '.join(sans[:20])}")
                    if len(sans) > 20:
                        lines.append(f"  ... and {len(sans) - 20} more")

            if asset:
                lines.append(f"\nAsset: {getattr(asset, 'name', 'N/A')} [{getattr(asset, 'type', '')}]")
                bus = format_bus(getattr(asset, 'business_units', []))
                if bus:
                    lines.append(f"Business Units:{bus}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error retrieving certificate details: {e}"

    @mcp.tool()
    def get_expiring_certificates(days: int = 30, page_size: int = 30) -> str:
        """List certificates expiring within a given number of days.

        Args:
            days: Number of days from today to check for expiring certificates.
            page_size: Results per page (max 30).
        """
        try:
            api = CertificatesApi(get_api_client())
            now = datetime.now()
            expiry_cutoff = now + timedelta(days=days)

            response = api.get_list_certificates(
                not_after_from=now,
                not_after_to=expiry_cutoff,
                page_size=min(page_size, 30),
            )

            if not hasattr(response, 'data') or not response.data:
                return f"No certificates expiring within {days} days."

            total = get_total(response)
            lines = []
            for c in response.data:
                cid = getattr(c, 'id', '')
                cert = getattr(c, 'certificate', None)
                asset = getattr(c, 'asset', None)
                cn = getattr(cert, 'subject_common_name', 'Unknown') if cert else 'Unknown'
                asset_name = getattr(asset, 'name', '') if asset else ''
                asset_str = f" on {asset_name}" if asset_name else ""
                lines.append(f"• [ID:{cid}] {cn}{asset_str}")

            header = f"Certificates Expiring Within {days} Days ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing expiring certificates: {e}"

    # ── Pending Domains ───────────────────────────────────────────

    @mcp.tool()
    def search_pending_domains(
        name: str = None,
        source: str = None,
        start_date: str = None,
        end_date: str = None,
        sort_by: str = None,
        sort_order: str = None,
        page: int = 1,
        page_size: int = 20,
    ) -> str:
        """List pending/unclaimed domains that could be claimed by adversaries.

        These are domains found via DNS analysis (e.g. CNAME to expired domain,
        NS pointing to unregistered nameserver) that represent takeover risks.

        Args:
            name: Filter by domain name.
            source: Filter by discovery source.
            start_date: Start date filter (YYYY-MM-DD).
            end_date: End date filter (YYYY-MM-DD).
            sort_by: Sort field.
            sort_order: Sort direction (asc/desc).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = PendingDomainsApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if name:
                kwargs["name"] = name
            if source:
                kwargs["source"] = source
            if start_date:
                kwargs["start_date"] = parse_date(start_date)
            if end_date:
                kwargs["end_date"] = parse_date(end_date)
            if sort_by:
                kwargs["sort_by"] = sort_by
            if sort_order:
                kwargs["sort_order"] = sort_order

            response = api.get_list_pending_domains(**kwargs)

            if not hasattr(response, "data") or not response.data:
                return "No pending domains found."

            total = get_total(response) or 0
            lines = [f"Pending Domains ({len(response.data)} of {total}):", ""]

            for i, domain in enumerate(response.data, 1):
                did = getattr(domain, "id", "")
                dname = getattr(domain, "name", "") or getattr(domain, "domain", "")
                reason = getattr(domain, "source", "") or getattr(domain, "reason", "")
                created = getattr(domain, "created_at", "") or getattr(domain, "discovered_at", "")

                lines.append(f"{i}. ID: {did} | {dname}")
                if reason:
                    lines.append(f"   Source: {reason}")
                if created:
                    lines.append(f"   Discovered: {created}")
                lines.append("")

            return "\n".join(lines)
        except Exception as e:
            return f"Error listing pending domains: {e}"
