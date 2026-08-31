"""Intelligence tools for watchTowr MCP."""


from watchtowr_api_sdk.api.vulnerability_intelligence_api import VulnerabilityIntelligenceApi
from watchtowr_api_sdk.api.adversary_intelligence_api import AdversaryIntelligenceApi
# from watchtowr_api_sdk.api.compromised_endpoints_api import CompromisedEndpointsApi
# from watchtowr_api_sdk.api.credential_attempt_logs_api import CredentialAttemptLogsApi
from watchtowr_api_sdk.api.finding_retest_history_api import FindingRetestHistoryApi
from watchtowr_api_sdk.api.active_defense_library_api import ActiveDefenseLibraryApi
from watchtowr_api_sdk.api.capability_search_api import CapabilitySearchApi

from ..client import get_api_client, get_total, parse_date, severity_display, supported_kwargs


def register_intelligence_tools(mcp):

    @mcp.tool()
    def list_vulnerability_intelligence(
        search: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List vulnerability intelligence entries (CVEs tracked by watchTowr).
        
        Args:
            search: CVE ID, watchTowr ID, or title.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = VulnerabilityIntelligenceApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search
            response = api.get_list_vulnerability_intelligence(**kwargs)
            if not hasattr(response, 'data') or not response.data:
                return "No vulnerability intelligence entries found."
            
            total = get_total(response) or 0
            lines = [f"Vulnerability Intelligence ({len(response.data)} of {total}):"]
            for v in response.data:
                vid = getattr(v, 'vulnerability_id', '')
                title = getattr(v, 'display_name', '') or getattr(v, 'title', 'Untitled')
                risk = getattr(v, 'exploitation_risk_level', '')
                is_affected = getattr(v, 'is_affected', False)
                vuln_type = getattr(v, 'type', '')
                epss_score = getattr(v, 'epss_score', None)
                epss_pct = getattr(v, 'epss_percentile', None)
                wt_score = getattr(v, 'wt_instinct_score', None)
                wt_risk = getattr(v, 'wt_instinct_risk_level', '')
                kev_types = getattr(v, 'kev_types', []) or []
            
                affected_str = " ⚠️ AFFECTED" if is_affected else ""
                lines.append(f"• [{vid}] {title}{affected_str}")
            
                detail_parts = []
                if vuln_type:
                    detail_parts.append(f"Type: {vuln_type}")
                if risk:
                    detail_parts.append(f"Risk: {risk}")
                if epss_score is not None:
                    epss_str = f"EPSS: {epss_score}"
                    if epss_pct is not None:
                        epss_str += f" ({epss_pct}th pct)"
                    detail_parts.append(epss_str)
                if detail_parts:
                    lines.append(f"  {' | '.join(detail_parts)}")
            
                extra_parts = []
                if wt_score is not None:
                    wt_str = f"wtInstinct: {wt_score}"
                    if wt_risk:
                        wt_str += f" ({wt_risk})"
                    extra_parts.append(wt_str)
                if kev_types:
                    kev_parts = []
                    for source in ("cisa", "vulncheck", "watchtowr"):
                        if getattr(kev_types, source, False):
                            kev_parts.append(source)
                    if kev_parts:
                        extra_parts.append(f"KEV: {', '.join(kev_parts)}")
                if extra_parts:
                    lines.append(f"  {' | '.join(extra_parts)}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    @mcp.tool()
    def get_vulnerability_intelligence_details(
        identifier: str,
    ) -> str:
        """Get full details for a vulnerability intelligence entry.
        
        Args:
            identifier: CVE ID (e.g. "CVE-2024-1234") or watchTowr vuln ID.
        """
        try:
            api = VulnerabilityIntelligenceApi(get_api_client())
            response = api.get_vulnerability_intelligence_details(identifier=identifier)
            if not hasattr(response, 'data') or not response.data:
                return f"No details found for vulnerability intelligence entry {identifier}."
            v = response.data
            
            title = getattr(v, 'display_name', getattr(v, 'title', 'Untitled'))
            
            lines = [f"Vulnerability Intelligence Details: {title}"]
            lines.append(f"ID: {getattr(v, 'vulnerability_id', 'N/A')}")
            lines.append(f"CVE ID: {getattr(v, 'cve_id', 'N/A')}")
            lines.append(f"Risk Level: {getattr(v, 'exploitation_risk_level', 'N/A')}")
            lines.append(f"Published: {getattr(v, 'nvd_published_date', 'N/A')}")
            
            epss = getattr(v, 'epss', None)
            if epss is not None:
                lines.append(f"EPSS: {epss}")
            
            maturity = getattr(v, 'exploitation_maturity', None)
            if maturity:
                lines.append(f"Exploitation Maturity: {maturity}")
            
            description = getattr(v, 'description', '')
            if description:
                lines.append("\nDescription:")
                lines.append(description)
                
            wt_score = getattr(v, 'wt_instinct_score', None)
            wt_risk = getattr(v, 'wt_instinct_risk_level', '')
            if wt_score is not None:
                lines.append(f"wtInstinct Score: {wt_score} ({wt_risk})")
            
            first_exploited = getattr(v, 'first_exploited_date', None)
            if first_exploited:
                lines.append(f"First Exploited: {first_exploited}")
            
            is_affected = getattr(v, 'is_affected', False)
            lines.append(f"Affected: {'Yes' if is_affected else 'No'}")
            
            vendor = getattr(v, 'affected_vendor', None)
            if vendor:
                lines.append(f"Affected Vendor: {vendor}")
            
            cvss = getattr(v, 'cvss_v3x_metrics', None)
            if cvss:
                lines.append(f"CVSS v3.x: {cvss}")

            access_vector = getattr(v, 'access_vector', None) or getattr(v, 'accessVector', None)
            if access_vector:
                lines.append(f"Access Vector: {access_vector}")

            kev = getattr(v, 'kev_details', None)
            if kev:
                lines.append(f"KEV Details: {kev}")

            cwes = getattr(v, 'kb_entry_cwes', [])
            if cwes:
                cwe_parts = []
                for c in cwes:
                    cwe_id = getattr(c, 'cwe_id', None) or (c if isinstance(c, str) else str(c))
                    cwe_url = getattr(c, 'cwe_url', None) or getattr(c, 'cweUrl', None)
                    cwe_parts.append(f"{cwe_id} ({cwe_url})" if cwe_url else str(cwe_id))
                lines.append(f"CWEs: {', '.join(cwe_parts)}")
            
            attacker_summary = getattr(v, 'first_reported_by_attacker_summary', '')
            if attacker_summary:
                lines.append(f"\nAttacker Summary:\n{attacker_summary}")

            affected_products = getattr(v, 'affected_products', [])
            if affected_products:
                lines.append("\nAffected Products:")
                for product in affected_products:
                    lines.append(f"• {product}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    @mcp.tool()
    def list_adversary_intelligence(
        search: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List adversary intelligence profiles (threat actors tracked by watchTowr).
        
        Args:
            search: Name or alias.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = AdversaryIntelligenceApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search
            response = api.get_list_adversary_intelligence(**kwargs)
            if not hasattr(response, 'data') or not response.data:
                return "No adversary intelligence profiles found."
            
            total = get_total(response) or 0
            lines = [f"Adversary Intelligence ({min(page_size, len(response.data))} of {total}):"]
            for a in response.data:
                aid = getattr(a, 'attacker_id', '')
                name = getattr(a, 'name', 'Unknown')
                actor_type = getattr(a, 'type', '')
                country = getattr(a, 'origin_country_code', '')
                is_affected = getattr(a, 'is_affected', False)
                aliases = ", ".join(getattr(a, 'aliases', []) or [])
                last_reported = getattr(a, 'last_reported_date', '')
                hunts = getattr(a, 'affected_tracked_hunts_count', 0)
                findings = getattr(a, 'affected_open_findings_count', 0)
            
                affected_str = " ⚠️ AFFECTED" if is_affected else ""
                country_str = f" [{country}]" if country else ""
                type_str = f" ({actor_type})" if actor_type else ""
            
                lines.append(f"• [ID:{aid}] {name}{type_str}{country_str}{affected_str}")
                if aliases:
                    lines.append(f"  Aliases: {aliases}")
                lines.append(f"  Hunts: {hunts} | Open Findings: {findings} | Last Reported: {last_reported or 'N/A'}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    @mcp.tool()
    def get_adversary_intelligence_details(
        attacker_id: int,
    ) -> str:
        """Get full details for an adversary intelligence profile.
        
        Args:
            attacker_id: Numeric attacker ID.
        """
        try:
            api = AdversaryIntelligenceApi(get_api_client())
            response = api.get_adversary_intelligence_details(attacker_id=attacker_id)
            if not hasattr(response, 'data') or not response.data:
                return f"No details found for adversary intelligence profile {attacker_id}."
            a = response.data
            
            lines = [f"Adversary Intelligence Details: {getattr(a, 'name', 'Unknown')}"]
            lines.append(f"ID: {getattr(a, 'attacker_id', 'N/A')}")
            aliases = ", ".join(getattr(a, 'aliases', []) or [])
            lines.append(f"Aliases: {aliases}")
            
            actor_type = getattr(a, 'type', '')
            if actor_type:
                lines.append(f"Type: {actor_type}")
            
            country = getattr(a, 'country_code', '')
            if country:
                lines.append(f"Origin: {country}")
            
            is_affected = getattr(a, 'is_affected', False)
            lines.append(f"Affected: {'Yes ⚠️' if is_affected else 'No'}")
            
            first_reported = getattr(a, 'first_reported_date', None)
            if first_reported:
                lines.append(f"First Reported: {first_reported}")
            
            vuln_updated = getattr(a, 'vulnerability_last_updated', None)
            if vuln_updated:
                lines.append(f"Vulnerability Last Updated: {vuln_updated}")
            
            mitre_updated = getattr(a, 'mitre_last_updated', None)
            if mitre_updated:
                lines.append(f"MITRE Last Updated: {mitre_updated}")
            
            description = getattr(a, 'description', '')
            if description:
                lines.append("\nDescription:")
                lines.append(description)
                
            target_industries = getattr(a, 'target_industries', [])
            if target_industries:
                lines.append("\nTarget Industries:")
                for t in target_industries:
                    lines.append(f"• {t}")
                    
            victim_countries = getattr(a, 'victim_countries', [])
            if victim_countries:
                lines.append("\nVictim Countries:")
                for c in victim_countries:
                    lines.append(f"• {c}")
                    
            latest_media = getattr(a, 'latest_media', [])
            if latest_media:
                lines.append("\nLatest Media:")
                for media in latest_media:
                    lines.append(f"• {media}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    '''
    @mcp.tool()
    def list_compromised_endpoints(
        query: str = None,
        stealer_families: str = None,
        operating_systems: str = None,
        countries: str = None,
        statuses: str = None,
        compromised_from: str = None,
        compromised_to: str = None,
        created_from: str = None,
        created_to: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List compromised endpoints discovered via stealer logs.
        
        Args:
            query: Hostname or IP (partial match).
            stealer_families: Comma-separated stealer families.
            operating_systems: Comma-separated OS filters.
            countries: Comma-separated country codes.
            statuses: Comma-separated statuses.
            compromised_from: Start date (YYYY-MM-DD).
            compromised_to: End date (YYYY-MM-DD).
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = CompromisedEndpointsApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            
            if query: kwargs["query"] = query
            if stealer_families: kwargs["stealer_families"] = [x.strip() for x in stealer_families.split(",")]
            if operating_systems: kwargs["operating_systems"] = [x.strip() for x in operating_systems.split(",")]
            if countries: kwargs["countries"] = [x.strip() for x in countries.split(",")]
            if statuses: kwargs["statuses"] = [x.strip() for x in statuses.split(",")]
            if compromised_from: kwargs["compromised_from"] = parse_date(compromised_from)
            if compromised_to: kwargs["compromised_to"] = parse_date(compromised_to)
            if created_from: kwargs["created_from"] = parse_date(created_from)
            if created_to: kwargs["created_to"] = parse_date(created_to)
                
            response = api.get_list_compromised_endpoints(**supported_kwargs(api.get_list_compromised_endpoints, kwargs))
            if not hasattr(response, 'data') or not response.data:
                return "No compromised endpoints found."
            
            total = get_total(response) or 0
            lines = [f"Compromised Endpoints ({min(page_size, len(response.data))} of {total}):"]
            for ep in response.data:
                eid = getattr(ep, 'id', '')
                hostname = getattr(ep, 'hostname', 'N/A')
                ip = getattr(ep, 'ip', '')
                status = getattr(ep, 'status', 'N/A')
                country = getattr(ep, 'country', '')
                stealer = getattr(ep, 'stealer_family', 'N/A')
                os_name = getattr(ep, 'operating_system', 'N/A')
                comp_at = getattr(ep, 'date_compromised', 'N/A')
                discovery_type = getattr(ep, 'discovery_type', '')
                discovery_value = getattr(ep, 'discovery_value', '')
                malware_path = getattr(ep, 'malware_path', '')
            
                country_str = f" [{country}]" if country else ""
                ip_str = f" / {ip}" if ip else ""
                lines.append(f"• [ID:{eid}] {hostname}{ip_str}{country_str} - {status}")
                lines.append(f"  Stealer: {stealer} | OS: {os_name} | Compromised: {comp_at}")
            
                extras = []
                if discovery_type:
                    disc_str = f"Discovery: {discovery_type}"
                    if discovery_value:
                        disc_str += f" ({discovery_value})"
                    extras.append(disc_str)
                if malware_path:
                    extras.append(f"Malware: {malware_path}")
                if extras:
                    lines.append(f"  {' | '.join(extras)}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    @mcp.tool()
    def get_compromised_endpoint_credentials(
        endpoint_id: int,
        query: str = None,
        usernames: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List harvested credentials for a specific compromised endpoint.
        
        Args:
            endpoint_id: Compromised endpoint ID.
            query: Username or URL (partial match).
            usernames: Comma-separated usernames.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = CompromisedEndpointsApi(get_api_client())
            kwargs = {"id": endpoint_id, "page": page, "page_size": min(page_size, 30)}
            if query: kwargs["query"] = query
            if usernames: kwargs["usernames"] = [x.strip() for x in usernames.split(",")]
                
            response = api.get_list_compromised_endpoint_harvested_credentials(**supported_kwargs(api.get_list_compromised_endpoint_harvested_credentials, kwargs))
            if not hasattr(response, 'data') or not response.data:
                return f"No harvested credentials found for endpoint {endpoint_id}."
            
            total = get_total(response) or 0
            lines = [f"Harvested Credentials for Endpoint {endpoint_id} ({min(page_size, len(response.data))} of {total}):"]
            for c in response.data:
                cid = getattr(c, 'id', '')
                url = getattr(c, 'url', 'N/A')
                username = getattr(c, 'username', 'N/A')
                cred_type = getattr(c, 'type', 'N/A')
                created = getattr(c, 'created_at', '')
                # Never display password/credential value
                lines.append(f"• [ID:{cid}] [{cred_type}] {username} → {url} ({created})")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    @mcp.tool()
    def list_credential_attempt_logs(
        technologies: str = None,
        asset_name: str = None,
        username: str = None,
        statuses: str = None,
        sources: str = None,
        business_unit_ids: str = None,
        created_from: str = None,
        created_to: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List credential stuffing attempt logs across the attack surface.
        
        Args:
            technologies: Comma-separated technologies.
            asset_name: Partial match.
            username: Partial match.
            statuses: Comma-separated statuses.
            sources: Comma-separated sources.
            business_unit_ids: Comma-separated BU IDs.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = CredentialAttemptLogsApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            
            if technologies: kwargs["technologies"] = [x.strip() for x in technologies.split(",")]
            if asset_name: kwargs["asset_name"] = asset_name
            if username: kwargs["username"] = username
            if statuses: kwargs["statuses"] = [x.strip() for x in statuses.split(",")]
            if sources: kwargs["sources"] = [x.strip() for x in sources.split(",")]
            if business_unit_ids: kwargs["business_unit_ids"] = [int(x.strip()) for x in business_unit_ids.split(",")]
            if created_from: kwargs["created_from"] = parse_date(created_from)
            if created_to: kwargs["created_to"] = parse_date(created_to)
                
            response = api.get_list_credential_attempt_logs(**supported_kwargs(api.get_list_credential_attempt_logs, kwargs))
            if not hasattr(response, 'data') or not response.data:
                return "No credential attempt logs found."
            
            total = get_total(response) or 0
            lines = [f"Credential Attempt Logs ({min(page_size, len(response.data))} of {total}):"]
            for log in response.data:
                lid = getattr(log, 'id', '')
                tech = getattr(log, 'technology', 'N/A')
                status = getattr(log, 'status', 'N/A')
                source = getattr(log, 'source', '')
                attempted = getattr(log, 'attempted_at', 'N/A')
                finding_id = getattr(log, 'finding_id', None)
            
                creds = getattr(log, 'credentials', None)
                uname = getattr(creds, 'username', 'N/A') if creds else 'N/A'
                target_url = getattr(creds, 'target_url', '') if creds else ''
            
                affected = getattr(log, 'affected_asset', None)
                asset_name = getattr(affected, 'name', '') if affected else ''
                asset_type = getattr(affected, 'type', '') if affected else ''
            
                target_str = f" → {target_url}" if target_url else ""
                lines.append(f"• [ID:{lid}] {uname}{target_str} [{tech}] - {status}")
            
                detail_parts = []
                if asset_name:
                    type_str = f" ({asset_type})" if asset_type else ""
                    detail_parts.append(f"Asset: {asset_name}{type_str}")
                if source:
                    detail_parts.append(f"Source: {source}")
                if finding_id:
                    detail_parts.append(f"Finding: #{finding_id}")
                if detail_parts:
                    lines.append(f"  {' | '.join(detail_parts)}")
                lines.append(f"  Attempted: {attempted}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"
    '''


    @mcp.tool()
    def list_finding_retest_history(
        finding_id: str = None,
        finding_title: str = None,
        asset_name: str = None,
        severities: str = None,
        retest_run_statuses: str = None,
        retest_result_statuses: str = None,
        attempts: str = None,
        triggered_by: str = None,
        business_unit_ids: str = None,
        retest_start_date_from: str = None,
        retest_start_date_to: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List finding retest history across all findings (global audit view).

        Args:
            finding_id: Filter by finding ID.
            finding_title: Filter by finding title.
            asset_name: Filter by asset name.
            severities: Comma-separated severities.
            retest_run_statuses: Comma-separated retest run statuses.
            retest_result_statuses: Comma-separated result statuses (resolved, unresolved).
            attempts: Comma-separated attempt types.
            triggered_by: Comma-separated trigger sources.
            business_unit_ids: Comma-separated BU IDs.
            retest_start_date_from: Start date (YYYY-MM-DD).
            retest_start_date_to: End date (YYYY-MM-DD).
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = FindingRetestHistoryApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}

            if finding_id: kwargs["finding_id"] = finding_id
            if finding_title: kwargs["finding_title"] = finding_title
            if asset_name: kwargs["asset_name"] = asset_name
            if severities: kwargs["severities"] = severities
            if retest_run_statuses: kwargs["retest_run_statuses"] = retest_run_statuses
            if retest_result_statuses: kwargs["retest_result_statuses"] = retest_result_statuses
            if attempts: kwargs["attempts"] = attempts
            if triggered_by: kwargs["triggered_by"] = [x.strip() for x in triggered_by.split(",")]
            if business_unit_ids: kwargs["business_unit_ids"] = business_unit_ids
            if retest_start_date_from: kwargs["retest_start_date_from"] = parse_date(retest_start_date_from)
            if retest_start_date_to: kwargs["retest_start_date_to"] = parse_date(retest_start_date_to)
                
            response = api.get_list_finding_retest_history(**supported_kwargs(api.get_list_finding_retest_history, kwargs))
            if not hasattr(response, 'data') or not response.data:
                return "No finding retest history entries found."
            
            total = get_total(response) or 0
            lines = [f"Finding Retest History ({min(page_size, len(response.data))} of {total}):"]
            for h in response.data:
                hid = getattr(h, 'id', '')
                finding_obj = getattr(h, 'finding', None)
                title = getattr(finding_obj, 'title', 'Untitled') if finding_obj else 'Untitled'
                fid = getattr(finding_obj, 'id', '') if finding_obj else ''
                f_severity = severity_display(getattr(finding_obj, 'severity', '')) if finding_obj else ''
                f_status = getattr(finding_obj, 'status', '') if finding_obj else ''
            
                asset_obj = getattr(h, 'asset', None)
                aname = getattr(asset_obj, 'name', 'Unknown') if asset_obj else 'Unknown'
                atype = getattr(asset_obj, 'type', '') if asset_obj else ''
            
                trigger_obj = getattr(h, 'triggered_by', None)
                trigger = getattr(trigger_obj, 'name', 'Unknown') if trigger_obj else 'Unknown'
            
                status = getattr(h, 'current_retest_status', 'Unknown')
                result = getattr(h, 'result', '')
                attempt = getattr(h, 'attempt_number', 'N/A')
                days_open = getattr(h, 'days_open_before_retest', None)
                start = getattr(h, 'started_at', 'N/A')
                complete = getattr(h, 'completed_at', 'N/A')
            
                asset_str = f" | Asset: {aname} ({atype})" if aname != 'Unknown' else ""
                lines.append(f"• [ID:{hid}] Finding [#{fid}]: {title}{asset_str}")
            
                status_parts = [f"Attempt #{attempt}", f"Status: {status}"]
                if result:
                    status_parts.append(f"Result: {result}")
                lines.append(f"  {' | '.join(status_parts)}")
            
                detail_parts = []
                if f_severity:
                    detail_parts.append(f"Severity: {f_severity}")
                if f_status:
                    detail_parts.append(f"Finding Status: {f_status}")
                if detail_parts:
                    lines.append(f"  {' | '.join(detail_parts)}")
            
                meta_parts = [f"Triggered by: {trigger}"]
                if days_open is not None:
                    meta_parts.append(f"Days Open: {days_open}")
                lines.append(f"  {' | '.join(meta_parts)}")
                lines.append(f"  Started: {start} | Completed: {complete}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    @mcp.tool()
    def get_finding_retest_history_details(
        finding_id: int,
    ) -> str:
        """Get retest history for a specific finding (all retest runs).
        
        Args:
            finding_id: Numeric finding ID.
        """
        try:
            api = FindingRetestHistoryApi(get_api_client())
            kwargs = {"finding_id": str(finding_id), "page": 1, "page_size": 30}
            
            response = api.get_list_finding_retest_history(**supported_kwargs(api.get_list_finding_retest_history, kwargs))
            if not hasattr(response, 'data') or not response.data:
                return f"No retest history found for finding {finding_id}."
            
            total = get_total(response) or 0
            lines = [f"Found {total} retest runs for finding {finding_id}."]
            for h in response.data:
                finding_obj = getattr(h, 'finding', None)
                title = getattr(finding_obj, 'title', 'Untitled') if finding_obj else 'Untitled'
                
                asset_obj = getattr(h, 'asset', None)
                aname = getattr(asset_obj, 'name', 'Unknown') if asset_obj else 'Unknown'
                
                severity = severity_display(getattr(finding_obj, 'severity', '')) if finding_obj else ''
                status = getattr(h, 'current_retest_status', 'Unknown')
                
                trigger_obj = getattr(h, 'triggered_by', None)
                trigger = getattr(trigger_obj, 'name', 'Unknown') if trigger_obj else 'Unknown'
                
                attempt = getattr(h, 'attempt_number', 'N/A')
                start = getattr(h, 'started_at', 'N/A')
                complete = getattr(h, 'completed_at', 'N/A')
                
                lines.append(f"\nRetest Run [{getattr(h, 'id', '')}] - Attempt: {attempt}")
                lines.append(f"Finding: {title}")
                lines.append(f"Asset: {aname}")
                lines.append(f"Severity: {severity}")
                lines.append(f"Status: {status}")
                
                result = getattr(h, 'result', '')
                if result:
                    lines.append(f"Result: {result}")
                
                days_open = getattr(h, 'days_open_before_retest', None)
                if days_open is not None:
                    lines.append(f"Days Open Before Retest: {days_open}")
                
                f_status = getattr(finding_obj, 'status', '') if finding_obj else ''
                if f_status:
                    lines.append(f"Finding Status: {f_status}")
                
                atype = getattr(asset_obj, 'type', '') if asset_obj else ''
                if atype:
                    lines.append(f"Asset Type: {atype}")
                
                lines.append(f"Triggered By: {trigger}")
                lines.append(f"Started At: {start}")
                lines.append(f"Completed At: {complete}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    @mcp.tool()
    def search_active_defense_library(
        search: str = None,
        page: int = 1,
        page_size: int = 20,
    ) -> str:
        """Browse or search the active defense rule library.

        Lists detection rules and defense templates available in the platform.

        Args:
            search: Search by rule name or description.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = ActiveDefenseLibraryApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search

            response = api.get_list_active_defense_library_rules(
                **supported_kwargs(api.get_list_active_defense_library_rules, kwargs)
            )

            if not hasattr(response, "data") or not response.data:
                return "No active defense rules found."

            total = get_total(response) or 0
            lines = [f"Active Defense Library ({len(response.data)} of {total}):"]
            lines.append("")

            for i, rule in enumerate(response.data, 1):
                rid = getattr(rule, "id", "")
                rule_name = getattr(rule, "rule_name", "")
                cve_id = getattr(rule, "cve_id", None)
                wt_id = getattr(rule, "wt_id", None)
                rule_type = getattr(rule, "type", "")
                kev_status = getattr(rule, "kev_status", None)
                zero_day = getattr(rule, "zero_day", False)
                providers = getattr(rule, "providers", []) or []
                created_at = getattr(rule, "created_at", "")
                updated_at = getattr(rule, "updated_at", "")

                lines.append(f"{i}. ID: {rid} | {rule_name}")

                meta_parts = []
                if rule_type:
                    meta_parts.append(f"Type: {rule_type}")
                if cve_id:
                    meta_parts.append(f"CVE: {cve_id}")
                if wt_id:
                    meta_parts.append(f"WT ID: {wt_id}")
                if zero_day:
                    meta_parts.append("Zero-day: Yes")
                if meta_parts:
                    lines.append(f"   {' | '.join(meta_parts)}")

                if kev_status:
                    kev_parts = []
                    for source in ("cisa", "vulncheck", "watchtowr"):
                        if getattr(kev_status, source, False):
                            kev_parts.append(source)
                    lines.append(f"   KEV: {', '.join(kev_parts) if kev_parts else 'None'}")

                if providers:
                    lines.append(f"   Providers: {', '.join(providers)}")

                if created_at or updated_at:
                    lines.append(f"   Created: {created_at or 'N/A'} | Updated: {updated_at or 'N/A'}")
                lines.append("")

            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"


    @mcp.tool()
    def search_capabilities(
        query: str,
        page: int = 1,
        page_size: int = 20,
    ) -> str:
        """Search watchTowr security coverage by hunt title, CVE ID, or TTP tactic.

        Returns matching hunts with associated CVE IDs and TTP Library tactics,
        showing what the platform actively detects.

        Args:
            query: Search term — hunt title, CVE ID (e.g. CVE-2021-44228), or tactic name.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = CapabilitySearchApi(get_api_client())
            kwargs = {"query": query, "page": page, "page_size": min(page_size, 30)}

            response = api.capability_search(
                **supported_kwargs(api.capability_search, kwargs)
            )

            data = response.data
            hunts = getattr(data, "hunts", None) or []
            ttp_library = getattr(data, "ttp_library", None) or []

            if not hunts and not ttp_library:
                return f'No capabilities found for "{query}".'

            total = get_total(response) or len(hunts)
            lines = [
                f'Capability Search: "{query}" ({len(hunts)} hunts of {total}, {len(ttp_library)} TTP tactics):'
            ]
            lines.append("")

            if hunts:
                lines.append("Matching Hunts:")
                for i, hunt in enumerate(hunts, 1):
                    title = getattr(hunt, "title", "") or "Untitled hunt"
                    cves = getattr(hunt, "cve_ids", []) or []
                    status = getattr(hunt, "status", None)
                    hunt_type = getattr(hunt, "type", None)
                    total_findings = getattr(hunt, "total_findings", None)
                    total_assets = getattr(hunt, "total_assets", None)

                    lines.append(f"{i}. {title}")
                    meta_parts = []
                    if status:
                        meta_parts.append(f"Status: {status}")
                    if hunt_type:
                        meta_parts.append(f"Type: {hunt_type}")
                    if total_findings is not None:
                        meta_parts.append(f"Findings: {total_findings}")
                    if total_assets is not None:
                        meta_parts.append(f"Assets: {total_assets}")
                    if meta_parts:
                        lines.append(f"   {' | '.join(meta_parts)}")
                    if cves:
                        cve_str = ", ".join(str(cve) for cve in cves[:5])
                        lines.append(f"   CVEs: {cve_str}")
                    lines.append("")

            if ttp_library:
                lines.append("Matching TTP Library Tactics:")
                for i, tactic in enumerate(ttp_library, 1):
                    name = getattr(tactic, "name", "") or "Unnamed tactic"
                    identifier = getattr(tactic, "identifier", None)
                    tactic_type = getattr(tactic, "type", None)
                    category = getattr(tactic, "category", None)
                    category_name = getattr(category, "name", None) if category else None
                    module = getattr(tactic, "module", None)

                    lines.append(f"{i}. {name}")
                    meta_parts = []
                    if identifier:
                        meta_parts.append(f"Identifier: {identifier}")
                    if tactic_type:
                        meta_parts.append(f"Type: {tactic_type}")
                    if category_name:
                        meta_parts.append(f"Category: {category_name}")
                    if module:
                        meta_parts.append(f"Module: {module}")
                    if meta_parts:
                        lines.append(f"   {' | '.join(meta_parts)}")
                    lines.append("")

            return "\n".join(lines)
        except Exception as e:
            return f"Error: {str(e)}"
