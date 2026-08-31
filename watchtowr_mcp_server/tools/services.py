from watchtowr_api_sdk.api.service_discovery_api import ServiceDiscoveryApi

from ..client import get_api_client, get_total, parse_date, format_bus


def register_service_tools(mcp):

    @mcp.tool()
    def list_technology_statistics(
        search: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List technology statistics for discovered services, ordered by count.

        Use this to find available technology names before filtering services.

        Args:
            search: Search technologies by name (e.g. "php", "nginx").
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = ServiceDiscoveryApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search
            
            response = api.get_technology_statistics(**kwargs)
            if not hasattr(response, 'data') or not response.data:
                return "No technology statistics found."
            
            total = get_total(response)
            lines = []
            for t in response.data:
                name = getattr(t, 'name', 'Unknown')
                count = getattr(t, 'count', 0)
                lines.append(f"• {name} — {count} services")
                
            header = f"Technologies ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing technology statistics: {e}"

    @mcp.tool()
    def list_services(
        search: str = None,
        countries: str = None,
        technology: str = None,
        port_numbers: str = None,
        port_services: str = None,
        ports: str = None,
        port_types: str = None,
        service_type_ids: str = None,
        business_unit_ids: str = None,
        include_closed_port: bool = False,
        include_no_service: bool = False,
        created_from: str = None,
        created_to: str = None,
        updated_from: str = None,
        updated_to: str = None,
        sort_by: str = None,
        order_by: str = None,
        suppression_filter: str = None,
        page: int = 1,
        page_size: int = 30,
    ) -> str:
        """List exposed services across the attack surface with extensive filtering.

        Args:
            search: Search keyword.
            countries: Comma-separated country codes.
            technology: Filter by technology NAME (e.g. "PHP,Apache").
            port_numbers: Comma-separated port numbers.
            port_services: Comma-separated service names.
            ports: Comma-separated port/protocols.
            port_types: Transport layer protocols (UDP/TCP).
            service_type_ids: Comma-separated service type IDs.
            business_unit_ids: Comma-separated business unit IDs.
            include_closed_port: Include closed ports.
            include_no_service: Include listings without service.
            created_from: Start date (YYYY-MM-DD).
            created_to: End date (YYYY-MM-DD).
            updated_from: Updated start date (YYYY-MM-DD).
            updated_to: Updated end date (YYYY-MM-DD).
            sort_by: Sort field.
            order_by: Order direction.
            suppression_filter: Filter by suppression status.
            page: Page number.
            page_size: Results per page (max 30).
        """
        try:
            api = ServiceDiscoveryApi(get_api_client())
            kwargs = {"page": page, "page_size": min(page_size, 30)}
            if search:
                kwargs["search"] = search
            if countries:
                kwargs["countries"] = countries
            if technology:
                kwargs["technology"] = technology
            if port_numbers:
                kwargs["port_numbers"] = port_numbers
            if port_services:
                kwargs["port_services"] = port_services
            if ports:
                kwargs["ports"] = ports
            if port_types:
                kwargs["port_types"] = port_types
            if service_type_ids:
                kwargs["service_type_ids"] = [x.strip() for x in service_type_ids.split(",")]
            if business_unit_ids:
                kwargs["business_unit_ids"] = [x.strip() for x in business_unit_ids.split(",")]
            if include_closed_port:
                kwargs["include_closed_port"] = include_closed_port
            if include_no_service:
                kwargs["include_no_service"] = include_no_service
            if created_from:
                kwargs["created_from"] = parse_date(created_from)
            if created_to:
                kwargs["created_to"] = parse_date(created_to)
            if updated_from:
                kwargs["updated_from"] = parse_date(updated_from)
            if updated_to:
                kwargs["updated_to"] = parse_date(updated_to)
            if sort_by:
                kwargs["sort_by"] = sort_by
            if order_by:
                kwargs["order_by"] = order_by
            if suppression_filter:
                kwargs["suppression_filter"] = suppression_filter

            response = api.get_list_service_listing(**kwargs)

            if not hasattr(response, 'data') or not response.data:
                return "No services found."

            total = get_total(response)
            lines = []
            for s in response.data:
                sid = getattr(s, 'id', '')
                ip = getattr(s, 'ip', 'Unknown')
                port = getattr(s, 'port', '?')
                service = getattr(s, 'service', '')
                country = getattr(s, 'country', '')
                banner = getattr(s, 'banner', '')
                ip_id = getattr(s, 'ip_id', None)
                state = getattr(s, 'state', None)
                finding_id = getattr(s, 'finding_id', None)
                techs = getattr(s, 'technologies', [])
                tech_names = [getattr(t, 'display_name', getattr(t, 'name', ''))
                              for t in techs] if techs else []
                tech_str = f" [{', '.join(tech_names)}]" if tech_names else ""
                svc_str = f" ({service})" if service else ""
                country_str = f" [{country}]" if country else ""
                banner_str = f" - {banner}" if banner else ""
                
                # Format the new fields
                extra_fields = []
                if ip_id is not None:
                    extra_fields.append(f"IP_ID:{int(ip_id)}")
                if state:
                    extra_fields.append(f"State:{state}")
                if finding_id is not None:
                    extra_fields.append(f"Finding_ID:{int(finding_id)}")
                extra_str = f" ({', '.join(extra_fields)})" if extra_fields else ""

                lines.append(f"• [ID:{sid}] {ip}:{port}{svc_str}{tech_str}{country_str}{banner_str}{extra_str}")

            header = f"Services ({len(lines)}"
            if total:
                header += f" of {total}"
            header += "):"
            return header + "\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing services: {e}"
