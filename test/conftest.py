"""Shared fixtures for the watchtowr-mcp test suite.

The MCP tools are FastMCP-decorated callables. Tests don't need a running MCP
transport — they just need the underlying Python function. To get those we
register every tool against a lightweight capture object that mimics the
`@mcp.tool()` decorator, then look them up by name.
"""
from __future__ import annotations

import os
import re

import pytest

from watchtowr_mcp_server.sdk_compat import apply_watchtowr_sdk_compat_patches
from watchtowr_mcp_server.tools import register_all_tools


ID_PATTERN = re.compile(r"\[ID:(\d+)\]")


class ToolCapture:
    """Stand-in for FastMCP that captures @tool()-decorated functions by name."""

    def __init__(self):
        self.tools: dict[str, callable] = {}

    def tool(self, *args, **kwargs):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorator


def pytest_addoption(parser):
    parser.addoption(
        "--run-writes",
        action="store_true",
        default=False,
        help="Run @pytest.mark.write tests that mutate platform state.",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-writes"):
        return
    skip_writes = pytest.mark.skip(reason="opt-in: pass --run-writes to execute")
    for item in items:
        if "write" in item.keywords:
            item.add_marker(skip_writes)


@pytest.fixture(scope="session")
def live_env():
    """Skip the test if live credentials are not present in the environment."""
    if not os.environ.get("WATCHTOWR_API_KEY"):
        pytest.skip("WATCHTOWR_API_KEY not set — skipping live test")
    if not os.environ.get("WATCHTOWR_PLATFORM_HOST"):
        pytest.skip("WATCHTOWR_PLATFORM_HOST not set — skipping live test")


@pytest.fixture(scope="session")
def tools() -> dict[str, callable]:
    """Every @mcp.tool() function in the server, keyed by function name."""
    apply_watchtowr_sdk_compat_patches()
    capture = ToolCapture()
    register_all_tools(capture)
    return capture.tools


@pytest.fixture(scope="session")
def call(tools):
    """Convenience: `call('tool_name', kwarg=value)` invokes the tool function."""
    def _call(name: str, **kwargs):
        if name not in tools:
            raise KeyError(f"Tool {name!r} is not registered")
        return tools[name](**kwargs)
    return _call


def _first_id(text: str) -> int | None:
    """Return the first numeric [ID:<n>] from a tool's formatted string."""
    if not isinstance(text, str):
        return None
    match = ID_PATTERN.search(text)
    return int(match.group(1)) if match else None


def _sample_via_list(call, list_tool: str, label: str, **kwargs) -> int:
    """Call a list_* tool and pull the first [ID:N] out of the response.

    Skips the test (and any dependent test) with a clear message if the tenant
    has zero records of that type.
    """
    response = call(list_tool, **kwargs)
    if isinstance(response, str) and response.startswith("Error"):
        pytest.skip(f"{list_tool} returned error: {response!r}")
    sample = _first_id(response)
    if sample is None:
        pytest.skip(f"no {label} returned by {list_tool} in this tenant")
    return sample


@pytest.fixture(scope="session")
def sample_finding_id(live_env, call) -> int:
    return _sample_via_list(call, "search_findings", "findings", page_size=5)


@pytest.fixture(scope="session")
def sample_retestable_finding_id(live_env, call) -> int:
    """Return the first finding that can be retested (remaining > 0, no active retest)."""
    response = call("search_findings", page_size=30)
    if isinstance(response, str) and response.startswith("Error"):
        pytest.skip(f"search_findings returned error: {response!r}")

    ids = ID_PATTERN.findall(response)
    if not ids:
        pytest.skip("no findings returned by search_findings")

    for fid_str in ids:
        fid = int(fid_str)
        details = call("get_finding_details", finding_id=fid)
        if not isinstance(details, str) or details.startswith("Error"):
            continue
        remaining = None
        for line in details.splitlines():
            stripped = line.strip()
            if stripped.startswith("Retests Remaining:"):
                try:
                    remaining = int(stripped.split(":", 1)[1].strip())
                except ValueError:
                    pass
                break
        if not remaining or remaining <= 0:
            continue
        if any("Current Retest:" in line for line in details.splitlines()):
            continue
        return fid

    pytest.skip("no retestable finding found in this tenant (remaining=0 or active retest on all)")


@pytest.fixture(scope="session")
def sample_hunt_id(live_env, call) -> int:
    return _sample_via_list(call, "search_hunts", "hunts", page_size=5)



_HUNT_TITLE_PATTERN = re.compile(r"\[ID:\d+\]\s+(.+?)\s+-\s+")


@pytest.fixture(scope="session")
def sample_hunt_title(live_env, call) -> str:
    """Return a real hunt title from the tenant to drive capability search.

    capability_search matches hunts by title, so we derive the query from an
    actual hunt instead of hardcoding a term that may not exist in the tenant.
    Skips when the tenant has no hunts or no title >= 3 chars (DTO min length).
    """
    response = call("search_hunts", page_size=30)
    if isinstance(response, str) and response.startswith("Error"):
        pytest.skip(f"search_hunts returned error: {response!r}")

    for title in _HUNT_TITLE_PATTERN.findall(response or ""):
        title = title.strip()
        if len(title) >= 3 and title.lower() != "unnamed":
            return title

    pytest.skip("no hunt with a usable title (>=3 chars) found in this tenant")


@pytest.fixture(scope="session")
def sample_bu_id(live_env, call) -> int:
    return _sample_via_list(call, "list_business_units", "business units")


@pytest.fixture(scope="session")
def sample_domain_id(live_env, call) -> int:
    return _sample_via_list(call, "list_asset_domains", "domains", page_size=5)


@pytest.fixture(scope="session")
def sample_subdomain_id(live_env, call) -> int:
    return _sample_via_list(call, "list_asset_subdomains", "subdomains", page_size=5)


@pytest.fixture(scope="session")
def sample_ip_id(live_env, call) -> int:
    return _sample_via_list(call, "list_asset_ips", "IP addresses", page_size=5)


@pytest.fixture(scope="session")
def sample_port_id(live_env, call) -> int:
    return _sample_via_list(call, "list_asset_ports", "ports", page_size=5)


@pytest.fixture(scope="session")
def sample_iprange_id(live_env, call) -> int:
    return _sample_via_list(call, "list_asset_ip_ranges", "IP ranges", page_size=5)


@pytest.fixture(scope="session")
def sample_cert_id(live_env, call) -> int:
    return _sample_via_list(call, "list_certificates", "certificates", page_size=5)


@pytest.fixture(scope="session")
def sample_cloud_storage_id(live_env, call) -> int:
    return _sample_via_list(call, "list_cloud_storage_assets", "cloud storage", page_size=5)


@pytest.fixture(scope="session")
def sample_repo_id(live_env, call) -> int:
    return _sample_via_list(call, "list_source_code_repositories", "repositories", page_size=5)


@pytest.fixture(scope="session")
def sample_container_id(live_env, call) -> int:
    return _sample_via_list(call, "list_container_assets", "containers", page_size=5)


@pytest.fixture(scope="session")
def sample_saas_id(live_env, call) -> int:
    return _sample_via_list(call, "list_saas_platforms", "SaaS platforms", page_size=5)


@pytest.fixture(scope="session")
def sample_mobile_id(live_env, call) -> int:
    return _sample_via_list(call, "list_mobile_app_assets", "mobile apps", page_size=5)


@pytest.fixture(scope="session")
def sample_susp_domain_id(live_env, call) -> int:
    return _sample_via_list(call, "list_suspicious_domains", "suspicious domains", page_size=5)


@pytest.fixture(scope="session")
def sample_cloud_asset_id(live_env, call) -> int:
    return _sample_via_list(call, "list_cloud_assets", "cloud assets", page_size=5)


@pytest.fixture(scope="session")
def sample_api_documentation_id(live_env, call) -> int:
    return _sample_via_list(call, "list_api_documentations", "api documentations", page_size=5)


@pytest.fixture(scope="session")
def sample_package_manager_id(live_env, call) -> int:
    return _sample_via_list(call, "list_package_managers", "package managers", page_size=5)


@pytest.fixture(scope="session")
def sample_adversary_id(live_env, call) -> int:
    return _sample_via_list(call, "list_adversary_intelligence", "adversary profiles", page_size=5)


# @pytest.fixture(scope="session")
# def sample_compromised_endpoint_id(live_env, call) -> int:
#     return _sample_via_list(call, "list_compromised_endpoints", "compromised endpoints", page_size=5)

