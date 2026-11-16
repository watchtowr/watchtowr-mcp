import ipaddress
import logging
from collections.abc import Sequence

from fastmcp import FastMCP
from fastmcp.server.transforms import Transform
from fastmcp.tools import Tool
from mcp.types import ToolAnnotations

from . import __version__
from .client import env_value, read_only_mode_enabled, warn_if_read_only_value_is_unrecognised
from .constants import READ_ONLY
from .http_security import build_http_middleware
from .middleware import RequestHeadersMiddleware
from .parameter_docs import ParameterDocs
from .sdk_compat import apply_watchtowr_sdk_compat_patches
from .tools import register_all_tools
from .tools.assets.core import READ_ONLY_ACTIONS

logger = logging.getLogger(__name__)

SERVER_INSTRUCTIONS = (
    'Answer exposure questions ("are we affected by CVE-X?", "is adversary Y a risk to us?") with exactly '
    "one of these verdicts. "
    "For a CVE, call search_findings with only cve first: it prints the verdict and the affected assets. "
    "If it prints No evidence found, call get_vulnerability_intelligence_details with the CVE ID to check "
    "whether watchTowr tracks the CVE. "
    "Confirmed affected: a tool printed it, meaning the platform has Confirmed findings at the "
    "organization's impact threshold in the caller's business units (status up to 15 minutes old). "
    "Possibly exposed: only when you show a technology or version match from asset data; no tool prints it. "
    "No evidence found: a tool printed it, meaning nothing Confirmed was found; it is not proof of safety. "
    "Check incomplete: a tool printed it or returned an error; there is no verdict. "
    'Never say "not affected" in an exposure answer. '
    "If a tool says watchTowr does not track the vulnerability or adversary, say so and give no verdict. "
    'A line starting "Incomplete:" means that part of the answer failed or timed out; '
    "never report the missing part as none. "
    'A total written as "at least N" leaves out the parts that failed; never report it as exact. '
    "Tools return at most 30 results per call (asset list tools: 100), so never ask for a larger page_size; "
    'tools with a page parameter return later pages, and a list longer than one page ends with a "Page N of M" line. '
    "Call first: get_attack_surface_summary for an overview of the attack surface; "
    'get_attack_surface_delta for what is new or most recent in the last N days.'
)


def with_read_action_only(tool: Tool) -> Tool:
    read = READ_ONLY_ACTIONS[tool.name]
    properties = {name: schema for name, schema in tool.parameters["properties"].items() if name in read.parameters}
    properties["action"] = {
        **properties["action"], "enum": [read.action], "default": read.action, "description": read.action_description,
    }
    return tool.model_copy(update={
        "title": read.title,
        "description": read.description,
        "parameters": {**tool.parameters, "properties": properties},
        "annotations": ToolAnnotations(**READ_ONLY),
    })


class ReadOnlyActions(Transform):
    """In read-only mode, lists each mixed read/write tool with only its read action and a read-only annotation."""

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        return [with_read_action_only(tool) if tool.name in READ_ONLY_ACTIONS else tool for tool in tools]


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _http_port() -> int:
    raw = env_value("PORT") or "8080"
    try:
        port = int(raw)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise ValueError(f"PORT must be a whole number from 1 to 65535, got {raw!r}")
    return port


def create_server() -> FastMCP:
    apply_watchtowr_sdk_compat_patches()
    mcp = FastMCP(
        "watchtowr",
        version=__version__,
        website_url="https://watchtowr.com",
        instructions=SERVER_INSTRUCTIONS,
        mask_error_details=True,
    )
    register_all_tools(mcp)
    mcp.add_transform(ParameterDocs())
    mcp.add_middleware(RequestHeadersMiddleware())
    warn_if_read_only_value_is_unrecognised()
    if read_only_mode_enabled():
        mcp.disable(tags={"write"})
        mcp.add_transform(ReadOnlyActions())
    return mcp


def main():
    mcp = create_server()

    transport = env_value("MCP_TRANSPORT") or "stdio"

    if transport == "streamable-http":
        host = env_value("MCP_HOST") or "127.0.0.1"
        port = _http_port()
        if not _is_loopback(host):
            logger.warning(
                "Binding streamable-http to non-loopback host %s: anyone who can reach port %d "
                "can call this server with their own API key. Put it behind TLS and restrict "
                "network access.",
                host,
                port,
            )
        mcp.run(
            transport="streamable-http",
            host=host,
            port=port,
            path="/mcp",
            stateless_http=True,
            middleware=build_http_middleware(),
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
