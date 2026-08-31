import os

from fastmcp import FastMCP

from .sdk_compat import apply_watchtowr_sdk_compat_patches
from .tools import register_all_tools


def main():
    apply_watchtowr_sdk_compat_patches()
    mcp = FastMCP("watchtowr")
    register_all_tools(mcp)

    transport = os.environ.get("MCP_TRANSPORT", "stdio")

    if transport == "streamable-http":
        port = int(os.environ.get("PORT", 8080))
        mcp.run(
            transport="streamable-http",
            host="0.0.0.0",
            port=port,
            path="/mcp",
            stateless_http=True,
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
