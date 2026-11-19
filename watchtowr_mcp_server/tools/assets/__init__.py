from .core import register_asset_core_tools
from .changelog import register_asset_changelog_tools
from .dns import register_asset_dns_tools
from .discovery_reason import register_asset_discovery_reason_tools


def register_asset_tools(mcp):
    register_asset_core_tools(mcp)
    register_asset_changelog_tools(mcp)
    register_asset_dns_tools(mcp)
    register_asset_discovery_reason_tools(mcp)
