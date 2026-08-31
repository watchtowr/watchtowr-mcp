from .core import (
    ASSET_API_CLASSES,
    BUSINESS_UNIT_METHODS,
    CRITICALITY_METHODS,
    CUSTOM_PROPERTY_METHODS,
    ENGINE_SETTINGS_METHODS,
    NOTES_METHODS,
    get_api_client,
    register_asset_core_tools,
)
from .changelog import register_asset_changelog_tools
from .dns import register_asset_dns_tools


def register_asset_tools(mcp):
    register_asset_core_tools(mcp)
    register_asset_changelog_tools(mcp)
    register_asset_dns_tools(mcp)
