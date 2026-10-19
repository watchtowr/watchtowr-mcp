from __future__ import annotations

import asyncio
import inspect
import re

import watchtowr_api_sdk.api as sdk_api

from fastmcp import Client

from watchtowr_mcp_server import __version__
from watchtowr_mcp_server.mcp import create_server
from watchtowr_mcp_server.tools.assets import core as asset_tools


def _server_tools():
    return asyncio.run(create_server().list_tools())


def test_initialize_reports_package_version_and_website():
    async def _server_info():
        async with Client(create_server()) as mcp_client:
            return mcp_client.initialize_result.serverInfo

    info = asyncio.run(_server_info())

    assert info.version == __version__
    assert info.websiteUrl == "https://watchtowr.com"


def test_every_tool_has_title_and_annotations():
    tools = _server_tools()
    missing = [
        tool.name
        for tool in tools
        if not tool.title
        or tool.annotations is None
        or tool.annotations.readOnlyHint is None
        or tool.annotations.openWorldHint is not False
    ]

    assert len(tools) >= 100
    assert missing == []


def test_write_tools_are_not_read_only():
    tools = _server_tools()
    write_tools = [tool for tool in tools if "write" in tool.tags or _writes_through_an_action(tool)]

    mislabelled = [
        tool.name
        for tool in write_tools
        if tool.annotations.readOnlyHint is not False or tool.annotations.destructiveHint is None
    ]

    assert len(write_tools) >= 12
    assert mislabelled == []


def _writes_through_an_action(tool) -> bool:
    return "refuse_write_action_in_read_only_mode" in inspect.getsource(tool.fn)


def test_read_only_tools_only_call_get_endpoints():
    verbs = _sdk_method_verbs()
    method_tables = {name: table for name, table in vars(asset_tools).items() if name.endswith("_METHODS")}

    writes = []
    for tool in _server_tools():
        if not tool.annotations.readOnlyHint:
            continue
        source = inspect.getsource(tool.fn)
        called = {name for name in re.findall(r"\.(\w+)\(", source) if name in verbs}
        for table_name, table in method_tables.items():
            if table_name in source:
                called |= set(_method_names(table))
        writes += [f"{tool.name} -> {name} ({verbs[name]})" for name in called if verbs[name] != "GET"]

    assert len(verbs) > 100
    assert writes == []


def _sdk_method_verbs() -> dict[str, str]:
    verbs = {}
    for api_class in vars(sdk_api).values():
        if not inspect.isclass(api_class):
            continue
        for attr, fn in vars(api_class).items():
            serializer = re.fullmatch(r"_(\w+)_serialize", attr)
            if serializer:
                verbs[serializer.group(1)] = re.search(r"method='(\w+)'", inspect.getsource(fn)).group(1)
    return verbs


def _method_names(table):
    if isinstance(table, str):
        yield table
    elif isinstance(table, dict):
        for value in table.values():
            yield from _method_names(value)
