from __future__ import annotations

import asyncio
import json

from fastmcp import Client

from watchtowr_mcp_server.mcp import create_server


TOOL_LIST_BASELINE_CHARS = 84100
ALLOWED_DRIFT = 0.05


def _tool_list_chars() -> int:
    async def _list():
        async with Client(create_server()) as mcp_client:
            return await mcp_client.list_tools()

    tool_list = [
        {"name": tool.name, "description": tool.description, "inputSchema": tool.inputSchema}
        for tool in asyncio.run(_list())
    ]
    return len(json.dumps(tool_list, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def test_tool_list_sent_to_the_model_stays_within_budget():
    size = _tool_list_chars()
    budget = int(TOOL_LIST_BASELINE_CHARS * (1 + ALLOWED_DRIFT))
    floor = int(TOOL_LIST_BASELINE_CHARS * (1 - ALLOWED_DRIFT))

    assert size <= budget, (
        f"Tool names, descriptions and input schemas now take {size} chars, over the {budget}-char "
        f"budget ({TOOL_LIST_BASELINE_CHARS} + {ALLOWED_DRIFT:.0%}). Every MCP session sends them "
        f"to the model. Trim the growth, or set TOOL_LIST_BASELINE_CHARS to {size} in this test."
    )
    assert size >= floor, (
        f"Tool names, descriptions and input schemas shrank to {size} chars, under the {floor}-char "
        f"floor ({TOOL_LIST_BASELINE_CHARS} - {ALLOWED_DRIFT:.0%}). Set TOOL_LIST_BASELINE_CHARS to "
        f"{size} in this test, so the trimmed chars don't become free headroom."
    )
