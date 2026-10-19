from __future__ import annotations

import asyncio
import inspect

import pytest

from watchtowr_mcp_server.mcp import create_server
from watchtowr_mcp_server.parameter_docs import split_args_section


@pytest.fixture
def listed_tools():
    return asyncio.run(create_server().list_tools())


def test_every_tool_parameter_has_a_description(listed_tools):
    undescribed = [
        f"{tool.name}.{name}"
        for tool in listed_tools
        for name, schema in (tool.parameters.get("properties") or {}).items()
        if not schema.get("description")
    ]

    assert not undescribed, f"add an Args: entry to the tool's docstring for {undescribed}"


def test_every_args_entry_names_a_tool_parameter(listed_tools):
    orphaned = [
        f"{tool.name}.{name}"
        for tool in listed_tools
        for name in split_args_section(inspect.getdoc(tool.fn) or "")[1]
        if name not in (tool.parameters.get("properties") or {})
    ]

    assert not orphaned, f"remove or rename the Args: entry, it matches no parameter: {orphaned}"


def test_tool_descriptions_no_longer_repeat_the_args_section(listed_tools):
    assert not [tool.name for tool in listed_tools if "\nArgs:" in (tool.description or "")]


def test_split_args_section_joins_wrapped_entries_and_keeps_later_sections():
    docstring = (
        "List things.\n\n"
        "Args:\n"
        "    statuses: Comma-separated statuses: received,\n"
        "        in-progress.\n"
        "    page (int): Page number.\n"
        "    flag:\n"
        "        Wrapped from the first line.\n\n"
        "Returns:\n"
        "    A summary."
    )

    assert split_args_section(docstring) == (
        "List things.\n\nReturns:\n    A summary.",
        {
            "statuses": "Comma-separated statuses: received, in-progress.",
            "page": "Page number.",
            "flag": "Wrapped from the first line.",
        },
    )
