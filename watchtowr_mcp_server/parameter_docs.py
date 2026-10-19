import re
from collections.abc import Sequence

from fastmcp.server.transforms import Transform
from fastmcp.tools import Tool

ARGS_HEADER = "\nArgs:\n"
ARG_ENTRY = re.compile(r"^    (\w+)(?: \([^)]*\))?:\s*(.*)$")


def split_args_section(description: str) -> tuple[str, dict[str, str]]:
    summary, found, section = description.partition(ARGS_HEADER)
    if not found:
        return description, {}
    lines = section.splitlines()
    end = next((i for i, line in enumerate(lines) if line and not line.startswith(" ")), len(lines))
    docs: dict[str, str] = {}
    name = None
    for line in lines[:end]:
        entry = ARG_ENTRY.match(line)
        if entry:
            name, text = entry.groups()
            docs[name] = text
        elif name and line.strip():
            docs[name] = f"{docs[name]} {line.strip()}".strip()
    after_args = "\n".join(lines[end:]).strip()
    return "\n\n".join(part for part in (summary.rstrip(), after_args) if part), docs


def with_parameter_docs(tool: Tool) -> Tool:
    description, docs = split_args_section(tool.description or "")
    properties = tool.parameters.get("properties")
    if properties is None:
        return tool.model_copy(update={"description": description})
    described = {
        name: {**schema, "description": docs[name]} if name in docs else schema
        for name, schema in properties.items()
    }
    return tool.model_copy(update={
        "description": description,
        "parameters": {**tool.parameters, "properties": described},
    })


class ParameterDocs(Transform):
    """Moves each tool's docstring `Args:` entries into its input schema, so clients see them per parameter."""

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        return [with_parameter_docs(tool) for tool in tools]
