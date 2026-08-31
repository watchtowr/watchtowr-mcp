"""Static check: README's tool tables stay in sync with the @mcp.tool() registry.

If you add a new `@mcp.tool()` function but forget to document it in README.md
(or vice versa), this test fails and tells you exactly which name diverged.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"
TOOLS_DIR = REPO_ROOT / "watchtowr_mcp_server" / "tools"

# Maps the README's `### <heading>` to the matching file(s) under tools/.
# The README also tells us the expected count per category — keep these
# pairs in lockstep with the README headings.
CATEGORY_MAP = {
    "Findings": (("findings.py",), 11),
    "Assets": (("assets/core.py", "assets/changelog.py", "assets/dns.py"), 38),
    "Hunts": (("hunts.py",), 6),
    "Threat Intelligence": (("threat_intel.py",), 7),
    "Services": (("services.py",), 2),
    "Organisation": (("organization.py",), 5),
    "Composite & Triage": (("composite.py",), 13),
    "Reporting & Compliance": (("reporting.py",), 12),
    "Incident Response": (("incident.py",), 5),
    "Workflow & Automation": (("workflow.py",), 6),
    "Intelligence": (("intelligence.py",), 8),
}


def _readme_tool_names() -> set[str]:
    """Pull every `tool_name` from markdown table rows in the README."""
    text = README_PATH.read_text()
    # A tool row in the README looks like:
    #   | `tool_name` | Description |
    # Pull the backticked identifier as long as it's snake_case (so we
    # ignore environment-variable rows like `WATCHTOWR_API_KEY`).
    pattern = re.compile(r"^\|\s*`([a-z_][a-z0-9_]*)`\s*\|", re.MULTILINE)
    return set(pattern.findall(text))


def _tool_names_in_file(path: Path) -> set[str]:
    """Every function inside a register_*_tools function that has @mcp.tool()."""
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            # Match @mcp.tool() (a Call whose .func is an Attribute named 'tool').
            target = deco.func if isinstance(deco, ast.Call) else deco
            if isinstance(target, ast.Attribute) and target.attr == "tool":
                names.add(node.name)
                break
    return names


def _tool_names_in_files(filenames: tuple[str, ...]) -> set[str]:
    out: set[str] = set()
    for filename in filenames:
        out |= _tool_names_in_file(TOOLS_DIR / filename)
    return out


def _all_code_tool_names() -> set[str]:
    out: set[str] = set()
    for filenames, _ in CATEGORY_MAP.values():
        out |= _tool_names_in_files(filenames)
    return out


def test_readme_and_code_tool_sets_match():
    readme = _readme_tool_names()
    code = _all_code_tool_names()
    missing_from_readme = code - readme
    missing_from_code = readme - code
    assert not missing_from_readme, (
        f"{len(missing_from_readme)} tool(s) implemented but not documented in "
        f"README.md: {sorted(missing_from_readme)}"
    )
    assert not missing_from_code, (
        f"{len(missing_from_code)} tool(s) listed in README.md but not "
        f"implemented: {sorted(missing_from_code)}"
    )


@pytest.mark.parametrize("category,filenames,expected", [
    (cat, fns, n) for cat, (fns, n) in CATEGORY_MAP.items()
])
def test_category_tool_count_matches_readme_heading(category, filenames, expected):
    actual = len(_tool_names_in_files(filenames))
    assert actual == expected, (
        f"README claims '{category} ({expected} tools)' but {', '.join(filenames)} "
        f"defines {actual} @mcp.tool() functions."
    )


def test_total_tool_count_is_113():
    """README.md line 7 claims '113 tools'."""
    total = sum(len(_tool_names_in_files(fns)) for fns, _ in CATEGORY_MAP.values())
    assert total == 113, f"Expected 113 tools across all categories, found {total}"
