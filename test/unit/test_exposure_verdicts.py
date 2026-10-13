from __future__ import annotations

import asyncio
from typing import Callable, NamedTuple

import pytest
import urllib3
from fastmcp import Client
from fastmcp.exceptions import ToolError

from test.unit.conftest import JsonReply, page_of
from watchtowr_mcp_server.mcp import create_server


VERDICTS = ("Confirmed affected", "Possibly exposed", "No evidence found", "Check incomplete")
BANNED_PHRASES = ("affected: no", "not affected")


class ExposureTool(NamedTuple):
    arguments: dict
    path: str
    body: Callable[[dict], dict]


EXPOSURE_TOOLS = {
    "list_vulnerability_intelligence": ExposureTool(
        {"search": "CVE-2023-27350"},
        r"/vulnerability-intelligence/list$",
        lambda flag: page_of([{"vulnerabilityId": 1.0, "type": "CVE", "displayName": "CVE-2023-27350 example", **flag}]),
    ),
    "get_vulnerability_intelligence_details": ExposureTool(
        {"identifier": "CVE-2023-27350"},
        r"/vulnerability-intelligence/show/",
        lambda flag: {"data": {
            "vulnerabilityId": 1.0,
            "cveId": "CVE-2023-27350",
            "displayName": "CVE-2023-27350 example",
            "affectedKbEntryIds": [],
            **flag,
        }},
    ),
    "list_adversary_intelligence": ExposureTool(
        {"search": "Example Adversary"},
        r"/adversary-intelligence/list$",
        lambda flag: page_of([{"attackerId": 1.0, "name": "Example Adversary", "type": "APT", **flag}]),
    ),
    "get_adversary_intelligence_details": ExposureTool(
        {"attacker_id": 1},
        r"/adversary-intelligence/show/",
        lambda flag: {"data": {"attackerId": 1.0, "name": "Example Adversary", "affectedKbEntryIds": [], **flag}},
    ),
}

FLAG_CASES = {
    "is_affected_true": ({"isAffected": True}, "Confirmed affected"),
    "is_affected_false": ({"isAffected": False}, "No evidence found"),
    "is_affected_missing": ({}, "Check incomplete"),
    "is_affected_null": ({"isAffected": None}, "Check incomplete"),
}

TOOLS_WHOSE_SDK_MODEL_REQUIRES_IS_AFFECTED = {
    "get_vulnerability_intelligence_details",
    "list_adversary_intelligence",
    "get_adversary_intelligence_details",
}

SCOPE_WORDING = {
    "Confirmed affected": ("impact threshold", "business units", "15 minutes"),
    "No evidence found": ("impact threshold", "business units", "15 minutes"),
    "Check incomplete": (),
}


def _assert_no_banned_phrase(answer: str) -> None:
    for phrase in BANNED_PHRASES:
        assert phrase not in answer.lower(), f"{phrase!r} in:\n{answer}"


@pytest.mark.parametrize("flag_case", sorted(FLAG_CASES))
@pytest.mark.parametrize("tool_name", sorted(EXPOSURE_TOOLS))
def test_is_affected_flag_answers_with_one_verdict(tool_name, flag_case, tools, fake_platform):
    tool = EXPOSURE_TOOLS[tool_name]
    flag, expected_verdict = FLAG_CASES[flag_case]
    fake_platform.route(tool.path, JsonReply(tool.body(flag)))

    if flag_case in {"is_affected_missing", "is_affected_null"} and tool_name in TOOLS_WHOSE_SDK_MODEL_REQUIRES_IS_AFFECTED:
        with pytest.raises(ToolError) as raised:
            tools[tool_name](**tool.arguments)
        answer = str(raised.value)
        assert answer.startswith("Check incomplete: ")
    else:
        answer = tools[tool_name](**tool.arguments)

    assert expected_verdict in answer
    for other_verdict in VERDICTS:
        if other_verdict != expected_verdict:
            assert other_verdict not in answer
    for scope_wording in SCOPE_WORDING[expected_verdict]:
        assert scope_wording in answer
    assert len(fake_platform.requested_urls) == 1
    _assert_no_banned_phrase(answer)


@pytest.mark.parametrize("tool_name", sorted(EXPOSURE_TOOLS))
def test_failed_call_raises_check_incomplete_naming_the_call(tool_name, tools, fake_platform):
    tool = EXPOSURE_TOOLS[tool_name]
    fake_platform.route(tool.path, JsonReply({"message": "Server Error"}, status=500))

    with pytest.raises(ToolError) as raised:
        tools[tool_name](**tool.arguments)

    answer = str(raised.value)
    assert answer.startswith("Check incomplete:")
    assert "intelligence" in answer
    assert "HTTP 500" in answer
    assert "Confirmed affected" not in answer
    assert "No evidence found" not in answer
    _assert_no_banned_phrase(answer)


def test_timed_out_call_raises_check_incomplete_with_the_timeout(tools, fake_platform):
    fake_platform.route(
        r"/vulnerability-intelligence/show/",
        urllib3.exceptions.ReadTimeoutError(None, "/api", "read timed out"),
    )

    with pytest.raises(ToolError) as raised:
        tools["get_vulnerability_intelligence_details"](identifier="CVE-2023-27350")

    assert str(raised.value) == (
        "Check incomplete: the vulnerability intelligence details call failed: "
        "no answer from the watchTowr Platform within 30 seconds - try a narrower query, or raise WATCHTOWR_MCP_REQUEST_TIMEOUT. "
        "There is no exposure verdict."
    )


def test_failed_call_reaches_the_mcp_client_as_an_error_result(fake_platform):
    fake_platform.route(r"/vulnerability-intelligence/show/", JsonReply({"message": "Forbidden"}, status=403))

    async def call_details():
        async with Client(create_server()) as client:
            return await client.call_tool(
                "get_vulnerability_intelligence_details",
                {"identifier": "CVE-2023-27350"},
                raise_on_error=False,
            )

    result = asyncio.run(call_details())

    assert result.is_error
    assert result.content[0].text.startswith("Check incomplete:")
    assert "HTTP 403" in result.content[0].text


DETAILS_TOOLS = ("get_vulnerability_intelligence_details", "get_adversary_intelligence_details")


@pytest.mark.parametrize("tool_name", DETAILS_TOOLS)
def test_no_evidence_found_says_what_the_platform_reports_without_claiming_it_checked(tool_name, tools, fake_platform):
    tool = EXPOSURE_TOOLS[tool_name]
    fake_platform.route(tool.path, JsonReply(tool.body({"isAffected": False})))

    answer = tools[tool_name](**tool.arguments)

    assert "Exposure: No evidence found. The platform reports no Confirmed findings for" in answer
    assert "checked" not in answer.lower()
    assert "found none" not in answer.lower()


@pytest.mark.parametrize(
    ("tool_name", "mentions_cve_mapping"),
    [("get_vulnerability_intelligence_details", False), ("get_adversary_intelligence_details", True)],
)
def test_only_the_adversary_verdict_leaves_out_entries_with_no_cve_mapping(tool_name, mentions_cve_mapping, tools, fake_platform):
    tool = EXPOSURE_TOOLS[tool_name]
    fake_platform.route(tool.path, JsonReply(tool.body({"isAffected": False})))

    answer = tools[tool_name](**tool.arguments)

    assert ("no CVE mapping" in answer) is mentions_cve_mapping


@pytest.mark.parametrize("tool_name", ["list_vulnerability_intelligence", "list_adversary_intelligence"])
def test_search_with_no_match_says_watchtowr_does_not_track_it_and_gives_no_verdict(tool_name, tools, fake_platform):
    tool = EXPOSURE_TOOLS[tool_name]
    fake_platform.route(tool.path, JsonReply(page_of([])))

    answer = tools[tool_name](**tool.arguments)

    assert "watchTowr does not track" in answer
    assert "no exposure verdict" in answer
    for verdict in VERDICTS:
        assert verdict not in answer
    _assert_no_banned_phrase(answer)


@pytest.mark.parametrize("tool_name", DETAILS_TOOLS)
def test_details_of_an_untracked_entry_say_watchtowr_does_not_track_it(tool_name, tools, fake_platform):
    tool = EXPOSURE_TOOLS[tool_name]
    fake_platform.route(tool.path, JsonReply({"message": "Not Found"}, status=404))

    answer = tools[tool_name](**tool.arguments)

    assert "watchTowr does not track" in answer
    for verdict in VERDICTS:
        assert verdict not in answer


@pytest.mark.parametrize(
    "arguments",
    [{"page": 2, "search": "CVE-2023-27350"}, {}],
    ids=["page-past-the-results", "no-search"],
)
def test_an_empty_page_is_not_called_untracked_unless_a_first_page_search_found_nothing(arguments, tools, fake_platform):
    fake_platform.route(r"/vulnerability-intelligence/list$", JsonReply(page_of([])))

    answer = tools["list_vulnerability_intelligence"](**arguments)

    assert answer == "No vulnerability intelligence entries found."


def test_scope_footer_is_left_out_when_no_entry_has_a_verdict(tools, fake_platform):
    fake_platform.route(
        r"/vulnerability-intelligence/list$",
        JsonReply(page_of([{"vulnerabilityId": 1.0, "type": "CVE", "displayName": "CVE-2023-27350 example"}])),
    )

    answer = tools["list_vulnerability_intelligence"](search="CVE-2023-27350")

    assert "Check incomplete" in answer
    assert "Exposure verdicts cover" not in answer


@pytest.mark.parametrize("tool_name", DETAILS_TOOLS)
def test_no_evidence_found_says_remediated_and_closed_findings_are_not_counted(tool_name, tools, fake_platform):
    tool = EXPOSURE_TOOLS[tool_name]
    fake_platform.route(tool.path, JsonReply(tool.body({"isAffected": False})))

    assert "remediated or closed findings" in tools[tool_name](**tool.arguments)


@pytest.fixture(scope="module")
def tool_descriptions() -> dict[str, str]:
    return {tool.name: tool.description or "" for tool in asyncio.run(create_server().list_tools())}


@pytest.mark.parametrize("tool_name", sorted(EXPOSURE_TOOLS))
def test_exposure_tool_description_states_the_verdict_rule(tool_name, tool_descriptions):
    description = tool_descriptions[tool_name]

    for verdict in VERDICTS:
        assert verdict in description, f"{verdict!r} missing from {tool_name} description"
    assert "never say" in description.lower()
    assert "technology or version match" in description


def test_server_instructions_name_every_verdict():
    instructions = create_server().instructions or ""

    for verdict in VERDICTS:
        assert verdict in instructions, f"{verdict!r} missing from server instructions"
    assert "not affected" in instructions
    assert "technology or version match" in instructions
    assert "does not track" in instructions
    assert 'Never say "not affected" in an exposure answer' in instructions
