from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

import pytest

from test.unit.conftest import JsonReply, page_of


def test_note_last_modified_prints_the_date_not_the_sdk_wrapper(tools, fake_platform):
    fake_platform.route(r"/assets/domain/show/[^/]+/notes$", JsonReply(page_of([{
        "id": 7,
        "note": "Example note",
        "note_type": "domain",
        "note_id": 1,
        "title": "Example title",
        "author": {"id": 1, "name": "Example Author"},
        "last_modified": "2026-10-01T00:00:00Z",
    }])))

    out = tools["manage_asset_notes"](asset_type="domain", asset_id=1, action="list")

    assert "(by Example Author, 2026-10-01 00:00:00+00:00)" in out
    assert "oneof_schema" not in out
    assert "actual_instance" not in out


@pytest.mark.parametrize("tool_name", ["manage_asset_notes", "manage_asset_custom_property"])
def test_list_action_caps_page_size_at_30(tool_name, tools, fake_platform):
    fake_platform.route(r"/assets/domain/show/[^/]+/", JsonReply(page_of([])))

    tools[tool_name](asset_type="domain", asset_id=1, action="list", page_size=100)

    assert ("pageSize", "30.0") in parse_qsl(urlsplit(fake_platform.requested_urls[0]).query)
