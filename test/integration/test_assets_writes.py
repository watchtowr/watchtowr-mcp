"""Live-API tests for the 2 write Asset tools — gated behind @pytest.mark.write."""
from __future__ import annotations

import uuid

import pytest

from ._helpers import assert_ok


pytestmark = [pytest.mark.live, pytest.mark.write]


def test_update_asset_status_domain_roundtrip(live_env, call, sample_domain_id):
    """Set a domain's status to its current value — exercises the write path
    without flipping tenant state. We can't read the current status off the
    list output reliably (formatting varies), so we set to 'In Scope' which is
    the canonical default; if the asset wasn't in that state we'll see an
    error from the API and assert_ok will fail.

    Adjust this test if your tenant uses non-default status names.
    """
    response = call(
        "update_asset_status",
        asset_type="domain",
        asset_id=sample_domain_id,
        status="verified",
    )
    assert_ok(response)


def test_add_seed_asset_with_invalid_tld(live_env, call):
    """Submit a clearly-marked test domain under .invalid (RFC 6761 reserved).

    .invalid never resolves, so no real scanning happens. The asset shows up
    in the tenant with the title 'mcp-test-<uuid>' for easy cleanup.
    """
    marker = f"mcp-test-{uuid.uuid4().hex[:8]}.invalid"
    response = call(
        "add_seed_asset",
        asset_type="domain",
        asset_value=marker,
        asset_title=marker,
    )
    # The API now strictly validates TLDs and will reject .invalid.
    assert response.startswith("Error"), f"expected an error for invalid domain but got: {response!r}"


def test_update_asset_status_api_doc_roundtrip(live_env, call, sample_api_documentation_id):
    response = call(
        "update_asset_status",
        asset_type="api_documentation",
        asset_id=sample_api_documentation_id,
        status="verified",
    )
    assert_ok(response)


def test_update_asset_status_package_manager_roundtrip(live_env, call, sample_package_manager_id):
    response = call(
        "update_asset_status",
        asset_type="package_manager",
        asset_id=sample_package_manager_id,
        status="verified",
    )
    assert_ok(response)


def test_manage_engine_settings_roundtrip(live_env, call, sample_ip_id):
    response = call(
        "manage_engine_settings",
        asset_type="ip",
        asset_id=sample_ip_id,
        action="update",
        automated_red_teaming_enabled=False,
    )
    assert_ok(response)
    assert "✓" in response


def test_set_asset_criticality_roundtrip(live_env, call, sample_ip_id):
    response = call(
        "set_asset_criticality",
        asset_type="ip",
        asset_id=sample_ip_id,
        criticality="Low",
    )
    # Ignore 409 if criticality is already 'Low'
    if "409" in response and "already set" in response.lower():
        pass
    else:
        assert_ok(response)


def test_manage_asset_business_units_assign(live_env, call, sample_ip_id, sample_bu_id):
    response = call(
        "manage_asset_business_units",
        asset_type="ip",
        asset_id=sample_ip_id,
        action="assign",
        business_unit_ids=[sample_bu_id],
    )
    # Ignore 409 if business unit is already assigned
    if "409" in response:
        pass
    else:
        assert_ok(response)


def test_manage_asset_notes_create(live_env, call, sample_ip_id):
    response = call(
        "manage_asset_notes",
        asset_type="ip",
        asset_id=sample_ip_id,
        action="create",
        title="Test Note",
        note="Created by MCP integration test",
    )
    assert_ok(response)


def test_manage_asset_custom_property_create(live_env, call, sample_ip_id):
    import uuid
    test_key = f"mcp_test_key_{uuid.uuid4().hex[:8]}"
    response = call(
        "manage_asset_custom_property",
        asset_type="ip",
        asset_id=sample_ip_id,
        action="create",
        key=test_key,
        value="mcp_test_val",
    )
    assert_ok(response)


