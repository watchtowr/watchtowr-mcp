"""Verify `apply_watchtowr_sdk_compat_patches()` runs cleanly and the patched
models actually accept the payload shapes the live Platform returns (nullable
`completed_at`/`evidence`, missing `previous`/`next` on edge pages, etc.)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from watchtowr_mcp_server.sdk_compat import (
    FindingRetestResponseDtoCompat,
    apply_watchtowr_sdk_compat_patches,
)


@pytest.fixture(scope="module", autouse=True)
def _patches_applied():
    apply_watchtowr_sdk_compat_patches()


def test_retest_dto_accepts_null_completed_at_and_evidence():
    dto = FindingRetestResponseDtoCompat.from_dict({
        "requested_by": "tester",
        "requested_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "retest_status": "started",
        "status_occurred_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "completed_at": None,
        "evidence": None,
    })
    assert dto is not None
    assert dto.completed_at is None
    assert dto.evidence is None


def test_retest_dto_rejects_unknown_status():
    with pytest.raises(Exception):
        FindingRetestResponseDtoCompat.from_dict({
            "requested_by": "tester",
            "requested_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "retest_status": "completely-made-up",
            "status_occurred_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        })


def test_patched_link_accepts_null_previous_and_next():
    """First/last page responses set Link.previous / Link.next to null."""
    from watchtowr_api_sdk.models.link import Link
    link = Link.from_dict({"first": "?page=1", "last": "?page=5", "previous": None, "next": None})
    assert link is not None
    assert link.previous is None
    assert link.next is None


def test_client_finding_from_dict_handles_minimal_payload():
    """The patched ClientFinding.from_dict uses model_construct and should
    accept a payload with just an id, mirroring what some endpoints return."""
    from watchtowr_api_sdk.models.client_finding import ClientFinding
    finding = ClientFinding.from_dict({"id": 1234})
    assert finding is not None
    assert finding.id == 1234


def test_patches_are_idempotent():
    """Calling apply_*_patches a second time must not error."""
    apply_watchtowr_sdk_compat_patches()
    apply_watchtowr_sdk_compat_patches()


def test_client_ip_schema_accepts_string_id():
    """Generated ClientIp schema should accept string IDs returned by the Platform."""
    from watchtowr_api_sdk.models.client_ip import ClientIp
    # Minimal payload matching the ClientIp model requirements
    ip_payload = {
        "type": "ip",
        "source": "manual",
        "status": "verified",
        "created_at": "2026-05-29T16:10:47Z",
        "id": "79985",
        "name": "1.2.3.4",
        "businessUnits": [],
        "country": "SG",
        "live": True,
        "metadata": {},
        "customProperties": [],

        "engineSettings": {
            "adversarySightEnabled": True,
            "automatedRedTeamingEnabled": True,
            "credentialStuffingEnabled": True,
            "dnsBruteforcingEnabled": False,
            "rapidReactionEnabled": True,
            "intrusiveHttpChecksEnabled": False
        }
    }
    client_ip = ClientIp.from_dict(ip_payload)
    assert client_ip is not None
    assert client_ip.id == "79985"


