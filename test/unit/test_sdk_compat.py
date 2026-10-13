"""Verify `apply_watchtowr_sdk_compat_patches()` runs cleanly and the patched
models actually accept the payload shapes the live Platform returns (nullable
`completed_at`/`evidence`, missing `previous`/`next` on edge pages, etc.)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import BaseModel
from watchtowr_api_sdk.models.capability_search_hunt_item import CapabilitySearchHuntItem
from watchtowr_api_sdk.models.hunt import Hunt
from watchtowr_api_sdk.models.hunt_detail import HuntDetail

from watchtowr_mcp_server.sdk_compat import (
    NULLABLE_FIELDS,
    FindingRetestResponseDtoCompat,
    _sdk_models_embedded_in,
    accept_null_field,
    apply_watchtowr_sdk_compat_patches,
    models_embedding,
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


def _domain_payload(whois_fields: dict) -> dict:
    return {
        "type": "domain",
        "source": "manual",
        "status": "verified",
        "created_at": "2026-05-29T16:10:47Z",
        "id": "101",
        "name": "example.com",
        "businessUnits": [],
        "live": True,
        "whoisData": [{"id": 1, "data": whois_fields, "raw": ""}],
        "dns_records": [],
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


def test_client_domain_accepts_whois_fields_the_sdk_does_not_define():
    from watchtowr_api_sdk.models.client_domain import ClientDomain

    domain = ClientDomain.from_dict(_domain_payload({
        "domain_name": "example.com",
        "registrar": "Example Registrar",
        "reseller": "Example Reseller",
        "updated_date": "2026-01-01",
    }))
    assert domain.whois_data[0].data.registrar == "Example Registrar"


def test_suspicious_domain_accepts_whois_message_and_list_dnssec():
    from watchtowr_api_sdk.models.suspicious_domain import SuspiciousDomain

    suspicious_domain = SuspiciousDomain.from_dict({
        "id": 7,
        "name": "example.net",
        "discovery_reason": "Lookalike",
        "status": "pending",
        "whoisData": [{
            "id": 1,
            "data": {
                "domain_name": "example.net",
                "message": "No match for domain",
                "dnssec": ["signedDelegation", "unsigned"],
            },
            "raw": "",
        }],
    })
    assert suspicious_domain.whois_data[0].data.to_dict()["dnssec"] == "signedDelegation, unsigned"


PAGINATION_META = {
    "pagination": {
        "total": 1,
        "count": 1,
        "per_page": 30,
        "current_page": 1,
        "total_pages": 1,
        "links": {"previous": None, "next": None},
    }
}


def _hunt_payload(hunt_request_type) -> dict:
    return {
        "id": 42,
        "type": "bespoke",
        "created_at": "2026-05-29T16:10:47Z",
        "updated_at": "2026-05-29T16:10:47Z",
        "total_findings": 0,
        "total_assets": 1,
        "hunt_request_type": hunt_request_type,
        "rapid_exposure_mechanism": None,
        "title": "Example hunt",
        "status": "completed",
    }


def _hunt_detail_payload(hunt_request_type) -> dict:
    return {
        **_hunt_payload(hunt_request_type),
        "description": "Example description",
        "hypothesis": None,
        "references": [],
        "completed_at": None,
        "completed_by": None,
        "requested_by": None,
    }


def _engine_settings(intrusive_http_checks_enabled) -> dict:
    return {
        "adversarySightEnabled": True,
        "automatedRedTeamingEnabled": True,
        "credentialStuffingEnabled": True,
        "dnsBruteforcingEnabled": False,
        "rapidReactionEnabled": True,
        "intrusiveHttpChecksEnabled": intrusive_http_checks_enabled,
    }


def test_paginated_hunts_accepts_a_hunt_with_null_hunt_request_type():
    from watchtowr_api_sdk.models.paginated_hunts import PaginatedHunts

    hunts = PaginatedHunts.from_dict({
        "data": [_hunt_payload("Misconfig"), _hunt_payload(None)],
        "meta": PAGINATION_META,
    })
    assert [hunt.hunt_request_type for hunt in hunts.data] == ["Misconfig", None]


def test_hunt_detail_accepts_null_hunt_request_type():
    from watchtowr_api_sdk.models.hunt_detail_response import HuntDetailResponse

    response = HuntDetailResponse.from_dict({"data": _hunt_detail_payload(None)})
    assert response.data.hunt_request_type is None


def test_capability_search_hunt_item_accepts_null_hunt_request_type():
    from watchtowr_api_sdk.models.capability_search_data import CapabilitySearchData

    data = CapabilitySearchData.from_dict({
        "hunts": [{**_hunt_payload(None), "cve_ids": ["CVE-2021-44228"]}],
        "ttp_library": [],
    })
    assert data.hunts[0].hunt_request_type is None


@pytest.mark.parametrize(("model_class", "payload"), [
    (Hunt, _hunt_payload("NotARequestType")),
    (HuntDetail, _hunt_detail_payload("NotARequestType")),
    (CapabilitySearchHuntItem, {**_hunt_payload("NotARequestType"), "cve_ids": []}),
])
def test_hunt_request_type_still_rejects_values_outside_the_sdk_enum(model_class, payload):
    with pytest.raises(ValueError):
        model_class.from_dict(payload)


def test_hunt_assets_list_accepts_null_intrusive_http_checks_enabled():
    from watchtowr_api_sdk.models.assets_list_response import AssetsListResponse

    assets = AssetsListResponse.from_dict({
        "data": [{
            "id": 7,
            "created_at": "2026-05-29T16:10:47Z",
            "source": "manual",
            "type": "ip",
            "status": "verified",
            "name": "192.0.2.10",
            "country": None,
            "platform": None,
            "provider": None,
            "url": None,
            "businessUnits": [],
            "discovery_reason": None,
            "owner": None,
            "live": True,
            "sub_type": None,
            "super_type": None,
            "metadata": {},
            "engineSettings": _engine_settings(None),
        }],
        "meta": PAGINATION_META,
    })
    assert assets.data[0].engine_settings.intrusive_http_checks_enabled is None


def test_client_ip_accepts_null_intrusive_http_checks_enabled():
    from watchtowr_api_sdk.models.client_ip import ClientIp

    client_ip = ClientIp.from_dict({
        "type": "ip",
        "source": "manual",
        "status": "verified",
        "created_at": "2026-05-29T16:10:47Z",
        "id": "7",
        "name": "192.0.2.10",
        "businessUnits": [],
        "country": "US",
        "live": True,
        "metadata": {},
        "customProperties": [],
        "engineSettings": _engine_settings(None),
    })
    assert client_ip.engine_settings.intrusive_http_checks_enabled is None


def test_engine_settings_details_accepts_null_intrusive_http_checks_enabled():
    from watchtowr_api_sdk.models.client_engine_settings_data import ClientEngineSettingsData

    settings = ClientEngineSettingsData.from_dict({
        "data": {**_engine_settings(None), "id": 7, "type": "ip"},
    })
    assert settings.data.intrusive_http_checks_enabled is None


def test_intrusive_http_checks_enabled_still_rejects_non_bool_values():
    from watchtowr_api_sdk.models.client_engine_settings import ClientEngineSettings

    with pytest.raises(ValueError):
        ClientEngineSettings.from_dict(_engine_settings("yes"))


@pytest.mark.parametrize(("model_name", "payload"), [
    ("PaginatedHunts", {"data": [_hunt_payload(None)], "meta": PAGINATION_META}),
    ("HuntDetailResponse", {"data": _hunt_detail_payload(None)}),
    ("CapabilitySearchData", {"hunts": [{**_hunt_payload(None), "cve_ids": []}], "ttp_library": []}),
    ("ClientEngineSettingsData", {"data": {**_engine_settings(None), "id": 7, "type": "ip"}}),
])
def test_models_embedding_a_nullable_field_accept_null_when_validated_from_a_dict(model_name, payload):
    import watchtowr_api_sdk.models as models_pkg

    getattr(models_pkg, model_name).model_validate(payload)


def test_models_embedding_a_patched_model_are_rebuilt_after_the_models_they_embed():
    import watchtowr_api_sdk.models as models_pkg

    patched = {model_name for model_name, _ in NULLABLE_FIELDS}
    order = models_embedding(models_pkg, patched)

    assert {"ClientEngineSettingsData", "ClientIp", "PaginatedClientIp", "AssetsListResponse"} <= set(order)
    for position, name in enumerate(order):
        embedded = _sdk_models_embedded_in(getattr(models_pkg, name))
        assert embedded & set(order) <= set(order[:position]), name
        assert embedded & (patched | set(order[:position])), name


def test_models_embedding_follows_nesting_more_than_one_level_deep():
    class Leaf(BaseModel):
        value: int

    class Middle(BaseModel):
        leaf: Leaf

    class Outer(BaseModel):
        middles: list[Middle]

    class Unrelated(BaseModel):
        value: int

    models_pkg = type("Models", (), {"Leaf": Leaf, "Middle": Middle, "Outer": Outer, "Unrelated": Unrelated})

    assert models_embedding(models_pkg, {"Leaf"}) == ["Middle", "Outer"]


def test_accept_null_field_skips_a_field_the_sdk_model_no_longer_has():
    accept_null_field(Hunt, "field_removed_by_an_sdk_regeneration")

    assert "field_removed_by_an_sdk_regeneration" not in Hunt.model_fields


def test_client_ip_accepts_whois_keys_the_sdk_does_not_define():
    from watchtowr_api_sdk.models.client_ip import ClientIp

    client_ip = ClientIp.from_dict({
        "type": "ip",
        "source": "manual",
        "status": "verified",
        "created_at": "2026-05-29T16:10:47Z",
        "id": "1",
        "name": "192.0.2.1",
        "businessUnits": [],
        "country": "SG",
        "live": True,
        "whoisData": [{
            "id": 1,
            "data": {
                "asn": "64500",
                "query": "192.0.2.1",
                "nets": [{"cidr": "192.0.2.0/24", "name": "EXAMPLE-NET", "abuse_emails": ["abuse@example.com"]}],
                "asn_source": "rdap",
            },
            "raw": "NetRange: 192.0.2.0 - 192.0.2.255",
            "fetched_at": "2026-10-01T00:00:00Z",
        }],
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
    })

    whois = client_ip.whois_data[0]
    assert whois.raw == "NetRange: 192.0.2.0 - 192.0.2.255"
    assert whois.data.asn == "64500"
    assert whois.data.nets[0].name == "EXAMPLE-NET"
