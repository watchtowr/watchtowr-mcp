"""Compatibility fixes for the generated watchtowr-api SDK vs live Platform responses.

- ``FindingRetestResponseDto``: allow null ``completed_at`` / ``evidence``.
- ``Retest.from_dict`` / ``ClientFinding.from_dict``: pass nested retest payloads as
  raw dicts into ``model_validate`` so Pydantic uses the patched DTO class (the
  stock helpers pre-build nested models with the old type and validation fails).

Must run ``apply_watchtowr_sdk_compat_patches()`` before importing ``FindingsApi``.
"""

from __future__ import annotations

import json
import pprint
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, StrictStr, field_validator
from typing_extensions import Self


class FindingRetestResponseDtoCompat(BaseModel):
    """Drop-in replacement with nullable fields the Platform may omit."""

    requested_by: StrictStr
    requested_at: datetime
    retest_status: StrictStr
    status_occurred_at: datetime
    completed_at: Optional[datetime] = None
    evidence: Optional[StrictStr] = None

    @field_validator("retest_status")
    def retest_status_validate_enum(cls, value):
        allowed = frozenset({"started", "in-progress", "success", "error"})
        if value not in allowed:
            raise ValueError(
                "must be one of enum values ('started', 'in-progress', 'success', 'error')"
            )
        return value

    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        protected_namespaces=(),
    )

    def to_str(self) -> str:
        return pprint.pformat(self.model_dump(by_alias=True))

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> Optional[Self]:
        return cls.from_dict(json.loads(json_str))

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(by_alias=True, exclude_none=True)

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        if obj is None:
            return None
        if not isinstance(obj, dict):
            return cls.model_validate(obj)
        return cls.model_validate(
            {
                "requested_by": obj.get("requested_by"),
                "requested_at": obj.get("requested_at"),
                "retest_status": obj.get("retest_status"),
                "status_occurred_at": obj.get("status_occurred_at"),
                "completed_at": obj.get("completed_at"),
                "evidence": obj.get("evidence"),
            }
        )


def apply_watchtowr_sdk_compat_patches() -> None:
    import watchtowr_api_sdk.models.finding_retest_response_dto as dto_mod
    import watchtowr_api_sdk.models.client_finding as cf_mod
    import watchtowr_api_sdk.models.paginated_client_findings as pcf_mod
    import watchtowr_api_sdk.models.retest as retest_mod
    import watchtowr_api_sdk.models.link as link_mod
    from watchtowr_api_sdk.models.client_finding_assignee import ClientFindingAssignee
    from watchtowr_api_sdk.models.client_finding_impact_tag import ClientFindingImpactTag

    # Patch Link: previous/next are null on the first/last page respectively.
    def link_from_dict(cls, obj: Optional[Dict[str, Any]]) -> Any:
        if obj is None:
            return None
        if not isinstance(obj, dict):
            return obj
        return cls.model_construct(
            first=obj.get("first"),
            last=obj.get("last"),
            previous=obj.get("previous"),
            next=obj.get("next"),
        )

    link_mod.Link.from_dict = classmethod(link_from_dict)  # type: ignore[assignment]

    dto_mod.FindingRetestResponseDto = FindingRetestResponseDtoCompat
    cf_mod.FindingRetestResponseDto = dto_mod.FindingRetestResponseDto
    retest_mod.FindingRetestResponseDto = dto_mod.FindingRetestResponseDto

    def retest_from_dict(cls, obj: Optional[Dict[str, Any]]) -> Any:
        if obj is None:
            return None
        if not isinstance(obj, dict):
            return obj
        current = obj.get("current_retest")
        # Use model_construct to bypass Pydantic's cached type validator for
        # current_retest (model_rebuild does not update already-resolved field
        # validators in Pydantic v2). We manually convert through the compat class.
        return cls.model_construct(
            retest_remaining=obj.get("retest_remaining"),
            current_retest=FindingRetestResponseDtoCompat.from_dict(current)
            if isinstance(current, dict)
            else current,
        )

    retest_mod.Retest.from_dict = classmethod(retest_from_dict)  # type: ignore[assignment]

    def client_finding_from_dict(cls, obj: Optional[Dict[str, Any]]) -> Any:
        if obj is None:
            return None
        if not isinstance(obj, dict):
            return obj
        fr = obj.get("retest_history")
        # Use model_construct to bypass Pydantic's cached field validators.
        # Some generated SDK fields (e.g. created_at) are typed in a way that
        # rejects the raw API values at validation time even after model_rebuild.
        return cls.model_construct(
            id=obj.get("id"),
            title=obj.get("title"),
            description=obj.get("description"),
            impact=obj.get("impact"),
            finding_impact=obj.get("finding_impact"),
            tags=[
                ClientFindingImpactTag.from_dict(_item)
                for _item in obj["tags"]
            ]
            if obj.get("tags") is not None
            else None,
            evidence=obj.get("evidence"),
            recommendation=obj.get("recommendation"),
            severity=obj.get("severity"),
            cvssv3_score=obj.get("cvssv3_score"),
            cvssv3_metrics=obj.get("cvssv3_metrics"),
            status=obj.get("status"),
            created_at=obj.get("created_at"),
            affected=obj.get("affected"),
            cve_id=obj.get("cve_id"),
            epss_score=obj.get("epss_score"),
            retest=retest_mod.Retest.from_dict(obj["retest"])
            if obj.get("retest") is not None
            else None,
            retest_history=fr if fr is not None else [],
            assigned_user=ClientFindingAssignee.from_dict(obj["assigned_user"])
            if obj.get("assigned_user") is not None
            else None,
            state=obj.get("state"),
            last_seen=obj.get("last_seen"),
            age=obj.get("age"),
            criticality=obj.get("criticality"),
            detection_rules=obj.get("detection_rules"),
            custom_properties=obj.get("customProperties") or obj.get("custom_properties") or [],
            last_status_updated_at=obj.get("last_status_updated_at"),
            references=obj.get("references"),
        )

    cf_mod.ClientFinding.from_dict = classmethod(client_finding_from_dict)  # type: ignore[assignment]

    retest_mod.Retest.model_rebuild(force=True)
    cf_mod.ClientFinding.model_rebuild(force=True)
    pcf_mod.PaginatedClientFindings.model_rebuild(force=True)
    

    import watchtowr_api_sdk.models as models_pkg

    models_pkg.FindingRetestResponseDto = dto_mod.FindingRetestResponseDto

