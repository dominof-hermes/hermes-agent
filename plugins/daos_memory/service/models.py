"""Bounded request models and explicit DAOS Memory vocabulary."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


MAX_METADATA_JSON_BYTES = 4096

Authority = Literal[
    "OWNER_DECISION", "VERIFIED_EVIDENCE", "OPERATIONAL_STATE",
    "AGENT_ASSESSMENT", "HYPOTHESIS",
]
MemoryType = Literal[
    "FACT", "DECISION", "ASSESSMENT", "HYPOTHESIS", "STRATEGY",
    "EXECUTION", "EVIDENCE", "NEXT_ACTION", "SESSION_SUMMARY",
    "RESEARCH", "ARCHITECTURE_ASSESSMENT", "DESIGN_PROPOSAL",
    "INTEGRATION", "OPERATIONAL_STATE", "IMPLEMENTATION", "TECHNICAL_RESULT",
    "ANALYSIS", "IDE_TECHNICAL_RESULT",
]


class BootstrapRequest(BaseModel):
    agent_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,31}$")
    product: str | None = Field(default=None, max_length=120)
    topic: str | None = Field(default=None, max_length=160)


class EventWrite(BaseModel):
    product: str = Field(min_length=1, max_length=120)
    topic: str = Field(min_length=1, max_length=160)
    memory_type: MemoryType
    event_type: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=240)
    summary: str = Field(min_length=1, max_length=1200)
    content: str = Field(min_length=1, max_length=8000)
    source_interface: str = Field(min_length=1, max_length=80)
    authority_level: Authority
    thread_id: str | None = Field(default=None, max_length=160)
    work_id: str | None = Field(default=None, max_length=160)
    source_ref: str | None = Field(default=None, max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def metadata_is_bounded_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON serializable") from exc
        if len(encoded) > MAX_METADATA_JSON_BYTES:
            raise ValueError(f"metadata must not exceed {MAX_METADATA_JSON_BYTES} JSON bytes")
        return value


class RotateRequest(BaseModel):
    max_uses: int | None = Field(default=None, ge=1, le=5)
    ttl_seconds: int | None = Field(default=None, ge=30, le=3600)
