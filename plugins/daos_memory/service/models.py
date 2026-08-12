"""Bounded request models and explicit DAOS Memory vocabulary."""

from __future__ import annotations

import json
import hashlib
import re
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, Field, field_validator, model_validator


MAX_METADATA_JSON_BYTES = 4096
MAX_SOURCE_CONTENT_BYTES = 524288

Authority = Literal[
    "OWNER_DECISION", "VERIFIED_EVIDENCE", "OPERATIONAL_STATE",
    "AGENT_ASSESSMENT", "HYPOTHESIS",
]
MemoryType = Literal[
    "FACT", "DECISION", "ASSESSMENT", "HYPOTHESIS", "STRATEGY",
    "EXECUTION", "EVIDENCE", "NEXT_ACTION", "SESSION_SUMMARY",
    "RESEARCH", "ARCHITECTURE_ASSESSMENT", "DESIGN_PROPOSAL",
    "INTEGRATION", "OPERATIONAL_STATE", "IMPLEMENTATION", "TECHNICAL_RESULT",
    "ANALYSIS", "IDE_TECHNICAL_RESULT", "IDEA", "DESIGN_OPTION",
    "LESSON_LEARNED", "ENGINEERING_KNOWLEDGE", "ARCHITECTURE_DECISION",
    "DETAIL_NOTE",
]
SourceType = Literal[
    "CHAT_CONVERSATION", "SLACK_THREAD", "GIT_MD", "PDF", "ARCHITECTURE_DOCUMENT",
    "RUNBOOK", "ADR", "EVIDENCE", "ATTACHMENT", "ENGINEERING_DOCUMENT",
]
RelationType = Literal[
    "SUMMARIZES", "DERIVED_FROM", "SOURCE_OF", "RELATED_TO", "SUPERSEDES",
    "EVIDENCE_FOR", "DECIDED_BY", "IMPLEMENTED_BY",
]
DecisionStatus = Literal["PENDING_OWNER_CONFIRM", "APPROVED", "REJECTED", "SUPERSEDED"]
NoteType = Literal[
    "STRATEGY", "ASSESSMENT", "ARCHITECTURE", "ENGINEERING_KNOWLEDGE",
    "EXECUTION_REPORT", "RESEARCH", "MARKET_INTELLIGENCE", "IMPLEMENTATION_NOTE",
    "INCIDENT_LEARNING",
]
_GIT_SOURCE_TYPES = {"GIT_MD", "ARCHITECTURE_DOCUMENT", "ADR", "RUNBOOK", "ENGINEERING_DOCUMENT"}
_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:authorization\s*:\s*bearer\s+\S+|"
    r"(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*\S+|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
)


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
    occurred_at: AwareDatetime | None = None
    effective_from: AwareDatetime | None = None
    effective_to: AwareDatetime | None = None
    source_session_at: AwareDatetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def event_type_is_canonical(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("event_type must not be blank")
        return normalized

    @model_validator(mode="after")
    def temporal_contract_is_valid(self):
        if self.event_type.upper() == "HISTORY_IMPORT":
            if self.occurred_at is None or self.source_session_at is None:
                raise ValueError("HISTORY_IMPORT requires occurred_at and source_session_at")
        if self.effective_to is not None:
            start = self.effective_from or self.occurred_at
            if start is None:
                raise ValueError("effective_to requires effective_from or occurred_at")
            if self.effective_to < start:
                raise ValueError("effective_to must not precede effective_from or occurred_at")
        return self

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


class SourceWrite(BaseModel):
    source_type: SourceType
    product: str = Field(min_length=1, max_length=120)
    topic: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=240)
    source_interface: str = Field(min_length=1, max_length=80)
    actor: str = Field(min_length=1, max_length=80)
    participants: list[str] = Field(default_factory=list, max_length=32)
    repository: str | None = Field(default=None, max_length=240)
    path: str | None = Field(default=None, max_length=1000)
    commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40,64}$")
    source_url: str | None = Field(default=None, max_length=1000)
    file_reference: str | None = Field(default=None, max_length=1000)
    occurred_at: AwareDatetime
    source_session_at: AwareDatetime
    content: str = Field(min_length=1, max_length=524288)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    access_scope: Literal["OWNER", "COMPANY", "PRODUCT", "RESTRICTED"]
    security_level: Literal["INTERNAL", "RESTRICTED"]
    redaction_status: Literal["REVIEWED_NO_SECRETS"]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("participants")
    @classmethod
    def participants_are_bounded(cls, value: list[str]) -> list[str]:
        if any(not participant.strip() or len(participant) > 80 for participant in value):
            raise ValueError("participants must contain bounded non-empty names")
        return value

    @model_validator(mode="after")
    def source_integrity_and_location_are_valid(self):
        encoded_content = self.content.encode("utf-8")
        if len(encoded_content) > MAX_SOURCE_CONTENT_BYTES:
            raise ValueError(f"content must not exceed {MAX_SOURCE_CONTENT_BYTES} UTF-8 bytes")
        actual_hash = hashlib.sha256(encoded_content).hexdigest()
        if self.content_hash != actual_hash:
            raise ValueError("content_hash must match UTF-8 source content")
        if _CREDENTIAL_PATTERN.search(self.content):
            raise ValueError("source content contains a credential-like value")
        if self.source_type in _GIT_SOURCE_TYPES and not all((self.repository, self.path, self.commit_sha)):
            raise ValueError("Git-backed source requires repository, path, and commit_sha")
        if self.source_url and not self.source_url.startswith(("https://", "http://")):
            raise ValueError("source_url must use http or https")
        self.metadata_is_bounded_json(self.metadata)
        return self

    @staticmethod
    def metadata_is_bounded_json(value: dict[str, Any]) -> None:
        try:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON serializable") from exc
        if len(encoded) > MAX_METADATA_JSON_BYTES:
            raise ValueError(f"metadata must not exceed {MAX_METADATA_JSON_BYTES} JSON bytes")


class KnowledgeRelationWrite(BaseModel):
    relation_type: RelationType
    from_event_id: UUID | None = None
    from_source_id: UUID | None = None
    to_event_id: UUID | None = None
    to_source_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def endpoints_are_canonical_and_distinct(self):
        if (self.from_event_id is None) == (self.from_source_id is None):
            raise ValueError("exactly one from endpoint is required")
        if (self.to_event_id is None) == (self.to_source_id is None):
            raise ValueError("exactly one to endpoint is required")
        if self.from_event_id is not None and self.from_event_id == self.to_event_id:
            raise ValueError("relation endpoints must be distinct")
        if self.from_source_id is not None and self.from_source_id == self.to_source_id:
            raise ValueError("relation endpoints must be distinct")
        SourceWrite.metadata_is_bounded_json(self.metadata)
        return self


class RotateRequest(BaseModel):
    max_uses: int | None = Field(default=None, ge=1, le=5)
    ttl_seconds: int | None = Field(default=None, ge=30, le=3600)


class CurrentContextWrite(BaseModel):
    product: str = Field(min_length=1, max_length=120)
    topic: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=240)
    summary: str = Field(min_length=1, max_length=1200)
    next_action: str = Field(min_length=1, max_length=1200)
    occurred_at: AwareDatetime
    related_note_ids: list[UUID] = Field(default_factory=list, max_length=32)
    related_decision_ids: list[UUID] = Field(default_factory=list, max_length=32)


class DecisionWrite(BaseModel):
    product: str = Field(min_length=1, max_length=120)
    topic: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=240)
    decision_content: str = Field(min_length=1, max_length=8000)
    occurred_at: AwareDatetime
    related_note_ids: list[UUID] = Field(default_factory=list, max_length=32)
    related_source_ids: list[UUID] = Field(default_factory=list, max_length=32)
    supersedes_id: UUID | None = None


class DecisionAction(BaseModel):
    owner_comment: str | None = Field(default=None, max_length=1200)


class PolicyWrite(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    content: str = Field(min_length=1, max_length=8000)


class AgentNoteWrite(BaseModel):
    product: str = Field(min_length=1, max_length=120)
    topic: str = Field(min_length=1, max_length=160)
    note_type: NoteType
    title: str = Field(min_length=1, max_length=240)
    summary: str = Field(min_length=1, max_length=1200)
    full_content: str = Field(min_length=1, max_length=16000)
    occurred_at: AwareDatetime
    status: Literal["CURRENT", "CLOSED", "HISTORICAL", "SUPERSEDED"] = "CURRENT"
    related_source_ids: list[UUID] = Field(default_factory=list, max_length=32)
    related_note_ids: list[UUID] = Field(default_factory=list, max_length=32)
    access_scope: Literal["OWNER", "COMPANY", "PRODUCT", "RESTRICTED"]
    security_level: Literal["INTERNAL", "RESTRICTED"]
