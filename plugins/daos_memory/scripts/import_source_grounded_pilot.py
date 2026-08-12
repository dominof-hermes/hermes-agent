"""Atomic, idempotent importer for the bounded DAOS Memory v2 Zeus pilot."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import asyncpg

from plugins.daos_memory.service.models import SourceWrite

_ORDER_SQL = """CASE authority_level
 WHEN 'OWNER_DECISION' THEN 5 WHEN 'VERIFIED_EVIDENCE' THEN 4
 WHEN 'OPERATIONAL_STATE' THEN 3 WHEN 'AGENT_ASSESSMENT' THEN 2 ELSE 1 END DESC,
 CASE status WHEN 'CURRENT' THEN 3 WHEN 'HISTORY' THEN 2 WHEN 'SUPERSEDED' THEN 1 ELSE 0 END DESC,
 COALESCE(effective_from, occurred_at, created_at) DESC, occurred_at DESC, created_at DESC, id DESC"""
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_PHONE = re.compile(r"(?<!\d)(?:\+?82[- ]?)?0?1[016789][- ]?\d{3,4}[- ]?\d{4}(?!\d)")


def _raw_source(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    marker = "## Raw Source\n\n"
    if marker not in text:
        raise ValueError("raw source marker unavailable")
    raw = text.split(marker, 1)[1]
    return raw[:-1] if raw.endswith("\n") else raw


def _source_payload(manifest: dict[str, Any], root: Path, commit_sha: str | None) -> tuple[str, dict[str, Any]]:
    source = dict(manifest["source"])
    source_id = source.pop("id")
    archive_ref = Path(manifest["archive_path"])
    archive_path = archive_ref if archive_ref.is_absolute() else root / archive_ref
    content = _raw_source(archive_path)
    if hashlib.sha256(content.encode("utf-8")).hexdigest() != source["content_hash"]:
        raise ValueError("raw source content_hash mismatch")
    if _EMAIL.search(content) or _PHONE.search(content):
        raise ValueError("raw PII pattern detected")
    source.update({
        "repository": manifest.get("repository"),
        "path": str(archive_ref),
        "commit_sha": commit_sha,
        "source_url": None,
        "content": content,
    })
    validated = SourceWrite(**source).model_dump()
    return source_id, validated


def _timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("pilot timestamps must include timezone")
    return parsed


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _validate_manifest(manifest: dict[str, Any]) -> None:
    relation_ids = [relation["id"] for relation in manifest["relations"]]
    if len(relation_ids) != len(set(relation_ids)):
        raise ValueError("pilot relation ids must be unique")


async def _current_ids(connection: asyncpg.Connection) -> list[str]:
    rows = await connection.fetch(
        f"SELECT id FROM daos_memory.context_events WHERE status='CURRENT' ORDER BY {_ORDER_SQL}"
    )
    return [str(row["id"]) for row in rows]


async def import_pilot(manifest_path: Path, source_root: Path, commit_sha: str | None = None) -> dict[str, Any]:
    if commit_sha is not None and not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise ValueError("commit_sha must be an exact 40-character lowercase SHA")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _validate_manifest(manifest)
    source_id, source = _source_payload(manifest, source_root, commit_sha)
    database_url = os.environ.get("DAOS_MEMORY_DATABASE_URL", "")
    if not database_url:
        raise RuntimeError("DAOS_MEMORY_DATABASE_URL unavailable")
    connection = await asyncpg.connect(database_url)
    try:
        async with connection.transaction():
            required = await connection.fetch(
                "SELECT id,status FROM daos_memory.context_events WHERE id=ANY($1::uuid[])",
                [manifest["current_event_id"], manifest["summary_event_id"]],
            )
            required_map = {str(row["id"]): row["status"] for row in required}
            if required_map != {
                manifest["current_event_id"]: "CURRENT",
                manifest["summary_event_id"]: "CURRENT",
            }:
                raise RuntimeError("canonical Current/Summary pilot anchors are unavailable")
            before_current = await _current_ids(connection)
            await connection.execute(
                """INSERT INTO daos_memory.knowledge_sources
                (id,source_type,title,source_interface,actor,participants,repository,path,commit_sha,
                 source_url,occurred_at,source_session_at,content,content_hash,access_scope,
                 security_level,redaction_status,metadata)
                VALUES ($1::uuid,$2,$3,$4,$5,$6::text[],$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb)
                ON CONFLICT (id) DO NOTHING""",
                source_id, source["source_type"], source["title"], source["source_interface"],
                source["actor"], source["participants"], source["repository"], source["path"],
                source["commit_sha"], source["source_url"], source["occurred_at"],
                source["source_session_at"], source["content"], source["content_hash"],
                source["access_scope"], source["security_level"], source["redaction_status"],
                json.dumps(source["metadata"], ensure_ascii=False),
            )
            detail = manifest["detail_event"]
            await connection.execute(
                """INSERT INTO daos_memory.context_events
                (id,occurred_at,effective_from,effective_to,source_session_at,actor,actor_role,
                 source_interface,product,topic,thread_id,work_id,memory_type,event_type,title,
                 summary,content,status,authority_level,source_ref,supersedes_id,metadata)
                VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                        $18,$19,$20,$21::uuid,$22::jsonb)
                ON CONFLICT (id) DO NOTHING""",
                detail["id"], _timestamp(detail["occurred_at"]), _timestamp(detail["effective_from"]),
                _timestamp(detail["effective_to"]), _timestamp(detail["source_session_at"]),
                detail["actor"], detail["actor_role"],
                detail["source_interface"], detail["product"], detail["topic"], detail["thread_id"],
                detail["work_id"], detail["memory_type"], detail["event_type"], detail["title"],
                detail["summary"], detail["content"], detail["status"], detail["authority_level"],
                detail["source_ref"], detail.get("supersedes_id"),
                json.dumps(detail["metadata"], ensure_ascii=False),
            )
            for relation in manifest["relations"]:
                await connection.execute(
                    """INSERT INTO daos_memory.knowledge_relations
                    (id,from_event_id,from_source_id,to_event_id,to_source_id,relation_type,metadata)
                    VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7::jsonb)
                    ON CONFLICT (id) DO NOTHING""",
                    relation["id"], relation.get("from_event_id"), relation.get("from_source_id"),
                    relation.get("to_event_id"), relation.get("to_source_id"),
                    relation["relation_type"], json.dumps({"pilot_id": manifest["pilot_id"]}),
                )
            source_row = await connection.fetchrow(
                """SELECT source_type,title,source_interface,actor,participants,repository,path,
                commit_sha,source_url,occurred_at,source_session_at,content,content_hash,access_scope,
                security_level,redaction_status,metadata FROM daos_memory.knowledge_sources WHERE id=$1::uuid""",
                source_id,
            )
            detail_row = await connection.fetchrow(
                """SELECT actor,actor_role,source_interface,product,topic,thread_id,work_id,memory_type,
                event_type,title,summary,content,status,authority_level,source_ref,supersedes_id,occurred_at,
                effective_from,effective_to,source_session_at,metadata FROM daos_memory.context_events
                WHERE id=$1::uuid""",
                detail["id"],
            )
            relation_rows = await connection.fetch(
                """SELECT id,from_event_id,from_source_id,to_event_id,to_source_id,relation_type,metadata
                FROM daos_memory.knowledge_relations WHERE id=ANY($1::uuid[])""",
                [relation["id"] for relation in manifest["relations"]],
            )
            source_fields = (
                "source_type", "title", "source_interface", "actor", "participants", "repository",
                "path", "commit_sha", "source_url", "occurred_at", "source_session_at", "content",
                "content_hash", "access_scope", "security_level", "redaction_status", "metadata",
            )
            expected_source = (
                source["source_type"], source["title"], source["source_interface"], source["actor"],
                source["participants"], source["repository"], source["path"], source["commit_sha"],
                source["source_url"], source["occurred_at"], source["source_session_at"],
                source["content"], source["content_hash"], source["access_scope"],
                source["security_level"], source["redaction_status"], source["metadata"],
            )
            actual_source = tuple(source_row)[:-1] + (_json_value(source_row["metadata"]),) if source_row else ()
            source_mismatches = source_fields if not source_row else tuple(
                name for name, actual, expected in zip(source_fields, actual_source, expected_source)
                if actual != expected
            )
            if source_mismatches:
                raise RuntimeError("source readback mismatch: " + ",".join(source_mismatches))
            expected_detail = (
                detail["actor"], detail["actor_role"], detail["source_interface"], detail["product"],
                detail["topic"], detail["thread_id"], detail["work_id"], detail["memory_type"],
                detail["event_type"], detail["title"], detail["summary"], detail["content"],
                detail["status"], detail["authority_level"], detail["source_ref"], detail.get("supersedes_id"),
                _timestamp(detail["occurred_at"]), _timestamp(detail["effective_from"]),
                _timestamp(detail["effective_to"]), _timestamp(detail["source_session_at"]), detail["metadata"],
            )
            if detail_row:
                actual_detail_values = list(detail_row)
                if actual_detail_values[15] is not None:
                    actual_detail_values[15] = str(actual_detail_values[15])
                actual_detail_values[-1] = _json_value(actual_detail_values[-1])
                actual_detail = tuple(actual_detail_values)
            else:
                actual_detail = ()
            if not detail_row or actual_detail != expected_detail:
                raise RuntimeError("detail readback mismatch")
            actual_relations = {
                str(row["id"]): (
                    str(row["from_event_id"]) if row["from_event_id"] else None,
                    str(row["from_source_id"]) if row["from_source_id"] else None,
                    str(row["to_event_id"]) if row["to_event_id"] else None,
                    str(row["to_source_id"]) if row["to_source_id"] else None,
                    row["relation_type"], _json_value(row["metadata"]),
                ) for row in relation_rows
            }
            expected_relations = {
                relation["id"]: (
                    relation.get("from_event_id"), relation.get("from_source_id"),
                    relation.get("to_event_id"), relation.get("to_source_id"),
                    relation["relation_type"], {"pilot_id": manifest["pilot_id"]},
                ) for relation in manifest["relations"]
            }
            if actual_relations != expected_relations:
                raise RuntimeError("relation readback mismatch")
            after_current = await _current_ids(connection)
            if before_current != after_current:
                raise RuntimeError("existing Current ordering changed")
        return {
            "pilot_id": manifest["pilot_id"], "source_id": source_id,
            "detail_event_id": detail["id"], "relations": len(manifest["relations"]),
            "current_order_unchanged": True, "content_hash": source["content_hash"],
            "commit_sha": commit_sha,
        }
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--commit-sha")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(import_pilot(args.manifest, args.source_root, args.commit_sha)), ensure_ascii=False))


if __name__ == "__main__":
    main()
