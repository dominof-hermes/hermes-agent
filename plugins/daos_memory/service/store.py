"""Bounded asyncpg persistence for the isolated DAOS Memory service."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID, uuid4

import asyncpg


_EVENT_COLUMNS = """id, created_at, occurred_at, effective_from, effective_to, source_session_at,
actor, actor_role, source_interface, product, topic, thread_id, work_id, memory_type,
event_type, title, summary, content, status, authority_level, source_ref, supersedes_id, metadata"""
_SOURCE_COLUMNS = """id, source_type, title, source_interface, actor, participants,
repository, path, commit_sha, source_url, occurred_at, source_session_at, indexed_at,
content, content_hash, access_scope, security_level, redaction_status, metadata"""
_OPERATIONAL_TYPES = "('EXECUTION','NEXT_ACTION','OPERATIONAL_STATE')"
_ACTIVE_KNOWLEDGE_TYPES = """('STRATEGY','RESEARCH','EVIDENCE','ARCHITECTURE_ASSESSMENT',
'DESIGN_PROPOSAL','IDEA','DESIGN_OPTION','LESSON_LEARNED','ENGINEERING_KNOWLEDGE',
'ARCHITECTURE_DECISION')"""
_AUTHORITY_SQL = """CASE authority_level
WHEN 'OWNER_DECISION' THEN 5 WHEN 'VERIFIED_EVIDENCE' THEN 4
WHEN 'OPERATIONAL_STATE' THEN 3 WHEN 'AGENT_ASSESSMENT' THEN 2 ELSE 1 END"""
_STATUS_SQL = """CASE status
WHEN 'CURRENT' THEN 3 WHEN 'DRAFT' THEN 2 ELSE 1 END"""


class AsyncpgStore:
    def __init__(self, database_url: str, *, query_timeout_seconds: float = 2.0):
        self.database_url = database_url
        self.timeout = query_timeout_seconds
        self._pool: asyncpg.Pool | None = None
        self._pool_lock = asyncio.Lock()

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            async with self._pool_lock:
                if self._pool is None:
                    self._pool = await asyncpg.create_pool(
                        self.database_url, min_size=1, max_size=5,
                        command_timeout=self.timeout, timeout=self.timeout,
                    )
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def health(self) -> bool:
        pool = await self._get_pool()
        return bool(await pool.fetchval("SELECT TRUE", timeout=self.timeout))

    async def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        pool = await self._get_pool()
        row = await pool.fetchrow("SELECT * FROM daos_memory.agent_registry WHERE agent_id=$1", agent_id, timeout=self.timeout)
        return dict(row) if row else None

    async def rotate_bootstrap(self, agent_id: str, key_hash: str, expires_at, max_uses: int):
        pool = await self._get_pool()
        row = await pool.fetchrow(
            """UPDATE daos_memory.agent_registry SET status='ACTIVE', bootstrap_key_hash=$2,
            bootstrap_expires_at=$3, bootstrap_uses_remaining=$4, access_token_hash=NULL,
            access_expires_at=NULL, updated_at=now() WHERE agent_id=$1 RETURNING *""",
            agent_id, key_hash, expires_at, max_uses, timeout=self.timeout,
        )
        return dict(row) if row else None

    async def revoke_agent(self, agent_id: str):
        pool = await self._get_pool()
        row = await pool.fetchrow(
            """UPDATE daos_memory.agent_registry SET status='REVOKED', bootstrap_key_hash=NULL,
            bootstrap_expires_at=NULL, bootstrap_uses_remaining=0, access_token_hash=NULL,
            access_expires_at=NULL, updated_at=now() WHERE agent_id=$1 RETURNING *""",
            agent_id, timeout=self.timeout,
        )
        return dict(row) if row else None

    async def consume_bootstrap(self, agent_id: str, key_hash: str, now):
        pool = await self._get_pool()
        row = await pool.fetchrow(
            """UPDATE daos_memory.agent_registry SET
            bootstrap_uses_remaining=bootstrap_uses_remaining-1,
            bootstrap_key_hash=CASE WHEN bootstrap_uses_remaining <= 1 THEN NULL ELSE bootstrap_key_hash END,
            last_access_at=$3, updated_at=$3
            WHERE agent_id=$1 AND status='ACTIVE' AND bootstrap_key_hash=$2
              AND bootstrap_expires_at>$3 AND bootstrap_uses_remaining>0 RETURNING *""",
            agent_id, key_hash, now, timeout=self.timeout,
        )
        return dict(row) if row else None

    async def set_access_token(self, agent_id: str, token_hash: str, expires_at) -> None:
        pool = await self._get_pool()
        await pool.execute(
            "UPDATE daos_memory.agent_registry SET access_token_hash=$2, access_expires_at=$3, updated_at=now() WHERE agent_id=$1",
            agent_id, token_hash, expires_at, timeout=self.timeout,
        )

    async def authenticate_access(self, token_hash: str, now):
        pool = await self._get_pool()
        row = await pool.fetchrow(
            """UPDATE daos_memory.agent_registry SET last_access_at=$2, updated_at=$2
            WHERE status='ACTIVE' AND access_token_hash=$1 AND access_expires_at>$2 RETURNING *""",
            token_hash, now, timeout=self.timeout,
        )
        return dict(row) if row else None

    async def get_policies(self, categories: list[str], limit: int):
        pool = await self._get_pool()
        rows = await pool.fetch(
            """SELECT id, category, title, content, scope, status, version, updated_at
            FROM daos_memory.canonical_policies WHERE status='ACTIVE' AND category=ANY($1::text[])
            ORDER BY updated_at DESC LIMIT $2""",
            categories, limit, timeout=self.timeout,
        )
        return [dict(r) for r in rows]

    async def read_current(self, product: str | None, topic: str | None, limit: int):
        return await self.admin_events("current", product, topic, limit)

    async def read_operational_current(self, product: str | None, topic: str | None, limit: int):
        return await self.admin_events("current", product, topic, limit)

    async def read_active_knowledge(self, product: str | None, topic: str | None, limit: int):
        return await self.admin_events("agent_notes", product, topic, limit)

    async def search_history(self, product: str | None, topic: str | None, query: str | None, limit: int):
        return await self._events("status<>'CURRENT'", product, topic, query, limit)

    async def _events(self, status_clause: str, product, topic, query, limit):
        pool = await self._get_pool()
        rows = await pool.fetch(
            f"""SELECT {_EVENT_COLUMNS} FROM daos_memory.context_events
            WHERE {status_clause} AND ($1::text IS NULL OR product=$1)
              AND ($2::text IS NULL OR topic=$2)
              AND ($3::text IS NULL OR search_document @@ websearch_to_tsquery('simple',$3))
            ORDER BY {_AUTHORITY_SQL} DESC, {_STATUS_SQL} DESC,
              COALESCE(effective_from, occurred_at, created_at) DESC,
              occurred_at DESC, created_at DESC LIMIT $4""",
            product, topic, query, limit, timeout=self.timeout,
        )
        return [_record(r) for r in rows]

    async def write_event(self, event: dict[str, Any]):
        pool = await self._get_pool()
        return await _insert_event(pool, event, self.timeout)

    async def read_event(self, event_id: str):
        pool = await self._get_pool()
        row = await pool.fetchrow(
            f"SELECT {_EVENT_COLUMNS} FROM daos_memory.context_events WHERE id=$1::uuid",
            event_id,
            timeout=self.timeout,
        )
        return _record(row) if row else None

    async def read_source(self, source_id: str):
        pool = await self._get_pool()
        row = await pool.fetchrow(
            f"SELECT {_SOURCE_COLUMNS} FROM daos_memory.knowledge_sources WHERE id=$1::uuid",
            source_id, timeout=self.timeout,
        )
        return _source_record(row) if row else None

    async def read_event_knowledge(self, event_id: str):
        pool = await self._get_pool()
        relation_rows = await pool.fetch(
            """SELECT id, from_event_id, from_source_id, to_event_id, to_source_id,
            relation_type, created_at, metadata FROM daos_memory.knowledge_relations
            WHERE from_event_id=$1::uuid OR to_event_id=$1::uuid
            ORDER BY created_at, id""",
            event_id, timeout=self.timeout,
        )
        relations = [_relation_record(row) for row in relation_rows]
        related_event_ids = {
            str(value) for relation in relations
            for value in (relation.get("from_event_id"), relation.get("to_event_id"))
            if value is not None and str(value) != event_id
        }
        source_ids = {
            str(value) for relation in relations
            for value in (relation.get("from_source_id"), relation.get("to_source_id"))
            if value is not None
        }
        events = []
        if related_event_ids:
            rows = await pool.fetch(
                f"SELECT {_EVENT_COLUMNS} FROM daos_memory.context_events WHERE id=ANY($1::uuid[])",
                [UUID(value) for value in sorted(related_event_ids)], timeout=self.timeout,
            )
            events = [_record(row) for row in rows]
        sources = []
        if source_ids:
            rows = await pool.fetch(
                f"SELECT {_SOURCE_COLUMNS} FROM daos_memory.knowledge_sources WHERE id=ANY($1::uuid[]) ORDER BY occurred_at, id",
                [UUID(value) for value in sorted(source_ids)], timeout=self.timeout,
            )
            sources = [_source_record(row, include_content=False) for row in rows]
        return {
            "event_id": event_id,
            "evidence_status": "grounded" if sources else "insufficient_evidence",
            "related_events": events,
            "sources": sources,
            "relations": relations,
        }

    async def write_source(self, source: dict[str, Any]):
        pool = await self._get_pool()
        source_id = str(uuid4())
        row = await pool.fetchrow(
            f"""INSERT INTO daos_memory.knowledge_sources ({_SOURCE_COLUMNS},product,topic,file_reference) VALUES
            ($1::uuid,$2,$3,$4,$5,$6::text[],$7,$8,$9,$10,$11::timestamptz,
             $12::timestamptz,now(),$13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21)
            RETURNING {_SOURCE_COLUMNS}""",
            source_id, source["source_type"], source["title"], source["source_interface"],
            source["actor"], source.get("participants") or [], source.get("repository"),
            source.get("path"), source.get("commit_sha"), source.get("source_url"),
            source["occurred_at"], source["source_session_at"], source["content"],
            source["content_hash"], source["access_scope"], source["security_level"],
            source["redaction_status"], json.dumps(source.get("metadata") or {}),
            source["product"], source["topic"], source.get("file_reference"), timeout=self.timeout,
        )
        return _source_record(row)

    async def write_knowledge_relation(self, relation: dict[str, Any]):
        pool = await self._get_pool()
        relation_id = str(uuid4())
        row = await pool.fetchrow(
            """INSERT INTO daos_memory.knowledge_relations
            (id,from_event_id,from_source_id,to_event_id,to_source_id,relation_type,metadata)
            VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7::jsonb)
            RETURNING id,from_event_id,from_source_id,to_event_id,to_source_id,relation_type,created_at,metadata""",
            relation_id, relation.get("from_event_id"), relation.get("from_source_id"),
            relation.get("to_event_id"), relation.get("to_source_id"), relation["relation_type"],
            json.dumps(relation.get("metadata") or {}), timeout=self.timeout,
        )
        return _relation_record(row)

    async def supersede_event(self, old_id: str, actor_id: str, event: dict[str, Any]):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                old = await conn.fetchrow(
                    """SELECT id FROM daos_memory.context_events
                    WHERE id=$1::uuid AND actor=$2 AND product=$3 AND topic=$4
                      AND status='CURRENT'
                      AND authority_level IN ('AGENT_ASSESSMENT','HYPOTHESIS','OPERATIONAL_STATE')
                    FOR UPDATE""",
                    old_id, actor_id, event["product"], event["topic"], timeout=self.timeout,
                )
                if not old:
                    return None
                await conn.execute(
                    "UPDATE daos_memory.context_events SET status='SUPERSEDED' WHERE id=$1::uuid",
                    old_id, timeout=self.timeout,
                )
                row = await _insert_event(conn, {**event, "status": "CURRENT", "supersedes_id": old_id}, self.timeout)
                await conn.execute(
                    """INSERT INTO daos_memory.context_relations
                    (from_event_id,to_event_id,relation_type) VALUES ($1::uuid,$2::uuid,'SUPERSEDES')""",
                    row["id"], old_id, timeout=self.timeout,
                )
                return row

    async def list_agents(self, limit: int):
        pool = await self._get_pool()
        rows = await pool.fetch(
            """SELECT agent_id,status,role_categories,allowed_memory_types,last_access_at,
            bootstrap_expires_at,bootstrap_uses_remaining,updated_at
            FROM daos_memory.agent_registry ORDER BY agent_id LIMIT $1""", limit, timeout=self.timeout,
        )
        return [dict(r) for r in rows]

    async def admin_events(self, view: str, product, topic, limit: int):
        pool = await self._get_pool()
        filters = "($1::text IS NULL OR product=$1) AND ($2::text IS NULL OR topic=$2)"
        if view == "current":
            sql, args = f"SELECT *, 'CURRENT_CONTEXT' AS item_kind FROM daos_memory.current_contexts WHERE status='CURRENT' AND {filters} ORDER BY occurred_at DESC,stored_at DESC LIMIT $3", (product, topic, limit)
        elif view == "decisions":
            sql, args = f"SELECT *, 'DECISION' AS item_kind FROM daos_memory.decisions WHERE {filters} ORDER BY occurred_at DESC,stored_at DESC LIMIT $3", (product, topic, limit)
        elif view == "agent_notes":
            sql, args = f"SELECT *, 'AGENT_NOTE' AS item_kind FROM daos_memory.agent_notes WHERE status='CURRENT' AND {filters} ORDER BY occurred_at DESC,stored_at DESC LIMIT $3", (product, topic, limit)
        elif view == "knowledge_vault":
            sql, args = f"SELECT id,source_type,title,source_interface,actor,participants,product,topic,occurred_at,imported_at,repository,path,commit_sha,content_hash,access_scope,security_level,'SOURCE' AS item_kind FROM daos_memory.knowledge_sources WHERE {filters} ORDER BY occurred_at DESC,imported_at DESC LIMIT $3", (product, topic, limit)
        elif view == "policies":
            sql, args = "SELECT *, 'POLICY' AS item_kind FROM daos_memory.canonical_policies ORDER BY updated_at DESC LIMIT $1", (limit,)
        else:
            sql, args = f"""SELECT * FROM (
              SELECT id,product,topic,title,summary AS content,actor,occurred_at,stored_at,status,'CURRENT_CONTEXT' AS item_kind FROM daos_memory.current_contexts WHERE status<>'CURRENT'
              UNION ALL SELECT id,product,topic,title,decision_content,proposed_by,occurred_at,stored_at,status,'DECISION' FROM daos_memory.decisions WHERE status IN ('REJECTED','SUPERSEDED')
              UNION ALL SELECT id,product,topic,title,full_content,actor,occurred_at,stored_at,status,'AGENT_NOTE' FROM daos_memory.agent_notes WHERE status<>'CURRENT'
            ) history WHERE {filters} ORDER BY occurred_at DESC,stored_at DESC LIMIT $3""", (product, topic, limit)
        return [_json_record(row) for row in await pool.fetch(sql, *args, timeout=self.timeout)]

    async def write_current_context(self, actor: str, values: dict[str, Any]):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("UPDATE daos_memory.current_contexts SET status='SUPERSEDED' WHERE product=$1 AND topic=$2 AND status='CURRENT'", values["product"], values["topic"], timeout=self.timeout)
                row = await conn.fetchrow("""INSERT INTO daos_memory.current_contexts
                  (id,product,topic,title,summary,next_action,actor,occurred_at,related_note_ids,related_decision_ids)
                  VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9::uuid[],$10::uuid[]) RETURNING *""",
                  str(uuid4()), values["product"], values["topic"], values["title"], values["summary"], values["next_action"], actor, values["occurred_at"], values.get("related_note_ids", []), values.get("related_decision_ids", []), timeout=self.timeout)
        return _json_record(row)

    async def write_decision(self, actor: str, values: dict[str, Any]):
        pool = await self._get_pool()
        row = await pool.fetchrow("""INSERT INTO daos_memory.decisions
          (id,product,topic,title,decision_content,proposed_by,occurred_at,supersedes_id,related_note_ids,related_source_ids)
          VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8::uuid,$9::uuid[],$10::uuid[]) RETURNING *""",
          str(uuid4()), values["product"], values["topic"], values["title"], values["decision_content"], actor, values["occurred_at"], values.get("supersedes_id"), values.get("related_note_ids", []), values.get("related_source_ids", []), timeout=self.timeout)
        return _json_record(row)

    async def decide(self, decision_id: str, result: str, owner_comment: str | None):
        pool = await self._get_pool()
        row = await pool.fetchrow("""UPDATE daos_memory.decisions SET status=$2,
          authority_level=CASE WHEN $2='APPROVED' THEN 'OWNER_DECISION' ELSE 'AGENT_ASSESSMENT' END,
          owner_comment=$3,approved_at=CASE WHEN $2='APPROVED' THEN now() ELSE NULL END
          WHERE id=$1::uuid AND status='PENDING_OWNER_CONFIRM' RETURNING *""", decision_id, result, owner_comment, timeout=self.timeout)
        return _json_record(row) if row else None

    async def write_policy(self, values: dict[str, Any]):
        pool = await self._get_pool()
        version = await pool.fetchval("SELECT COALESCE(max(version),0)+1 FROM daos_memory.canonical_policies WHERE title=$1", values["title"], timeout=self.timeout)
        row = await pool.fetchrow("""INSERT INTO daos_memory.canonical_policies
          (id,category,title,content,scope,status,version,author)
          VALUES($1::uuid,'GLOBAL',$2,$3,'GLOBAL','ACTIVE',$4,$5) RETURNING *""",
          str(uuid4()), values["title"], values["content"], version, values["author"], timeout=self.timeout)
        return _json_record(row)

    async def write_agent_note(self, actor: str, actor_role: str, values: dict[str, Any]):
        pool = await self._get_pool()
        row = await pool.fetchrow("""INSERT INTO daos_memory.agent_notes
          (id,actor,actor_role,product,topic,note_type,title,summary,full_content,occurred_at,status,related_source_ids,related_note_ids,access_scope,security_level)
          VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::uuid[],$13::uuid[],$14,$15) RETURNING *""",
          str(uuid4()),actor,actor_role,values["product"],values["topic"],values["note_type"],values["title"],values["summary"],values["full_content"],values["occurred_at"],values["status"],values.get("related_source_ids",[]),values.get("related_note_ids",[]),values["access_scope"],values["security_level"],timeout=self.timeout)
        return _json_record(row)


async def _insert_event(conn, event: dict[str, Any], timeout: float) -> dict[str, Any]:
    event_id = str(uuid4())
    row = await conn.fetchrow(
        f"""INSERT INTO daos_memory.context_events ({_EVENT_COLUMNS}) VALUES
        ($1::uuid,now(),COALESCE($2::timestamptz,now()),
         COALESCE($3::timestamptz,$2::timestamptz,now()),$4::timestamptz,
         COALESCE($5::timestamptz,$2::timestamptz,now()),
         $6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21::uuid,$22::jsonb)
        RETURNING {_EVENT_COLUMNS}""",
        event_id,
        event.get("occurred_at"), event.get("effective_from"), event.get("effective_to"),
        event.get("source_session_at"), event["actor"], event["actor_role"],
        event["source_interface"], event["product"], event["topic"], event.get("thread_id"),
        event.get("work_id"), event["memory_type"], event["event_type"], event["title"],
        event["summary"], event["content"], event["status"], event["authority_level"],
        event.get("source_ref"), event.get("supersedes_id"),
        json.dumps(event.get("metadata") or {}), timeout=timeout,
    )
    return _record(row)


def _record(row) -> dict[str, Any]:
    value = dict(row)
    value["id"] = str(value["id"])
    if value.get("supersedes_id") is not None:
        value["supersedes_id"] = str(value["supersedes_id"])
    return value


def _source_record(row, *, include_content: bool = True) -> dict[str, Any]:
    value = dict(row)
    value["id"] = str(value["id"])
    if isinstance(value.get("metadata"), str):
        value["metadata"] = json.loads(value["metadata"])
    if not include_content:
        value.pop("content", None)
    return value


def _json_record(row) -> dict[str, Any]:
    value = dict(row)
    if value.get("id") is not None:
        value["id"] = str(value["id"])
    for key, item in list(value.items()):
        if isinstance(item, UUID):
            value[key] = str(item)
        elif isinstance(item, list):
            value[key] = [str(part) if isinstance(part, UUID) else part for part in item]
    return value


def _relation_record(row) -> dict[str, Any]:
    value = dict(row)
    value["id"] = str(value["id"])
    if isinstance(value.get("metadata"), str):
        value["metadata"] = json.loads(value["metadata"])
    for key in ("from_event_id", "from_source_id", "to_event_id", "to_source_id"):
        if value.get(key) is not None:
            value[key] = str(value[key])
    return value
