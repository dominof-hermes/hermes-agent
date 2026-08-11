"""Bounded asyncpg persistence for the isolated DAOS Memory service."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import uuid4

import asyncpg


_EVENT_COLUMNS = """id, created_at, occurred_at, effective_from, effective_to, source_session_at,
actor, actor_role, source_interface, product, topic, thread_id, work_id, memory_type,
event_type, title, summary, content, status, authority_level, source_ref, supersedes_id, metadata"""
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
            """SELECT id, category, title, content, status, priority, updated_at
            FROM daos_memory.canonical_policies WHERE status='ACTIVE' AND category=ANY($1::text[])
            ORDER BY priority DESC, updated_at DESC LIMIT $2""",
            categories, limit, timeout=self.timeout,
        )
        return [dict(r) for r in rows]

    async def read_current(self, product: str | None, topic: str | None, limit: int):
        return await self._events("status='CURRENT'", product, topic, None, limit)

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
        clauses = {
            "current": "status='CURRENT'",
            "decisions": "memory_type='DECISION'",
            "policies": "(memory_type='POLICY' OR event_type='POLICY')",
            "agent_notes": "authority_level IN ('AGENT_ASSESSMENT','HYPOTHESIS')",
            "history": "status<>'CURRENT'",
            "knowledge_vault": "memory_type IN ('RESEARCH','ARCHITECTURE_ASSESSMENT','DESIGN_PROPOSAL','EVIDENCE','TECHNICAL_RESULT','SESSION_SUMMARY')",
        }
        return await self._events(clauses.get(view, "status='CURRENT'"), product, topic, None, limit)


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
