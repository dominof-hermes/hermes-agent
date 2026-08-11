from __future__ import annotations

import asyncio
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from plugins.daos_memory.service.store import AsyncpgStore


class _Transaction(AbstractAsyncContextManager):
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        self.connection.in_transaction = True
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        self.connection.transaction_exception = exc
        self.connection.in_transaction = False
        return False


class _Acquire(AbstractAsyncContextManager):
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class RecordingConnection:
    def __init__(self, *, eligible: bool, fail_relation: bool = False):
        self.eligible = eligible
        self.fail_relation = fail_relation
        self.in_transaction = False
        self.transaction_exception = None
        self.fetches = []
        self.executes = []

    def transaction(self):
        return _Transaction(self)

    async def fetchrow(self, sql, *args, **kwargs):
        assert self.in_transaction
        self.fetches.append((sql, args, kwargs))
        if "SELECT id FROM daos_memory.context_events" in sql:
            return {"id": args[0]} if self.eligible else None
        event_id = args[0]
        return {
            "id": event_id,
            "created_at": datetime.now(timezone.utc),
            "actor": args[1],
            "actor_role": args[2],
            "source_interface": args[3],
            "product": args[4],
            "topic": args[5],
            "thread_id": args[6],
            "work_id": args[7],
            "memory_type": args[8],
            "event_type": args[9],
            "title": args[10],
            "summary": args[11],
            "content": args[12],
            "status": args[13],
            "authority_level": args[14],
            "source_ref": args[15],
            "supersedes_id": args[16],
            "metadata": {},
        }

    async def execute(self, sql, *args, **kwargs):
        assert self.in_transaction
        self.executes.append((sql, args, kwargs))
        if self.fail_relation and "context_relations" in sql:
            raise RuntimeError("relation insert failed")
        return "OK"


class RecordingPool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        return _Acquire(self.connection)


def _event():
    return {
        "actor": "zeus",
        "actor_role": "ZEUS",
        "source_interface": "test",
        "product": "DAOS",
        "topic": "memory",
        "thread_id": None,
        "work_id": None,
        "memory_type": "ASSESSMENT",
        "event_type": "NOTE",
        "title": "replacement",
        "summary": "replacement",
        "content": "replacement",
        "status": "CURRENT",
        "authority_level": "AGENT_ASSESSMENT",
        "source_ref": None,
        "supersedes_id": None,
        "metadata": {},
    }


def test_supersede_eligibility_is_locked_by_actor_authority_and_topic_before_mutation():
    connection = RecordingConnection(eligible=False)
    store = AsyncpgStore("postgresql://ignored")
    store._pool = RecordingPool(connection)
    old_id = str(uuid4())

    result = asyncio.run(store.supersede_event(old_id, "zeus", _event()))

    assert result is None
    assert connection.executes == []
    sql, args, _ = connection.fetches[0]
    assert "FOR UPDATE" in sql
    assert "actor=$2" in sql
    assert "product=$3" in sql and "topic=$4" in sql
    assert "authority_level IN ('AGENT_ASSESSMENT','HYPOTHESIS','OPERATIONAL_STATE')" in sql
    assert args == (old_id, "zeus", "DAOS", "memory")


def test_supersede_history_replacement_and_relation_share_one_transaction():
    connection = RecordingConnection(eligible=True, fail_relation=True)
    store = AsyncpgStore("postgresql://ignored")
    store._pool = RecordingPool(connection)

    with pytest.raises(RuntimeError, match="relation insert failed"):
        asyncio.run(store.supersede_event(str(uuid4()), "zeus", _event()))

    assert len(connection.executes) == 2
    assert "SET status='SUPERSEDED'" in connection.executes[0][0]
    assert "context_relations" in connection.executes[1][0]
    assert isinstance(connection.transaction_exception, RuntimeError)
