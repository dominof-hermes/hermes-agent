from __future__ import annotations

import logging
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from plugins.daos_memory.service.app import create_app
from plugins.daos_memory.service.auth import hash_credential
from plugins.daos_memory.service.config import Settings


NOW = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


class FakeStore:
    def __init__(self):
        self.agents = {
            "zeus": {
                "agent_id": "zeus",
                "status": "ACTIVE",
                "role_categories": ["STRATEGY"],
                "allowed_memory_types": ["STRATEGY", "ASSESSMENT", "SESSION_SUMMARY"],
                "bootstrap_key_hash": None,
                "bootstrap_expires_at": None,
                "bootstrap_uses_remaining": 0,
                "access_token_hash": None,
                "access_expires_at": None,
                "last_access_at": None,
            }
        }
        self.policies = [
            {"id": "p-global", "category": "GLOBAL", "title": "Truth First", "content": "Verify claims", "status": "ACTIVE", "priority": 1},
            {"id": "p-role", "category": "STRATEGY", "title": "Strategy", "content": "Prioritize", "status": "ACTIVE", "priority": 1},
            {"id": "p-other", "category": "DEVELOPMENT", "title": "Development", "content": "Test first", "status": "ACTIVE", "priority": 1},
            {"id": "p-agent", "category": "ZEUS", "title": "Agent-specific", "content": "must not leak", "status": "ACTIVE", "priority": 1},
        ]
        self.events = [
            self._event("DAOS", "memory", "DECISION", "Owner chose API", "CURRENT", "OWNER_DECISION", "owner"),
            self._event("Other", "unrelated", "DECISION", "Do not include", "CURRENT", "OWNER_DECISION", "owner"),
            self._event("DAOS", "memory", "NEXT_ACTION", "Ship v0.1", "CURRENT", "OPERATIONAL_STATE", "hermes"),
            self._event("DAOS", "memory", "ASSESSMENT", "Old note", "SUPERSEDED", "AGENT_ASSESSMENT", "zeus"),
        ]
        self.relations = []
        self.healthy = True

    @staticmethod
    def _event(product, topic, memory_type, summary, status, authority_level, actor):
        return {
            "id": str(uuid4()), "created_at": NOW, "actor": actor, "actor_role": actor.upper(),
            "source_interface": "test", "product": product, "topic": topic, "thread_id": None,
            "work_id": None, "memory_type": memory_type, "event_type": memory_type,
            "title": summary, "summary": summary, "content": summary, "status": status,
            "authority_level": authority_level, "source_ref": None, "supersedes_id": None,
            "metadata": {},
        }

    async def health(self):
        if not self.healthy:
            raise TimeoutError("database unavailable")
        return True

    async def get_agent(self, agent_id):
        value = self.agents.get(agent_id)
        return deepcopy(value) if value else None

    async def rotate_bootstrap(self, agent_id, key_hash, expires_at, max_uses):
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        agent.update(bootstrap_key_hash=key_hash, bootstrap_expires_at=expires_at, bootstrap_uses_remaining=max_uses)
        return deepcopy(agent)

    async def revoke_agent(self, agent_id):
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        agent.update(status="REVOKED", bootstrap_key_hash=None, bootstrap_uses_remaining=0,
                     access_token_hash=None, access_expires_at=None)
        return deepcopy(agent)

    async def consume_bootstrap(self, agent_id, key_hash, now):
        agent = self.agents.get(agent_id)
        if not agent or agent["status"] != "ACTIVE" or agent["bootstrap_key_hash"] != key_hash:
            return None
        if agent["bootstrap_expires_at"] <= now or agent["bootstrap_uses_remaining"] <= 0:
            return None
        agent["bootstrap_uses_remaining"] -= 1
        agent["last_access_at"] = now
        if agent["bootstrap_uses_remaining"] == 0:
            agent["bootstrap_key_hash"] = None
        return deepcopy(agent)

    async def set_access_token(self, agent_id, token_hash, expires_at):
        self.agents[agent_id].update(access_token_hash=token_hash, access_expires_at=expires_at)

    async def authenticate_access(self, token_hash, now):
        for agent in self.agents.values():
            if (agent["status"] == "ACTIVE" and agent["access_token_hash"] == token_hash
                    and agent["access_expires_at"] and agent["access_expires_at"] > now):
                agent["last_access_at"] = now
                return deepcopy(agent)
        return None

    async def get_policies(self, categories, limit):
        return [deepcopy(p) for p in self.policies if p["status"] == "ACTIVE" and p["category"] in categories][:limit]

    async def read_current(self, product, topic, limit):
        rows = [e for e in self.events if e["status"] == "CURRENT"]
        if product:
            rows = [e for e in rows if e["product"] == product]
        if topic:
            rows = [e for e in rows if e["topic"] == topic]
        return deepcopy(rows[:limit])

    async def search_history(self, product, topic, query, limit):
        rows = [e for e in self.events if e["status"] != "CURRENT"]
        if product:
            rows = [e for e in rows if e["product"] == product]
        if topic:
            rows = [e for e in rows if e["topic"] == topic]
        if query:
            q = query.casefold()
            rows = [e for e in rows if q in (e["summary"] + " " + e["content"]).casefold()]
        return deepcopy(rows[:limit])

    async def write_event(self, event):
        row = {**event, "id": str(uuid4()), "created_at": NOW}
        self.events.append(row)
        return deepcopy(row)

    async def supersede_event(self, old_id, event):
        old = next((e for e in self.events if e["id"] == old_id and e["status"] == "CURRENT"), None)
        if not old:
            return None
        old["status"] = "SUPERSEDED"
        row = await self.write_event({**event, "status": "CURRENT", "supersedes_id": old_id})
        self.relations.append({"from_event_id": row["id"], "to_event_id": old_id, "relation_type": "SUPERSEDES"})
        return row

    async def list_agents(self, limit):
        return [deepcopy(v) for v in self.agents.values()][:limit]

    async def admin_events(self, view, product, topic, limit):
        rows = self.events
        if view == "decisions": rows = [e for e in rows if e["memory_type"] == "DECISION"]
        elif view == "agent_notes": rows = [e for e in rows if e["authority_level"] in {"AGENT_ASSESSMENT", "HYPOTHESIS"}]
        elif view == "history": rows = [e for e in rows if e["status"] != "CURRENT"]
        else: rows = [e for e in rows if e["status"] == "CURRENT"]
        return deepcopy(rows[:limit])


@pytest.fixture
def store():
    return FakeStore()


@pytest.fixture
def settings():
    return Settings(database_url="postgresql://ignored", owner_token="owner-secret", credential_pepper="test-pepper",
                    bootstrap_ttl_seconds=300, access_ttl_seconds=600, max_bootstrap_uses=1,
                    max_bootstrap_bytes=12_000, max_results=25, query_timeout_seconds=1.0)


@pytest.fixture
def client(store, settings):
    return TestClient(create_app(settings=settings, store=store, clock=lambda: NOW))


def rotate(client, agent_id="zeus"):
    response = client.post(f"/v1/admin/agents/{agent_id}/rotate", headers={"Authorization": "Bearer owner-secret"})
    assert response.status_code == 200
    return response.json()["bootstrap_key"]


def bootstrap(client, key, **body):
    return client.post("/v1/bootstrap", headers={"Authorization": f"Bearer {key}"}, json={"agent_id": "zeus", **body})


def access(client, **body):
    key = rotate(client)
    response = bootstrap(client, key, **body)
    assert response.status_code == 200
    return response.json()["access_token"], response.json()


def test_health_reports_service_and_dependency_state(client, store):
    assert client.get("/health").json() == {"status": "ok", "database": "ok"}
    store.healthy = False
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["database"] == "unavailable"


def test_bearer_header_is_required_and_credentials_are_rejected_in_url(client, caplog):
    caplog.set_level(logging.DEBUG, logger="plugins.daos_memory")
    assert client.post("/v1/bootstrap", json={"agent_id": "zeus"}).status_code == 401
    assert client.post("/v1/bootstrap?key=secret-in-url", json={"agent_id": "zeus"}).status_code == 400
    assert "secret-in-url" not in caplog.text


def test_owner_auth_rotation_stores_only_hash_and_secret_is_one_response(client, store, settings):
    assert client.get("/v1/admin/agents").status_code == 401
    key = rotate(client)
    assert key not in repr(store.agents)
    assert store.agents["zeus"]["bootstrap_key_hash"] == hash_credential(key, settings.credential_pepper)
    listed = client.get("/v1/admin/agents", headers={"Authorization": "Bearer owner-secret"}).json()
    assert "bootstrap_key" not in repr(listed)
    assert "owner-secret" not in repr(listed)


def test_bootstrap_key_is_one_use_short_lived_and_revocable(client, store):
    key = rotate(client)
    assert bootstrap(client, key).status_code == 200
    assert bootstrap(client, key).status_code == 401

    key = rotate(client)
    store.agents["zeus"]["bootstrap_expires_at"] = NOW - timedelta(seconds=1)
    assert bootstrap(client, key).status_code == 401

    key = rotate(client)
    assert client.post("/v1/admin/agents/zeus/revoke", headers={"Authorization": "Bearer owner-secret"}).status_code == 200
    assert bootstrap(client, key).status_code == 401


def test_bootstrap_is_current_first_scoped_and_bounded_without_history(client, settings):
    key = rotate(client)
    response = bootstrap(client, key, product="DAOS", topic="memory")
    assert response.status_code == 200
    assert len(response.content) < settings.max_bootstrap_bytes
    payload = response.json()
    token = payload["access_token"]
    assert payload["history"] == []
    assert {p["category"] for p in payload["global_principles"]} == {"GLOBAL"}
    assert {p["category"] for p in payload["role_principles"]} == {"STRATEGY"}
    assert all(e["product"] == "DAOS" and e["topic"] == "memory" for e in payload["current_context"])
    assert "Do not include" not in repr(payload)
    assert len(client.get("/v1/current", headers={"Authorization": f"Bearer {token}"}, params={"product": "DAOS", "topic": "memory", "limit": 999}).json()["items"]) <= settings.max_results
    assert len(client.post("/v1/bootstrap", headers={"Authorization": "Bearer invalid"}, json={"agent_id": "zeus"}).content) < settings.max_bootstrap_bytes


def test_current_supersede_and_bounded_history_retain_old_event(client, store):
    token, _ = access(client, product="DAOS", topic="memory")
    headers = {"Authorization": f"Bearer {token}"}
    old_id = store.events[0]["id"]
    response = client.post(f"/v1/events/{old_id}/supersede", headers=headers, json={
        "product": "DAOS", "topic": "memory", "memory_type": "STRATEGY", "event_type": "STRATEGY",
        "title": "New direction", "summary": "New direction", "content": "Current plan", "source_interface": "chatgpt",
        "authority_level": "AGENT_ASSESSMENT", "metadata": {},
    })
    assert response.status_code == 200
    current = client.get("/v1/current", headers=headers, params={"product": "DAOS", "topic": "memory"}).json()["items"]
    assert any(e["title"] == "New direction" for e in current)
    assert all(e["id"] != old_id for e in current)
    history = client.get("/v1/history", headers=headers, params={"topic": "memory", "limit": 999}).json()["items"]
    assert len(history) <= 25
    assert any(e["id"] == old_id and e["status"] == "SUPERSEDED" for e in history)


def test_writer_restrictions_and_owner_authority_protection(client):
    token, _ = access(client)
    headers = {"Authorization": f"Bearer {token}"}
    base = {"product": "DAOS", "topic": "memory", "event_type": "NOTE", "title": "x", "summary": "x",
            "content": "x", "source_interface": "chatgpt", "metadata": {}}
    denied_type = client.post("/v1/events", headers=headers, json={**base, "memory_type": "EVIDENCE", "authority_level": "AGENT_ASSESSMENT"})
    assert denied_type.status_code == 403
    denied_authority = client.post("/v1/events", headers=headers, json={**base, "memory_type": "STRATEGY", "authority_level": "OWNER_DECISION"})
    assert denied_authority.status_code == 403
    allowed = client.post("/v1/events", headers=headers, json={**base, "memory_type": "ASSESSMENT", "authority_level": "AGENT_ASSESSMENT"})
    assert allowed.status_code == 201
    assert allowed.json()["actor"] == "zeus"


def test_access_token_expires_and_is_revoked_with_agent(client, store):
    token, _ = access(client)
    store.agents["zeus"]["access_expires_at"] = NOW - timedelta(seconds=1)
    assert client.get("/v1/current", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    token, _ = access(client)
    client.post("/v1/admin/agents/zeus/revoke", headers={"Authorization": "Bearer owner-secret"})
    assert client.get("/v1/current", headers={"Authorization": f"Bearer {token}"}).status_code == 401
