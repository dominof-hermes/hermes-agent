from __future__ import annotations

import logging
import hashlib
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from plugins.daos_memory.service.app import create_app
from plugins.daos_memory.service.auth import hash_credential
from plugins.daos_memory.service.config import Settings
from plugins.daos_memory.scripts.import_source_grounded_pilot import _validate_manifest
from plugins.daos_memory.service.models import SourceWrite


NOW = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


def test_pilot_manifest_rejects_duplicate_relation_ids():
    with pytest.raises(ValueError, match="relation ids must be unique"):
        _validate_manifest({"relations": [{"id": "same"}, {"id": "same"}]})


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
            },
            "apollo": {
                "agent_id": "apollo",
                "status": "ACTIVE",
                "role_categories": ["STRATEGY"],
                "allowed_memory_types": ["STRATEGY", "ASSESSMENT", "SESSION_SUMMARY"],
                "bootstrap_key_hash": None,
                "bootstrap_expires_at": None,
                "bootstrap_uses_remaining": 0,
                "access_token_hash": None,
                "access_expires_at": None,
                "last_access_at": None,
            },
        }
        self.policies = [
            {"id": "p-global", "category": "GLOBAL", "title": "Truth First", "content": "Verify claims", "status": "ACTIVE", "priority": 1},
            {"id": "p-role", "category": "STRATEGY", "title": "Strategy", "content": "Prioritize", "status": "ACTIVE", "priority": 1},
            {"id": "p-other", "category": "DEVELOPMENT", "title": "Development", "content": "Test first", "status": "ACTIVE", "priority": 1},
            {"id": "p-agent", "category": "ZEUS", "title": "Agent-specific", "content": "must not leak", "status": "ACTIVE", "priority": 1},
        ]
        self.events = [
            self._event("DAOS", "memory", "DECISION", "Owner chose API", "CURRENT", "OWNER_DECISION", "owner"),
            self._event("DAOS", "memory", "EVIDENCE", "Verified benchmark", "CURRENT", "VERIFIED_EVIDENCE", "owner"),
            self._event("Other", "unrelated", "DECISION", "Do not include", "CURRENT", "OWNER_DECISION", "owner"),
            self._event("DAOS", "memory", "NEXT_ACTION", "Ship v0.1", "CURRENT", "OPERATIONAL_STATE", "hermes"),
            self._event("DAOS", "memory", "NEXT_ACTION", "Owner follow-up", "CURRENT", "OWNER_DECISION", "owner"),
            self._event("DAOS", "memory", "ASSESSMENT", "Zeus current note", "CURRENT", "AGENT_ASSESSMENT", "zeus"),
            self._event("DAOS", "memory", "ASSESSMENT", "Apollo current note", "CURRENT", "AGENT_ASSESSMENT", "apollo"),
            self._event("DAOS", "memory", "ASSESSMENT", "Old note", "SUPERSEDED", "AGENT_ASSESSMENT", "zeus"),
        ]
        self.relations = []
        source_content = "# Raw source\n\nOwner and Zeus discussed source-grounded memory."
        self.sources = [{
            "id": str(uuid4()), "source_type": "CHAT_CONVERSATION", "title": "Raw source",
            "source_interface": "slack", "actor": "owner", "participants": ["owner", "zeus"],
            "repository": None, "path": None, "commit_sha": None, "source_url": None,
            "occurred_at": NOW, "source_session_at": NOW, "indexed_at": NOW,
            "content": source_content, "content_hash": hashlib.sha256(source_content.encode()).hexdigest(),
            "access_scope": "OWNER", "security_level": "INTERNAL",
            "redaction_status": "REVIEWED_NO_SECRETS", "metadata": {},
        }]
        self.healthy = True

    @staticmethod
    def _event(product, topic, memory_type, summary, status, authority_level, actor):
        return {
            "id": str(uuid4()), "created_at": NOW, "occurred_at": NOW,
            "effective_from": NOW, "effective_to": None, "source_session_at": NOW,
            "actor": actor, "actor_role": actor.upper(),
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
        occurred_at = event.get("occurred_at") or NOW
        row = {
            **event,
            "id": str(uuid4()),
            "created_at": NOW,
            "occurred_at": occurred_at,
            "effective_from": event.get("effective_from") or occurred_at,
            "effective_to": event.get("effective_to"),
            "source_session_at": event.get("source_session_at") or occurred_at,
        }
        self.events.append(row)
        return deepcopy(row)

    async def read_event(self, event_id):
        row = next((e for e in self.events if e["id"] == event_id), None)
        return deepcopy(row) if row else None

    async def supersede_event(self, old_id, actor_id, event):
        old = next((e for e in self.events if e["id"] == old_id and e["status"] == "CURRENT"
                    and e["actor"] == actor_id
                    and e["authority_level"] in {"AGENT_ASSESSMENT", "HYPOTHESIS", "OPERATIONAL_STATE"}
                    and e["product"] == event["product"] and e["topic"] == event["topic"]), None)
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
        elif view == "policies": rows = [e for e in rows if e["memory_type"] == "POLICY" or e["event_type"] == "POLICY"]
        elif view == "agent_notes": rows = [e for e in rows if e["authority_level"] in {"AGENT_ASSESSMENT", "HYPOTHESIS"}]
        elif view == "history": rows = [e for e in rows if e["status"] != "CURRENT"]
        elif view == "knowledge_vault": rows = [e for e in rows if e["memory_type"] in {"RESEARCH", "ARCHITECTURE_ASSESSMENT", "DESIGN_PROPOSAL", "EVIDENCE", "TECHNICAL_RESULT", "SESSION_SUMMARY"}]
        else: rows = [e for e in rows if e["status"] == "CURRENT"]
        return deepcopy(rows[:limit])

    async def read_operational_current(self, product, topic, limit):
        rows = [e for e in self.events if e["status"] == "CURRENT" and e["memory_type"] in {"EXECUTION", "NEXT_ACTION", "OPERATIONAL_STATE"}]
        return deepcopy(rows[:limit])

    async def read_active_knowledge(self, product, topic, limit):
        rows = [e for e in self.events if e["status"] == "CURRENT" and e["memory_type"] in {"STRATEGY", "RESEARCH", "EVIDENCE", "ARCHITECTURE_ASSESSMENT", "DESIGN_PROPOSAL", "IDEA", "DESIGN_OPTION", "LESSON_LEARNED", "ENGINEERING_KNOWLEDGE", "ARCHITECTURE_DECISION"}]
        return deepcopy(rows[:limit])

    async def read_source(self, source_id):
        return deepcopy(next((s for s in self.sources if s["id"] == source_id), None))

    async def read_event_knowledge(self, event_id):
        source = deepcopy(self.sources[0])
        return {
            "event_id": event_id, "evidence_status": "grounded", "related_events": [],
            "sources": [source],
            "relations": [{
                "id": str(uuid4()), "relation_type": "SUMMARIZES",
                "from_event_id": event_id, "from_source_id": None,
                "to_event_id": None, "to_source_id": source["id"],
            }],
        }

    async def write_source(self, source):
        row = {**deepcopy(source), "id": str(uuid4()), "indexed_at": NOW}
        self.sources.append(row)
        return deepcopy(row)

    async def write_knowledge_relation(self, relation):
        row = {**deepcopy(relation), "id": str(uuid4()), "created_at": NOW}
        self.relations.append(row)
        return deepcopy(row)

    async def write_decision(self, actor, values):
        row = {**deepcopy(values), "id": str(uuid4()), "proposed_by": actor,
               "stored_at": NOW, "status": "PENDING_OWNER_CONFIRM",
               "authority_level": "AGENT_ASSESSMENT", "owner_comment": None, "approved_at": None}
        self.events.append(row)
        return deepcopy(row)

    async def decide(self, decision_id, result, owner_comment):
        row = next((item for item in self.events if item.get("id") == decision_id and item.get("status") == "PENDING_OWNER_CONFIRM"), None)
        if not row:
            return None
        row.update(status=result, owner_comment=owner_comment,
                   authority_level="OWNER_DECISION" if result == "APPROVED" else "AGENT_ASSESSMENT",
                   approved_at=NOW if result == "APPROVED" else None)
        return deepcopy(row)

    async def write_policy(self, values):
        version = 1 + max((item.get("version", 0) for item in self.policies
                           if item.get("category") == values["category"] and item.get("title") == values["title"]), default=0)
        row = {**deepcopy(values), "id": str(uuid4()), "version": version, "created_at": NOW, "updated_at": NOW}
        self.policies.append(row)
        return deepcopy(row)

    async def write_current_context(self, actor, values):
        row = {**deepcopy(values), "id": str(uuid4()), "actor": actor, "stored_at": NOW, "status": "CURRENT"}
        return row

    async def write_agent_note(self, actor, actor_role, values):
        return {**deepcopy(values), "id": str(uuid4()), "actor": actor, "actor_role": actor_role, "stored_at": NOW}


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
    assert {e["title"] for e in payload["owner_decisions"]} == {"Owner chose API"}
    assert all("source_ref" in e for key in ("current_context", "owner_decisions", "next_actions") for e in payload[key])
    assert all(
        {"created_at", "occurred_at", "effective_from", "effective_to", "source_session_at"} <= set(e)
        for key in ("current_context", "owner_decisions", "next_actions") for e in payload[key]
    )
    assert "Owner follow-up" in {e["title"] for e in payload["next_actions"]}
    assert "Owner follow-up" not in {e["title"] for e in payload["owner_decisions"]}
    assert "Do not include" not in repr(payload)
    assert len(client.get("/v1/current", headers={"Authorization": f"Bearer {token}"}, params={"product": "DAOS", "topic": "memory", "limit": 999}).json()["items"]) <= settings.max_results
    assert len(client.post("/v1/bootstrap", headers={"Authorization": "Bearer invalid"}, json={"agent_id": "zeus"}).content) < settings.max_bootstrap_bytes


def test_current_supersede_and_bounded_history_retain_old_event(client, store):
    token, _ = access(client, product="DAOS", topic="memory")
    headers = {"Authorization": f"Bearer {token}"}
    old_id = next(e["id"] for e in store.events if e["title"] == "Zeus current note")
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


def test_read_event_requires_agent_token_and_returns_exact_event(client, store):
    event_id = next(e["id"] for e in store.events if e["title"] == "Owner chose API")
    assert client.get(f"/v1/events/{event_id}").status_code == 401

    token, _ = access(client)
    response = client.get(
        f"/v1/events/{event_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == event_id
    assert client.get(
        f"/v1/events/{uuid4()}",
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 404


def test_owner_can_read_exact_event_without_mutation(client, store):
    event = next(e for e in store.events if e["title"] == "Owner chose API")
    before = deepcopy(store.events)

    assert client.get(f"/v1/admin/events/{event['id']}").status_code == 401
    response = client.get(
        f"/v1/admin/events/{event['id']}",
        headers={"Authorization": "Bearer owner-secret"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == event["id"]
    assert store.events == before
    assert client.get(
        f"/v1/admin/events/{uuid4()}",
        headers={"Authorization": "Bearer owner-secret"},
    ).status_code == 404


@pytest.mark.parametrize("title", ["Owner chose API", "Verified benchmark", "Apollo current note"])
def test_agent_cannot_supersede_protected_or_other_actor_current_event(client, store, title):
    token, _ = access(client, product="DAOS", topic="memory")
    old = next(e for e in store.events if e["title"] == title)
    before = deepcopy(store.events)
    response = client.post(
        f"/v1/events/{old['id']}/supersede",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "product": "DAOS", "topic": "memory", "memory_type": "STRATEGY",
            "event_type": "STRATEGY", "title": "Unauthorized replacement",
            "summary": "Unauthorized replacement", "content": "must not persist",
            "source_interface": "chatgpt", "authority_level": "AGENT_ASSESSMENT", "metadata": {},
        },
    )
    assert response.status_code == 404
    assert store.events == before
    assert store.relations == []


def test_agent_cannot_supersede_own_event_into_another_product_or_topic(client, store):
    token, _ = access(client, product="DAOS", topic="memory")
    old = next(e for e in store.events if e["title"] == "Zeus current note")
    before = deepcopy(store.events)
    response = client.post(
        f"/v1/events/{old['id']}/supersede",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "product": "Other", "topic": "memory", "memory_type": "STRATEGY",
            "event_type": "STRATEGY", "title": "Cross-product replacement",
            "summary": "Cross-product replacement", "content": "must not persist",
            "source_interface": "chatgpt", "authority_level": "AGENT_ASSESSMENT", "metadata": {},
        },
    )
    assert response.status_code == 404
    assert store.events == before
    assert store.relations == []


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


def test_explicit_session_time_is_stored_as_history_and_excluded_from_bootstrap(client):
    token, _ = access(client, product="DAOS", topic="memory")
    occurred = "2026-06-18T09:00:00+00:00"
    response = client.post("/v1/events", headers={"Authorization": f"Bearer {token}"}, json={
        "product": "DAOS", "topic": "memory", "memory_type": "SESSION_SUMMARY",
        "event_type": "HISTORY_IMPORT", "title": "June imported session",
        "summary": "Historical conversation imported in August", "content": "Historical content",
        "source_interface": "chatgpt", "authority_level": "AGENT_ASSESSMENT",
        "occurred_at": occurred, "source_session_at": occurred,
        "effective_from": occurred, "effective_to": "2026-06-19T09:00:00+00:00",
        "metadata": {},
    })

    assert response.status_code == 201
    imported = response.json()
    assert imported["created_at"] == NOW.isoformat()
    assert datetime.fromisoformat(imported["occurred_at"].replace("Z", "+00:00")) == datetime.fromisoformat(occurred)
    assert datetime.fromisoformat(imported["source_session_at"].replace("Z", "+00:00")) == datetime.fromisoformat(occurred)
    assert imported["status"] == "HISTORY"
    current = client.get("/v1/current", headers={"Authorization": f"Bearer {token}"}).json()["items"]
    assert imported["id"] not in {item["id"] for item in current}
    history = client.get("/v1/history", headers={"Authorization": f"Bearer {token}"}, params={"topic": "memory"}).json()["items"]
    assert imported["id"] in {item["id"] for item in history}

    key = rotate(client)
    restored = bootstrap(client, key, product="DAOS", topic="memory").json()
    assert imported["id"] not in {item["id"] for item in restored["current_context"]}
    assert "Owner chose API" in {item["title"] for item in restored["owner_decisions"]}


def test_historical_import_cannot_use_supersede_to_replace_current(client, store):
    token, _ = access(client, product="DAOS", topic="memory")
    old = next(item for item in store.events if item["title"] == "Zeus current note")
    before = deepcopy(store.events)
    response = client.post(
        f"/v1/events/{old['id']}/supersede",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "product": "DAOS", "topic": "memory", "memory_type": "STRATEGY",
            "event_type": "HISTORY_IMPORT", "title": "Old imported direction",
            "summary": "Old imported direction", "content": "Old historical plan",
            "source_interface": "chatgpt", "authority_level": "AGENT_ASSESSMENT",
            "occurred_at": "2026-06-18T09:00:00+00:00",
            "source_session_at": "2026-06-18T09:00:00+00:00",
            "metadata": {},
        },
    )
    assert response.status_code == 409
    assert store.events == before
    assert store.relations == []


def test_history_import_intent_requires_original_session_times_and_never_becomes_current(client, store):
    token, _ = access(client, product="DAOS", topic="memory")
    headers = {"Authorization": f"Bearer {token}"}
    old = next(item for item in store.events if item["title"] == "Zeus current note")
    before = deepcopy(store.events)
    payload = {
        "product": "DAOS", "topic": "memory", "memory_type": "SESSION_SUMMARY",
        "event_type": "HISTORY_IMPORT", "title": "Undated prior session",
        "summary": "historical intent without source time", "content": "must fail closed",
        "source_interface": "chatgpt", "authority_level": "AGENT_ASSESSMENT", "metadata": {},
    }

    write = client.post("/v1/events", headers=headers, json=payload)
    supersede = client.post(f"/v1/events/{old['id']}/supersede", headers=headers, json=payload)
    padded_write = client.post("/v1/events", headers=headers, json={
        **payload, "event_type": " HISTORY_IMPORT ",
    })
    padded_supersede = client.post(f"/v1/events/{old['id']}/supersede", headers=headers, json={
        **payload, "event_type": " history_import ",
    })

    assert write.status_code == supersede.status_code == 422
    assert padded_write.status_code == padded_supersede.status_code == 422
    assert store.events == before
    assert store.relations == []


def test_event_metadata_over_json_byte_cap_is_rejected(client):
    token, _ = access(client)
    response = client.post(
        "/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "product": "DAOS", "topic": "memory", "memory_type": "ASSESSMENT",
            "event_type": "NOTE", "title": "bounded", "summary": "bounded",
            "content": "bounded", "source_interface": "chatgpt",
            "authority_level": "AGENT_ASSESSMENT", "metadata": {"value": "x" * 4096},
        },
    )
    assert response.status_code == 422
    assert "metadata must not exceed 4096 JSON bytes" in response.text


def test_access_token_expires_and_is_revoked_with_agent(client, store):
    token, _ = access(client)
    store.agents["zeus"]["access_expires_at"] = NOW - timedelta(seconds=1)
    assert client.get("/v1/current", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    token, _ = access(client)
    client.post("/v1/admin/agents/zeus/revoke", headers={"Authorization": "Bearer owner-secret"})
    assert client.get("/v1/current", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_bootstrap_prioritizes_operational_current_and_bounds_topic_active_knowledge(client):
    key = rotate(client)
    payload = bootstrap(client, key, product="DAOS", topic="memory").json()

    assert payload["history"] == []
    assert payload["current_context"] == []
    assert {item["title"] for item in payload["next_actions"]} == {"Ship v0.1", "Owner follow-up"}
    assert {item["title"] for item in payload["active_knowledge"]} == {"Verified benchmark"}


def test_operational_next_actions_are_not_starved_by_twenty_higher_authority_knowledge_rows(client, store):
    template = deepcopy(next(event for event in store.events if event["title"] == "Verified benchmark"))
    saturated = []
    for index in range(25):
        item = deepcopy(template)
        item.update(id=str(uuid4()), title=f"High authority knowledge {index}", summary=f"High authority knowledge {index}")
        saturated.append(item)
    store.events = saturated + store.events

    key = rotate(client)
    payload = bootstrap(client, key, product="DAOS", topic="memory").json()

    assert {item["title"] for item in payload["next_actions"]} == {"Ship v0.1", "Owner follow-up"}
    assert len(payload["active_knowledge"]) <= 5


def test_owner_can_follow_event_knowledge_to_raw_source_without_mutation(client, store):
    event = next(e for e in store.events if e["title"] == "Owner chose API")
    before_events = deepcopy(store.events)
    before_sources = deepcopy(store.sources)

    knowledge = client.get(
        f"/v1/admin/events/{event['id']}/knowledge",
        headers={"Authorization": "Bearer owner-secret"},
    )
    assert knowledge.status_code == 200
    assert knowledge.json()["evidence_status"] == "grounded"
    source_id = knowledge.json()["sources"][0]["id"]
    source = client.get(
        f"/v1/admin/sources/{source_id}",
        headers={"Authorization": "Bearer owner-secret"},
    )
    assert source.status_code == 200
    assert source.json()["content"].startswith("# Raw source")
    assert source.json()["content_hash"] == hashlib.sha256(source.json()["content"].encode()).hexdigest()
    assert store.events == before_events and store.sources == before_sources


def test_source_write_requires_exact_hash_and_rejects_embedded_credentials():
    content = "# Reviewed source\n\nNo credentials are present."
    base = {
        "source_type": "CHAT_CONVERSATION", "title": "Reviewed source",
        "source_interface": "slack", "actor": "owner", "participants": ["owner", "zeus"],
        "occurred_at": NOW, "source_session_at": NOW, "content": content,
        "content_hash": hashlib.sha256(content.encode()).hexdigest(),
        "access_scope": "OWNER", "security_level": "INTERNAL",
        "redaction_status": "REVIEWED_NO_SECRETS", "metadata": {},
    }
    assert SourceWrite(**base).content_hash == base["content_hash"]
    with pytest.raises(ValueError, match="content_hash"):
        SourceWrite(**{**base, "content_hash": "0" * 64})
    with pytest.raises(ValueError, match="credential"):
        leaked = content + "\naccess_token=plain-secret-value"
        SourceWrite(**{**base, "content": leaked, "content_hash": hashlib.sha256(leaked.encode()).hexdigest()})
    with pytest.raises(ValueError, match="UTF-8 bytes"):
        multibyte = "가" * 174763
        SourceWrite(**{**base, "content": multibyte, "content_hash": hashlib.sha256(multibyte.encode()).hexdigest()})


def test_owner_source_and_relation_writes_use_canonical_ids(client, store):
    content = "# Exact source\n\nReviewed Owner conversation."
    payload = {
        "source_type": "SLACK_THREAD", "title": "Exact source", "source_interface": "slack",
        "actor": "owner", "participants": ["owner", "zeus"], "occurred_at": NOW.isoformat(),
        "source_session_at": NOW.isoformat(), "content": content,
        "content_hash": hashlib.sha256(content.encode()).hexdigest(), "access_scope": "OWNER",
        "security_level": "INTERNAL", "redaction_status": "REVIEWED_NO_SECRETS", "metadata": {},
    }
    headers = {"Authorization": "Bearer owner-secret"}
    multibyte = "가" * 174763
    rejected = client.post("/v1/admin/sources", headers=headers, json={
        **payload, "content": multibyte, "content_hash": hashlib.sha256(multibyte.encode()).hexdigest(),
    })
    assert rejected.status_code == 422
    created = client.post("/v1/admin/sources", headers=headers, json=payload)
    assert created.status_code == 201
    source_id = created.json()["id"]
    event_id = next(event["id"] for event in store.events if event["title"] == "Owner chose API")
    relation = client.post("/v1/admin/relations", headers=headers, json={
        "relation_type": "SUMMARIZES", "from_event_id": event_id, "to_source_id": source_id,
        "metadata": {"pilot": True},
    })
    assert relation.status_code == 201
    assert relation.json()["from_event_id"] == event_id
    assert relation.json()["to_source_id"] == source_id


def test_agent_proposes_decision_and_owner_alone_can_approve(client, store):
    token, _ = access(client)
    proposed = client.post("/v1/decisions", headers={"Authorization": f"Bearer {token}"}, json={
        "product": "DAOS", "topic": "memory", "title": "Keep repositories separate",
        "decision_content": "Keep notes and raw sources separate.", "occurred_at": NOW.isoformat(),
        "related_note_ids": [], "related_source_ids": [],
    })
    assert proposed.status_code == 201
    assert proposed.json()["status"] == "PENDING_OWNER_CONFIRM"
    decision_id = proposed.json()["id"]
    assert client.post(f"/v1/admin/decisions/{decision_id}/approve", headers={"Authorization": f"Bearer {token}"}, json={}).status_code == 401
    approved = client.post(f"/v1/admin/decisions/{decision_id}/approve", headers={"Authorization": "Bearer owner-secret"}, json={"owner_comment": "Approved"})
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert approved.json()["authority_level"] == "OWNER_DECISION"


def test_owner_alone_creates_policy(client):
    payload = {"category": "WRITE_GUIDE", "title": "Writing", "content": "Write directly.", "scope": "GLOBAL", "status": "ACTIVE"}
    assert client.post("/v1/admin/policies", json=payload).status_code == 401
    created = client.post("/v1/admin/policies", headers={"Authorization": "Bearer owner-secret"}, json=payload)
    assert created.status_code == 201
    assert created.json()["version"] == 1
