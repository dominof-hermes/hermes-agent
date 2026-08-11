from __future__ import annotations

import asyncio
import json
import os

from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from plugins.daos_memory import action_api


NOW = datetime(2026, 8, 12, 2, 30, tzinfo=timezone.utc)
ACTION_TOKEN = "server-held-action-token"
HEADERS = {"Authorization": f"Bearer {ACTION_TOKEN}"}


class FakeUpstream:
    def __init__(self):
        self.calls: list[tuple] = []

    async def bootstrap(self, bootstrap_key, product, topic):
        self.calls.append(("bootstrap", bootstrap_key, product, topic))
        return {
            "agent_id": "zeus",
            "access_token": "internal-access-secret",
            "access_expires_at": (NOW + timedelta(minutes=10)).isoformat(),
            "scopes": ["memory:read", "memory:write"],
            "global_principles": [],
            "role_principles": [],
            "current_context": [
                {"id": "11111111-1111-1111-1111-111111111111", "source_ref": "source://daos/1", "title": "Current"}
            ],
            "owner_decisions": [],
            "next_actions": [],
            "history": [],
        }

    async def read_current(self, access_token, product, topic, limit):
        self.calls.append(("read_current", access_token, product, topic, limit))
        return {"items": [{"id": "22222222-2222-2222-2222-222222222222"}], "count": 1}

    async def search_history(self, access_token, product, topic, query, limit):
        self.calls.append(("search_history", access_token, product, topic, query, limit))
        return {"items": [{"id": "33333333-3333-3333-3333-333333333333"}], "count": 1}

    async def write_event(self, access_token, event):
        self.calls.append(("write_event", access_token, event))
        return {**event, "id": "44444444-4444-4444-4444-444444444444", "status": "CURRENT"}

    async def read_event(self, access_token, event_id):
        self.calls.append(("read_event", access_token, event_id))
        return {"id": event_id, "source_ref": "source://zeus/write", "status": "CURRENT"}


def test_memory_bootstrap_requires_action_auth_consumes_key_and_hides_internal_token():
    upstream = FakeUpstream()
    client = TestClient(
        action_api.build_asgi_app(
            upstream=upstream,
            tokens=(ACTION_TOKEN,),
            clock=lambda: NOW,
        )
    )
    body = {"bootstrap_key": "one-time-bootstrap", "product": "DAOS", "topic": "memory"}

    assert client.post("/zeus-memory/v1/bootstrap", json=body).status_code == 401
    response = client.post("/zeus-memory/v1/bootstrap", headers=HEADERS, json=body)

    assert response.status_code == 200
    payload = response.json()
    assert upstream.calls == [("bootstrap", "one-time-bootstrap", "DAOS", "memory")]
    assert payload["agent_id"] == "zeus"
    assert payload["context_id"]
    assert payload["bootstrap_event_ids"] == ["11111111-1111-1111-1111-111111111111"]
    assert payload["bootstrap_source_refs"] == ["source://daos/1"]
    assert "access_token" not in response.text
    assert "internal-access-secret" not in response.text
    assert "one-time-bootstrap" not in response.text


def test_context_handle_drives_current_history_write_and_exact_event_read():
    upstream = FakeUpstream()
    client = TestClient(
        action_api.build_asgi_app(
            upstream=upstream,
            tokens=(ACTION_TOKEN,),
            clock=lambda: NOW,
        )
    )
    boot = client.post(
        "/zeus-memory/v1/bootstrap",
        headers=HEADERS,
        json={"bootstrap_key": "one-time-bootstrap", "product": "DAOS"},
    ).json()
    context_id = boot["context_id"]

    current = client.post(
        "/zeus-memory/v1/current",
        headers=HEADERS,
        json={"context_id": context_id, "product": "DAOS", "limit": 10},
    )
    history = client.post(
        "/zeus-memory/v1/history",
        headers=HEADERS,
        json={"context_id": context_id, "product": "DAOS", "query": "decision", "limit": 5},
    )
    written = client.post(
        "/zeus-memory/v1/events",
        headers=HEADERS,
        json={
            "context_id": context_id,
            "product": "DAOS",
            "topic": "memory",
            "memory_type": "STRATEGY",
            "event_type": "ZEUS_UAT",
            "title": "Zeus Action UAT",
            "summary": "Zeus wrote through the GPT Action.",
            "content": "Bounded owner-directed UAT event.",
            "authority_level": "AGENT_ASSESSMENT",
            "work_id": "DAOS-MEM-260811-01",
            "source_ref": "source://zeus/write",
            "metadata": {"canary": True},
        },
    )
    event_id = written.json()["id"]
    event = client.post(
        "/zeus-memory/v1/event",
        headers=HEADERS,
        json={"context_id": context_id, "event_id": event_id},
    )

    assert current.status_code == history.status_code == written.status_code == event.status_code == 200
    assert current.json()["count"] == 1
    assert history.json()["count"] == 1
    assert event.json()["id"] == event_id
    write_call = next(call for call in upstream.calls if call[0] == "write_event")
    assert write_call[1] == "internal-access-secret"
    assert write_call[2]["source_interface"] == "chatgpt_zeus_action"
    assert "access_token" not in "".join(r.text for r in (current, history, written, event))


def test_action_write_forwards_timezone_aware_history_import_times_only():
    upstream = FakeUpstream()
    client = TestClient(action_api.build_asgi_app(
        upstream=upstream, tokens=(ACTION_TOKEN,), clock=lambda: NOW,
    ))
    context_id = client.post(
        "/zeus-memory/v1/bootstrap", headers=HEADERS,
        json={"bootstrap_key": "one-time-bootstrap"},
    ).json()["context_id"]
    base = {
        "context_id": context_id, "product": "DAOS", "topic": "memory",
        "memory_type": "SESSION_SUMMARY", "event_type": "HISTORY_IMPORT",
        "title": "June session", "summary": "Imported later", "content": "Historical content",
        "authority_level": "AGENT_ASSESSMENT",
    }
    occurred = "2026-06-18T09:00:00+00:00"

    accepted = client.post("/zeus-memory/v1/events", headers=HEADERS, json={
        **base, "occurred_at": occurred, "effective_from": occurred,
        "effective_to": "2026-06-19T09:00:00+00:00", "source_session_at": occurred,
    })
    rejected = client.post("/zeus-memory/v1/events", headers=HEADERS, json={
        **base, "occurred_at": "2026-06-18T09:00:00",
    })
    missing_start = client.post("/zeus-memory/v1/events", headers=HEADERS, json={
        **base, "effective_to": "2026-06-19T09:00:00+00:00",
    })
    undated_history = client.post("/zeus-memory/v1/events", headers=HEADERS, json=base)
    padded_undated_history = client.post("/zeus-memory/v1/events", headers=HEADERS, json={
        **base, "event_type": " HISTORY_IMPORT ",
    })

    assert accepted.status_code == 200
    assert rejected.status_code == missing_start.status_code == undated_history.status_code == padded_undated_history.status_code == 400
    write_calls = [call for call in upstream.calls if call[0] == "write_event"]
    assert len(write_calls) == 1
    forwarded = write_calls[0][2]
    for field in ("occurred_at", "effective_from", "effective_to", "source_session_at"):
        parsed = datetime.fromisoformat(forwarded[field].replace("Z", "+00:00"))
        assert parsed.tzinfo is not None
    assert forwarded["source_interface"] == "chatgpt_zeus_action"


def test_action_request_body_is_bounded_before_validation_and_rejects_extra_fields():
    client = TestClient(
        action_api.build_asgi_app(
            upstream=FakeUpstream(), tokens=(ACTION_TOKEN,), clock=lambda: NOW
        )
    )
    oversized = client.post(
        "/zeus-memory/v1/current",
        headers=HEADERS,
        json={"context_id": "x" * 43, "padding": "z" * 20_000},
    )
    assert oversized.status_code == 413
    assert oversized.json()["error"]["code"] == "REQUEST_TOO_LARGE"
    assert "padding" not in oversized.text

    small_extra = client.post(
        "/zeus-memory/v1/bootstrap",
        headers=HEADERS,
        json={"bootstrap_key": "one-time-bootstrap", "padding": "not-allowed"},
    )
    assert small_extra.status_code == 400
    assert "not-allowed" not in small_extra.text


def test_action_chunked_body_without_content_length_is_bounded():
    app = action_api.build_asgi_app(
        upstream=FakeUpstream(), tokens=(ACTION_TOKEN,), clock=lambda: NOW
    )
    payload = json.dumps(
        {"context_id": "x" * 43, "padding": "z" * 20_000}
    ).encode()
    messages = [
        {"type": "http.request", "body": payload[:8_000], "more_body": True},
        {"type": "http.request", "body": payload[8_000:], "more_body": False},
    ]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/zeus-memory/v1/current",
        "raw_path": b"/zeus-memory/v1/current",
        "query_string": b"",
        "headers": [(b"authorization", f"Bearer {ACTION_TOKEN}".encode()), (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 443),
        "root_path": "",
    }
    asyncio.run(app(scope, receive, send))
    status = next(message["status"] for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    assert status == 413
    assert json.loads(body)["error"]["code"] == "REQUEST_TOO_LARGE"
    assert b"padding" not in body


def test_action_routes_fail_closed_and_validation_never_echoes_credentials():
    client = TestClient(
        action_api.build_asgi_app(
            upstream=FakeUpstream(), tokens=(ACTION_TOKEN,), clock=lambda: NOW
        )
    )
    invalid = client.post(
        "/zeus-memory/v1/bootstrap",
        headers=HEADERS,
        json={"bootstrap_key": "secret"},
    )
    assert invalid.status_code == 400
    assert "secret" not in invalid.text

    for path in (
        "/zeus-memory/v1/bootstrap",
        "/zeus-memory/v1/current",
        "/zeus-memory/v1/history",
        "/zeus-memory/v1/events",
        "/zeus-memory/v1/event",
    ):
        assert client.get(path, headers=HEADERS).status_code == 405
        assert client.put(path, headers=HEADERS).status_code == 405
    assert client.post(
        "/zeus-memory/v1/current",
        headers=HEADERS,
        json={"context_id": "x" * 43},
    ).status_code == 401
    assert client.post(
        "/zeus-memory/v1/current/",
        headers=HEADERS,
        json={"context_id": "x" * 43},
    ).status_code == 404

    boot = client.post(
        "/zeus-memory/v1/bootstrap",
        headers=HEADERS,
        json={"bootstrap_key": "one-time-bootstrap"},
    ).json()
    denied = client.post(
        "/zeus-memory/v1/events",
        headers=HEADERS,
        json={
            "context_id": boot["context_id"],
            "product": "DAOS",
            "topic": "memory",
            "memory_type": "EVIDENCE",
            "event_type": "BAD",
            "title": "x",
            "summary": "x",
            "content": "credential-like-content-must-not-echo",
            "authority_level": "OWNER_DECISION",
        },
    )
    assert denied.status_code == 400
    assert "credential-like-content-must-not-echo" not in denied.text


def test_openapi_declares_exactly_five_zeus_memory_tools():
    schema_path = Path(__file__).parents[1] / "openapi/zeus_memory_action.yaml"
    document = yaml.safe_load(schema_path.read_text(encoding="utf-8"))

    assert document["openapi"] == "3.1.0"
    assert document["servers"] == [{"url": "https://memory.dominof.com"}]
    assert set(document["paths"]) == {
        "/zeus-memory/v1/bootstrap",
        "/zeus-memory/v1/current",
        "/zeus-memory/v1/history",
        "/zeus-memory/v1/events",
        "/zeus-memory/v1/event",
    }
    assert {
        item["post"]["operationId"] for item in document["paths"].values()
    } == {
        "memory_bootstrap",
        "memory_read_current",
        "memory_search_history",
        "memory_write",
        "memory_read_event",
    }
    assert all(set(item) == {"post"} for item in document["paths"].values())
    write_properties = document["components"]["schemas"]["WriteRequest"]["properties"]
    for field in ("occurred_at", "effective_from", "effective_to", "source_session_at"):
        assert field in write_properties
        serialized = json.dumps(write_properties[field])
        assert "date-time" in serialized and "null" in serialized
        assert field not in document["components"]["schemas"]["WriteRequest"]["required"]
    write_description = document["paths"]["/zeus-memory/v1/events"]["post"]["description"]
    assert "HISTORY" in write_description and "CURRENT" in write_description
    assert document["security"] == [{"BearerAuth": []}]
    auth = document["components"]["securitySchemes"]["BearerAuth"]
    assert auth == {"type": "apiKey", "in": "header", "name": "Authorization"}
    assert document["paths"]["/zeus-memory/v1/events"]["post"]["x-openai-isConsequential"] is True
    for path in ("/zeus-memory/v1/current", "/zeus-memory/v1/history", "/zeus-memory/v1/event"):
        assert document["paths"][path]["post"]["x-openai-isConsequential"] is False


def test_http_upstream_keeps_credentials_in_headers_and_maps_exact_memory_routes(monkeypatch):
    seen = []

    class Response:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return json.dumps(self.payload).encode()

    def urlopen(request, timeout):
        seen.append((request, timeout))
        if request.full_url.endswith("/v1/bootstrap"):
            return Response({"agent_id": "zeus"})
        return Response({"items": [], "count": 0})

    monkeypatch.setattr(action_api.urllib.request, "urlopen", urlopen)
    upstream = action_api.HttpMemoryUpstream("http://172.18.0.1:8791")
    asyncio.run(upstream.bootstrap("bootstrap-secret", "DAOS", "memory"))
    asyncio.run(upstream.read_current("access-secret", "DAOS", None, 5))

    bootstrap_request = seen[0][0]
    current_request = seen[1][0]
    assert bootstrap_request.full_url == "http://172.18.0.1:8791/v1/bootstrap"
    assert bootstrap_request.get_header("Authorization") == "Bearer bootstrap-secret"
    assert "bootstrap-secret" not in bootstrap_request.full_url
    assert json.loads(bootstrap_request.data)["agent_id"] == "zeus"
    assert current_request.full_url.endswith("/v1/current?product=DAOS&limit=5")
    assert current_request.get_header("Authorization") == "Bearer access-secret"
    assert "access-secret" not in current_request.full_url


def test_runtime_token_loader_requires_owner_only_regular_file(tmp_path):
    token_file = tmp_path / "action.token"
    token_file.write_text("a" * 48, encoding="ascii")
    os.chmod(token_file, 0o600)
    assert action_api._load_single_token(str(token_file)) == "a" * 48

    os.chmod(token_file, 0o640)
    try:
        action_api._load_single_token(str(token_file))
    except RuntimeError:
        pass
    else:
        raise AssertionError("group-readable token must fail closed")


def test_public_schema_privacy_and_private_health_are_bounded():
    client = TestClient(
        action_api.build_asgi_app(
            upstream=FakeUpstream(), tokens=(ACTION_TOKEN,), clock=lambda: NOW
        )
    )
    schema = client.get("/zeus-memory/openapi.yaml")
    privacy = client.get("/zeus-memory/privacy")
    health = client.get("/health")
    assert schema.status_code == privacy.status_code == health.status_code == 200
    assert "memory_bootstrap" in schema.text
    assert "Bootstrap Keys" in privacy.text
    assert health.json() == {"status": "ok", "service": "daos-zeus-memory-action"}
    assert all(len(response.content) < 100_000 for response in (schema, privacy, health))
