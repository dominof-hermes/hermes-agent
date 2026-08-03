"""Contracts for the read-only Zeus GPT Action gateway."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from hermes_cli import kanban_db as kb
from plugins.kanban.dashboard import executive_action_api as action_api
from plugins.kanban.dashboard import executive_read_model as erm


TOKEN = "server-held-action-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
BOARD = "geumhwa-ai-dx"


@pytest.fixture
def live_model(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.create_board(BOARD, name="Geumhwa AI-DX")
    conn = kb.connect(board=BOARD)
    try:
        task_id = kb.create_task(
            conn,
            title="Blocked owner-visible operational task",
            assignee="athena",
            board=BOARD,
        )
        conn.execute(
            "UPDATE tasks SET status='blocked', block_kind='dependency' WHERE id=?",
            (task_id,),
        )
        conn.commit()
    finally:
        conn.close()
    return erm.ExecutiveReadModel(
        clock=lambda: 2_000_000_000,
        pid_probe=lambda _pid: True,
        identity_salt=b"action-test-salt",
        usage_collector=lambda: {"available": False, "providers": []},
    )


def _client(model) -> TestClient:
    return TestClient(action_api.build_asgi_app(read_model=model, tokens=(TOKEN,)))


def test_exact_status_route_denies_missing_bearer():
    app = action_api.build_asgi_app(tokens=(TOKEN,))
    response = TestClient(app).get("/executive/status")

    assert response.status_code == 401
    assert response.json() == {
        "ok": False,
        "error": {"code": "UNAUTHORIZED", "message": "Bearer token required"},
        "read_only": True,
    }


def test_refuses_to_build_without_server_token(monkeypatch):
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN", raising=False)
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN_FILE", raising=False)
    with pytest.raises(action_api.AuthNotConfigured):
        action_api.build_asgi_app()


def test_exactly_one_public_route_and_no_mutation_methods(live_model):
    app = action_api.build_asgi_app(read_model=live_model, tokens=(TOKEN,))
    routes = [route for route in app.routes if getattr(route, "path", None)]
    assert [(route.path, route.methods) for route in routes] == [
        ("/executive/status", {"GET"})
    ]

    client = TestClient(app)
    for method in ("post", "put", "patch", "delete"):
        assert getattr(client, method)("/executive/status", headers=HEADERS).status_code == 405
    assert client.get("/executive/status/").status_code == 404
    assert client.get("/other").status_code == 404


def test_correct_bearer_aggregates_six_live_read_model_sections(live_model):
    response = _client(live_model).get(
        "/executive/status", params={"board_slug": BOARD}, headers=HEADERS
    )

    assert response.status_code == 200
    payload = response.json()
    assert {"board", "tasks", "workers", "usage", "blockers", "owner_gate"} <= payload.keys()
    assert payload["board"]["board_slug"] == BOARD
    assert payload["tasks"]["board"] == BOARD
    assert payload["tasks"]["data_marking"]["content_class"] == "UNTRUSTED_BOARD_DATA"
    assert payload["workers"]["board"] == BOARD
    assert payload["usage"]["boards"] == [BOARD]
    assert payload["blockers"]["items"] == payload["board"]["blockers"]
    assert payload["owner_gate"]["owner_confirm_status"] == "UNAVAILABLE"
    assert payload["read_only"] is True
    assert "strategy" not in payload


def test_wrong_bearer_is_rejected(live_model):
    response = _client(live_model).get(
        "/executive/status", headers={"Authorization": "Bearer wrong-token-value"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_default_board_slug_is_geumhwa(live_model):
    response = _client(live_model).get("/executive/status", headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["board"]["board_slug"] == BOARD


@pytest.mark.parametrize("slug", ["../secret", "x" * 65, "bad slug"])
def test_invalid_board_is_a_bounded_sanitized_4xx(live_model, slug):
    response = _client(live_model).get(
        "/executive/status", params={"board_slug": slug}, headers=HEADERS
    )
    assert 400 <= response.status_code < 500
    assert len(response.content) < 1000
    body = response.text.lower()
    assert slug.lower() not in body
    assert "traceback" not in body
    assert "/home/" not in body


class _FailingModel:
    def __init__(self, error):
        self.error = error

    def get_board_summary(self, _board_slug):
        raise self.error


def test_safe_read_error_is_sanitized():
    model = _FailingModel(erm.SafeReadError("BOARD_UNAVAILABLE", "path /secret/db"))
    response = _client(model).get("/executive/status", headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["error"] == {
        "code": "BOARD_UNAVAILABLE",
        "message": "Executive status is unavailable for this request",
    }
    assert "/secret/db" not in response.text


def test_unexpected_read_error_is_sanitized_503():
    model = _FailingModel(RuntimeError("token=leak /home/internal pid=123"))
    response = _client(model).get("/executive/status", headers=HEADERS)
    assert response.status_code == 503
    assert response.json()["error"] == {
        "code": "SERVICE_UNAVAILABLE",
        "message": "Executive status is temporarily unavailable",
    }
    assert "token=leak" not in response.text
    assert "/home/" not in response.text


def test_response_is_bounded_and_pagination_is_explicit(live_model):
    conn = kb.connect(board=BOARD)
    try:
        for index in range(60):
            kb.create_task(
                conn,
                title=f"Operational task {index} " + ("x" * 140),
                assignee="athena",
                board=BOARD,
            )
    finally:
        conn.close()

    response = _client(live_model).get("/executive/status", headers=HEADERS)
    payload = response.json()
    assert response.status_code == 200
    assert len(response.content) < 100_000
    assert payload["tasks"]["limit"] <= 50
    assert payload["tasks"]["has_more"] is True
    assert payload["tasks"]["next_cursor"] != "UNAVAILABLE"
    assert payload["workers"]["limit"] <= 50
    assert "truncation" in payload["workers"]
    assert payload["owner_gate"]["limit"] <= 50
    assert {"truncated", "next_cursor"} <= payload["blockers"].keys()


def test_request_performs_no_snapshot_or_file_write(live_model, tmp_path):
    home = tmp_path / ".hermes"

    def durable_files():
        return {
            p.relative_to(home): p.read_bytes()
            for p in home.rglob("*")
            if p.is_file() and not p.name.endswith(("-shm", "-wal"))
        }

    before = durable_files()
    response = _client(live_model).get("/executive/status", headers=HEADERS)
    after = durable_files()

    assert response.status_code == 200
    assert after == before
    assert not list(home.rglob("executive.json"))


def test_openapi_declares_only_the_read_action_surface():
    schema_path = (
        Path(__file__).parents[2]
        / "plugins/kanban/dashboard/openapi/zeus_executive_action.yaml"
    )
    schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))

    assert schema["openapi"] == "3.1.0"
    assert schema["servers"] == [{"url": "https://ax.dominof.com"}]
    assert set(schema["paths"]) == {"/executive/status"}
    operation = schema["paths"]["/executive/status"]
    assert set(operation) == {"get"}
    assert operation["get"]["operationId"] == "getExecutiveStatus"
    assert operation["get"]["security"] == [{"BearerAuth": []}]
    auth = schema["components"]["securitySchemes"]["BearerAuth"]
    assert auth["type"] == "apiKey"
    assert auth["in"] == "header"
    assert auth["name"] == "Authorization"
    assert "privacy" not in json.dumps(schema).lower()
