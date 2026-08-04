"""Contracts for the read-only Zeus GPT Action gateway."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, RefResolver
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


def test_refuses_to_build_with_multiple_server_tokens():
    with pytest.raises(action_api.AuthNotConfigured):
        action_api.build_asgi_app(tokens=(TOKEN, "second-server-held-token"))


def test_exact_get_only_public_routes_and_no_mutation_methods(live_model):
    app = action_api.build_asgi_app(read_model=live_model, tokens=(TOKEN,))
    routes = [route for route in app.routes if getattr(route, "path", None)]
    assert {(route.path, frozenset(route.methods)) for route in routes} == {
        ("/executive/status", frozenset({"GET"})),
        ("/executive/boards", frozenset({"GET"})),
        ("/executive/tasks", frozenset({"GET"})),
        ("/executive/tasks/{public_task_id}", frozenset({"GET"})),
        ("/executive/tasks/{public_task_id}/comments", frozenset({"GET"})),
    }

    client = TestClient(app)
    for path in (
        "/executive/status", "/executive/boards", "/executive/tasks",
        "/executive/tasks/t_abcd", "/executive/tasks/t_abcd/comments",
    ):
        for method in ("post", "put", "patch", "delete", "options"):
            response = getattr(client, method)(path, headers=HEADERS)
            assert response.status_code == 405
            assert response.json() == {
                "ok": False,
                "error": {"code": "METHOD_NOT_ALLOWED", "message": "Method is not allowed"},
                "read_only": True,
            }
    assert client.get("/executive/status/").status_code == 404
    assert client.get("/other").status_code == 404


def test_new_reads_are_authenticated_bounded_and_metadata_complete(live_model):
    client = _client(live_model)
    assert client.get("/executive/boards").status_code == 401

    boards = client.get("/executive/boards", headers=HEADERS)
    tasks = client.get(
        "/executive/tasks", params={"board_slug": BOARD}, headers=HEADERS,
    )
    task_id = tasks.json()["tasks"][0]["public_task_id"]
    detail = client.get(
        f"/executive/tasks/{task_id}", params={"board_slug": BOARD}, headers=HEADERS,
    )
    comments = client.get(
        f"/executive/tasks/{task_id}/comments",
        params={"board_slug": BOARD}, headers=HEADERS,
    )

    for response in (boards, tasks, detail, comments):
        assert response.status_code == 200
        assert len(response.content) <= 100_000
        assert {"freshness", "coverage", "source_gaps", "measured_at", "snapshot_boundary"} <= response.json().keys()
    assert tasks.json()["limit"] == 10
    assert comments.json()["limit"] == 10
    assert client.get(
        "/executive/tasks", params={"board_slug": BOARD, "limit": 21}, headers=HEADERS,
    ).status_code == 400


@pytest.mark.parametrize("path", [
    "/executive/tasks",
    "/executive/tasks/t_abcd",
    "/executive/tasks/t_abcd/comments",
])
def test_new_task_routes_require_board_slug(live_model, path):
    response = _client(live_model).get(path, headers=HEADERS)
    assert response.status_code == 400
    assert len(response.content) < 1000
    assert response.json()["error"]["code"] == "INVALID_BOARD"


def test_correct_bearer_returns_exact_owner_contract(live_model):
    response = _client(live_model).get(
        "/executive/status", params={"board_slug": BOARD}, headers=HEADERS
    )

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {
        "project",
        "lane",
        "task",
        "worker",
        "usage",
        "blocked",
        "owner_confirm",
        "freshness",
        "measured_at",
    }
    assert payload["project"]["board_slug"] == BOARD
    assert payload["lane"]["product_lane"] == "UNAVAILABLE"
    assert payload["lane"]["product_lanes"] == []
    assert payload["task"]["board"] == BOARD
    assert payload["worker"]["board"] == BOARD
    assert payload["usage"]["boards"] == [BOARD]
    assert payload["blocked"]["count"] == 1
    assert payload["owner_confirm"]["owner_confirm_status"] == "UNAVAILABLE"
    assert payload["measured_at"] == 2_000_000_000

    def nested_keys(value):
        if isinstance(value, dict):
            return set(value) | set().union(*(nested_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(nested_keys(item) for item in value))
        return set()

    assert nested_keys(payload).isdisjoint(
        {"internal_paths", "prompts", "sessions", "tokens", "pids", "bodies", "comments"}
    )


def test_wrong_bearer_is_rejected(live_model):
    response = _client(live_model).get(
        "/executive/status", headers={"Authorization": "Bearer wrong-token-value"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_default_board_slug_is_geumhwa(live_model):
    response = _client(live_model).get("/executive/status", headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["project"]["board_slug"] == BOARD


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
    assert payload["task"]["limit"] <= 50
    assert payload["task"]["has_more"] is True
    assert payload["task"]["next_cursor"] != "UNAVAILABLE"
    assert payload["worker"]["limit"] <= 50
    assert "truncation" in payload["worker"]
    assert payload["owner_confirm"]["limit"] <= 50
    assert {"truncated", "next_cursor"} <= payload["blocked"].keys()


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
    assert set(schema["paths"]) == {
        "/executive/status",
        "/executive/boards",
        "/executive/tasks",
        "/executive/tasks/{public_task_id}",
        "/executive/tasks/{public_task_id}/comments",
    }
    assert all(set(path_item) == {"get"} for path_item in schema["paths"].values())
    assert schema["security"] == [{"BearerAuth": []}]
    assert {
        path_item["get"]["operationId"] for path_item in schema["paths"].values()
    } == {
        "getExecutiveStatus", "listExecutiveBoards", "listExecutiveTasks",
        "getExecutiveTask", "listExecutiveTaskComments",
    }
    auth = schema["components"]["securitySchemes"]["BearerAuth"]
    assert auth["type"] == "apiKey"
    assert auth["in"] == "header"
    assert auth["name"] == "Authorization"
    success = schema["components"]["schemas"]["ExecutiveStatus"]
    assert success["additionalProperties"] is False
    assert set(success["required"]) == {
        "project", "lane", "task", "worker", "usage", "blocked",
        "owner_confirm", "freshness", "measured_at",
    }
    assert set(success["properties"]) == set(success["required"])
    journal = schema["components"]["schemas"]["JournalText"]
    assert journal["additionalProperties"] is False
    assert journal["properties"]["text"]["maxLength"] == 16_000
    assert schema["components"]["parameters"]["Limit"]["schema"] == {
        "type": "integer", "minimum": 1, "maximum": 20, "default": 10,
    }
    assert "privacy" not in json.dumps(schema).lower()


def test_every_endpoint_200_body_validates_against_openapi(live_model):
    schema_path = Path(__file__).parents[2] / "plugins/kanban/dashboard/openapi/zeus_executive_action.yaml"
    document = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    resolver = RefResolver.from_schema(document)
    client = _client(live_model)
    tasks = client.get("/executive/tasks", params={"board_slug": BOARD}, headers=HEADERS)
    task_id = tasks.json()["tasks"][0]["public_task_id"]
    calls = {
        "/executive/status": client.get("/executive/status", params={"board_slug": BOARD}, headers=HEADERS),
        "/executive/boards": client.get("/executive/boards", headers=HEADERS),
        "/executive/tasks": tasks,
        "/executive/tasks/{public_task_id}": client.get(f"/executive/tasks/{task_id}", params={"board_slug": BOARD}, headers=HEADERS),
        "/executive/tasks/{public_task_id}/comments": client.get(f"/executive/tasks/{task_id}/comments", params={"board_slug": BOARD}, headers=HEADERS),
    }
    for path, response in calls.items():
        assert response.status_code == 200
        response_schema = document["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        Draft202012Validator(response_schema, resolver=resolver).validate(response.json())


def test_task_page_projection_exactly_matches_declared_fields(live_model):
    document = yaml.safe_load((Path(__file__).parents[2] / "plugins/kanban/dashboard/openapi/zeus_executive_action.yaml").read_text(encoding="utf-8"))
    declared = set(document["components"]["schemas"]["TaskPage"]["properties"]["tasks"]["items"]["properties"])
    payload = _client(live_model).get(
        "/executive/tasks", params={"board_slug": BOARD}, headers=HEADERS,
    ).json()
    assert payload["tasks"]
    assert set(payload["tasks"][0]) == declared


def test_task_cursor_pages_including_final_page_never_claim_complete(live_model):
    conn = kb.connect(board=BOARD)
    try:
        kb.create_task(conn, title="Second card", assignee="athena", board=BOARD)
    finally:
        conn.close()
    client = _client(live_model)
    first = client.get(
        "/executive/tasks", params={"board_slug": BOARD, "limit": 1}, headers=HEADERS,
    ).json()
    assert first["has_more"] is True
    assert first["coverage"]["tasks"] == "PAGED"
    final = client.get(
        "/executive/tasks",
        params={"board_slug": BOARD, "limit": 1, "cursor": first["next_cursor"]},
        headers=HEADERS,
    ).json()
    assert final["has_more"] is False
    assert final["coverage"]["tasks"] == "PAGED"


def test_hangul_heavy_comments_degrade_and_all_rows_are_cursor_reachable(live_model):
    task_id = _client(live_model).get(
        "/executive/tasks", params={"board_slug": BOARD}, headers=HEADERS,
    ).json()["tasks"][0]["public_task_id"]
    conn = kb.connect(board=BOARD)
    try:
        for index in range(17):
            conn.execute(
                "INSERT INTO task_comments (task_id, author, body, created_at) VALUES (?,?,?,?)",
                (task_id, f"agent-{index}", f"row-{index}:" + "한" * 16_000, 10_000 + index),
            )
        conn.commit()
    finally:
        conn.close()

    client = _client(live_model)
    cursor = None
    seen = set()
    pages = 0
    while True:
        params = {"board_slug": BOARD, "limit": 20}
        if cursor:
            params["cursor"] = cursor
        response = client.get(f"/executive/tasks/{task_id}/comments", params=params, headers=HEADERS)
        assert response.status_code == 200
        assert len(response.content) <= 100_000
        payload = response.json()
        if payload["degraded_limit"] < 20:
            assert payload["truncated"] is True
        else:
            assert payload["has_more"] is False
            assert payload["truncated"] is False
        seen.update(comment["created_at"] for comment in payload["comments"])
        pages += 1
        if not payload["has_more"]:
            assert payload["coverage"]["comments"] == ("COMPLETE" if pages == 1 else "PAGED")
            break
        assert payload["next_cursor"] != "UNAVAILABLE"
        cursor = payload["next_cursor"]
    assert seen == {10_000 + index for index in range(17)}
