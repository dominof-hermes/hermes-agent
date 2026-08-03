"""Protocol-surface contracts for the DAOS Zeus Live Operations MCP server.

The server is a read-only ASGI Streamable HTTP MCP application over the
canonical Kanban ledger. These tests pin the surface itself: the exact tool
inventory, zero mutation reachability, bounded schemas, deny-by-default auth
against a server-controlled scope, the outermost request boundary (route
allowlist, body bound, protocol rate limit, response cap), safe audit records,
and a real in-memory MCP client session driving all eight tools against real
Kanban data.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb

pytest.importorskip("mcp")

from plugins.kanban.dashboard import executive_mcp as emcp  # noqa: E402
from plugins.kanban.dashboard import executive_read_model as erm  # noqa: E402


EXPECTED_TOOLS = (
    "list_boards",
    "get_board_summary",
    "get_lane_status",
    "list_tasks",
    "get_task_summary",
    "get_worker_status",
    "get_owner_confirm_queue",
    "get_usage_and_output_summary",
)

NOW = 2_000_000_000
TOKEN = "s3cret-owner-token"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
INIT_BODY = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "zeus-test", "version": "1"}},
}
LIST_BODY = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="Zeus live ops slice", assignee="athena")
        conn.execute(
            "UPDATE tasks SET status='running', claim_lock='c1', worker_pid=4242, "
            "created_at=? WHERE id=?", (NOW - 3600, tid),
        )
        cur = conn.execute(
            "INSERT INTO task_runs (task_id, profile, status, claim_lock, claim_expires, "
            "worker_pid, last_heartbeat_at, started_at) VALUES (?,?,?,?,?,?,?,?)",
            (tid, "athena", "running", "c1", NOW + 900, 4242, NOW - 30, NOW - 120),
        )
        conn.execute("UPDATE tasks SET current_run_id=? WHERE id=?", (cur.lastrowid, tid))
        conn.commit()
    finally:
        conn.close()
    return tid


def _read_model(**over):
    kw = {
        "clock": lambda: NOW,
        "pid_probe": lambda pid: True,
        "identity_salt": b"unit-test-salt",
        "usage_collector": lambda: {"available": False, "providers": []},
    }
    kw.update(over)
    return erm.ExecutiveReadModel(**kw)


def _server(**over):
    return emcp.build_mcp_server(
        read_model=_read_model(),
        config=emcp.ServerConfig(local_trusted=True, **over),
    )


def _structured(result):
    """Normalise FastMCP's (content, structured) tool return into a dict."""
    if isinstance(result, tuple):
        _content, structured = result
        return structured
    return result  # pragma: no cover - defensive


@pytest.fixture
def http_app(monkeypatch, kanban_home):
    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_TOKEN", TOKEN)
    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_ALLOWED_HOSTS", "testserver")

    def _build(**config_kwargs):
        return emcp.build_asgi_app(
            read_model=_read_model(),
            config=emcp.ServerConfig(**config_kwargs) if config_kwargs else None,
        )

    return _build


# ---------------------------------------------------------------------------
# Exact tool inventory / zero mutation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exactly_eight_tools_and_no_others():
    tools = await _server().list_tools()
    names = tuple(t.name for t in tools)
    assert len(names) == 8
    assert set(names) == set(EXPECTED_TOOLS)


@pytest.mark.asyncio
async def test_no_resources_or_prompts_are_exposed():
    server = _server()
    assert await server.list_resources() == []
    assert await server.list_resource_templates() == []
    assert await server.list_prompts() == []


@pytest.mark.asyncio
async def test_no_mutation_verb_is_reachable_anywhere_in_the_surface():
    tools = await _server().list_tools()
    # Every tool is a read verb, and no mutating action appears in any name.
    # ("owner_confirm" is a noun — the queue is read-only, see the OC tests.)
    banned_actions = (
        "create", "update", "delete", "remove", "move", "assign", "approve",
        "reject", "execute", "terminate", "push", "merge", "deploy", "download",
        "write", "patch", "reclaim", "dispatch", "spawn", "sql",
    )
    for tool in tools:
        assert tool.name.startswith(("list_", "get_")), tool.name
        assert not any(verb in tool.name for verb in banned_actions), tool.name
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name

    blob = json.dumps([t.model_dump() for t in tools]).lower()
    for verb in ("arbitrary sql", "raw sql", "mutation"):
        assert verb not in blob


@pytest.mark.asyncio
async def test_tool_schemas_are_strict_and_bounded():
    tools = {t.name: t for t in await _server().list_tools()}

    list_tasks = tools["list_tasks"].inputSchema
    limit = list_tasks["properties"]["limit"]
    assert limit["maximum"] == 50
    assert limit["minimum"] == 1
    # Owner filter vocabulary.
    assert "owner_confirm_status" in list_tasks["properties"]
    assert "cursor" in list_tasks["properties"]

    for tool in tools.values():
        assert tool.inputSchema.get("additionalProperties") is False, tool.name

    lane = tools["get_lane_status"].inputSchema
    assert set(lane["required"]) == {"board_slug", "lane"}


# ---------------------------------------------------------------------------
# Auth boundary — deny by default, server-controlled scope
# ---------------------------------------------------------------------------


def test_asgi_app_refuses_to_build_without_a_server_secret(monkeypatch):
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN", raising=False)
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN_FILE", raising=False)
    with pytest.raises(emcp.AuthNotConfigured):
        emcp.build_asgi_app()


@pytest.mark.asyncio
async def test_tools_deny_by_default_without_verified_identity(kanban_home):
    server = emcp.build_mcp_server(
        read_model=_read_model(), config=emcp.ServerConfig(),  # local_trusted defaults False
    )
    payload = _structured(await server.call_tool("list_boards", {}))
    assert payload["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_client_declared_scope_is_ignored(kanban_home):
    """A client-supplied scope argument can never grant access."""
    server = emcp.build_mcp_server(read_model=_read_model(), config=emcp.ServerConfig())
    payload = _structured(
        await server.call_tool("list_boards", {"scope": "daos.executive.read"}))
    assert payload["error"]["code"] in ("UNAUTHORIZED", "INVALID_ARGUMENTS")


def test_token_verifier_grants_only_the_read_scope(monkeypatch):
    import anyio

    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_TOKEN", TOKEN)
    verifier = emcp.ExecutiveTokenVerifier.from_env()

    good = anyio.run(verifier.verify_token, TOKEN)
    assert good is not None
    assert good.scopes == [emcp.REQUIRED_SCOPE]
    assert TOKEN not in good.client_id

    assert anyio.run(verifier.verify_token, "wrong-token") is None
    assert anyio.run(verifier.verify_token, "") is None


def test_unconfigured_verifier_denies_every_token(monkeypatch):
    import anyio

    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN", raising=False)
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN_FILE", raising=False)
    verifier = emcp.ExecutiveTokenVerifier(tokens=())
    assert anyio.run(verifier.verify_token, "anything") is None


# ---------------------------------------------------------------------------
# Token file hardening
# ---------------------------------------------------------------------------


def _token_file(tmp_path, mode=0o600, body=f"{TOKEN}\n"):
    path = tmp_path / "secret.token"
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def test_owner_only_token_file_is_accepted(tmp_path, monkeypatch):
    path = _token_file(tmp_path)
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN", raising=False)
    tokens = emcp.load_server_tokens({"DAOS_EXECUTIVE_MCP_TOKEN_FILE": str(path)})
    assert tokens == (TOKEN,)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o666, 0o777])
def test_group_or_world_readable_token_file_fails_closed(tmp_path, mode):
    path = _token_file(tmp_path, mode=mode)
    assert emcp.load_server_tokens({"DAOS_EXECUTIVE_MCP_TOKEN_FILE": str(path)}) == ()


def test_non_regular_token_file_fails_closed(tmp_path):
    directory = tmp_path / "adir"
    directory.mkdir(mode=0o700)
    assert emcp.load_server_tokens({"DAOS_EXECUTIVE_MCP_TOKEN_FILE": str(directory)}) == ()

    target = _token_file(tmp_path)
    link = tmp_path / "link.token"
    link.symlink_to(target)
    assert emcp.load_server_tokens({"DAOS_EXECUTIVE_MCP_TOKEN_FILE": str(link)}) == ()

    missing = tmp_path / "nope.token"
    assert emcp.load_server_tokens({"DAOS_EXECUTIVE_MCP_TOKEN_FILE": str(missing)}) == ()


def test_short_secrets_are_ignored(tmp_path):
    path = _token_file(tmp_path, body="tiny\n")
    assert emcp.load_server_tokens({"DAOS_EXECUTIVE_MCP_TOKEN_FILE": str(path)}) == ()
    assert emcp.load_server_tokens({"DAOS_EXECUTIVE_MCP_TOKEN": "tiny"}) == ()


def test_token_file_permissions_are_never_logged(tmp_path, caplog):
    path = _token_file(tmp_path, mode=0o666)
    with caplog.at_level(logging.DEBUG):
        emcp.load_server_tokens({"DAOS_EXECUTIVE_MCP_TOKEN_FILE": str(path)})
    blob = " ".join(r.getMessage() for r in caplog.records)
    assert str(path) not in blob
    assert TOKEN not in blob


# ---------------------------------------------------------------------------
# Configuration bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rate_limit_per_minute": 0},
        {"rate_limit_per_minute": -1},
        {"rate_limit_per_minute": emcp.MAX_RATE_LIMIT_PER_MINUTE + 1},
        {"rate_limit_per_minute": 1.5},
        {"max_response_bytes": 0},
        {"max_response_bytes": emcp.MAX_RESPONSE_BYTES + 1},
        {"max_request_bytes": 0},
        {"max_request_bytes": emcp.MAX_REQUEST_BYTES + 1},
        {"local_trusted": "yes"},
    ],
)
def test_configuration_limits_are_positive_and_bounded(kwargs):
    with pytest.raises(emcp.ConfigurationError):
        emcp.ServerConfig(**kwargs)


def test_default_configuration_is_within_reviewed_maxima():
    cfg = emcp.ServerConfig()
    assert 0 < cfg.rate_limit_per_minute <= emcp.MAX_RATE_LIMIT_PER_MINUTE
    assert 0 < cfg.max_response_bytes <= emcp.MAX_RESPONSE_BYTES
    assert 0 < cfg.max_request_bytes <= emcp.MAX_REQUEST_BYTES
    assert cfg.local_trusted is False


# ---------------------------------------------------------------------------
# Outermost HTTP boundary
# ---------------------------------------------------------------------------


def test_http_boundary_rejects_unauthenticated_and_wrong_tokens(http_app):
    from starlette.testclient import TestClient

    with TestClient(http_app()) as client:
        anon = client.post("/mcp", json=LIST_BODY,
                           headers={"Accept": "application/json, text/event-stream"})
        assert anon.status_code == 401
        bad = client.post("/mcp", json=LIST_BODY, headers={
            **HEADERS, "Authorization": "Bearer not-the-token"})
        assert bad.status_code == 401


def test_http_boundary_serves_a_verified_caller(http_app):
    """The boundary is deny-by-default, not deny-always: a verified token works."""
    from starlette.testclient import TestClient

    with TestClient(http_app()) as client:
        init = client.post("/mcp", headers=HEADERS, json=INIT_BODY)
        assert init.status_code == 200, init.text
        listed = client.post("/mcp", headers=HEADERS, json=LIST_BODY)
        assert listed.status_code == 200, listed.text
        names = {t["name"] for t in listed.json()["result"]["tools"]}
        assert names == set(EXPECTED_TOOLS)


@pytest.mark.parametrize(
    "method, path",
    [
        ("POST", "/mcp/"),
        ("POST", "/mcp/x"),
        ("POST", "/mcpx"),
        ("POST", "/MCP"),
        ("POST", "/"),
        ("PUT", "/mcp"),
        ("PATCH", "/mcp"),
        ("HEAD", "/mcp"),
        ("OPTIONS", "/mcp"),
    ],
)
def test_http_boundary_allowlists_exact_route_and_method(http_app, method, path):
    from starlette.testclient import TestClient

    with TestClient(http_app()) as client:
        resp = client.request(method, path, headers=HEADERS, json=LIST_BODY)
        assert resp.status_code == 404, f"{method} {path} -> {resp.status_code}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path", ["/mcp/../mcp", "/mcp%2f", "//mcp", "/mcp\\", "/mcp ", " /mcp"],
)
async def test_boundary_rejects_unnormalised_lookalike_paths(path):
    """Checked at the ASGI layer, where a client cannot normalise the path away."""
    seen = []

    async def _inner(scope, receive, send):  # pragma: no cover - must not run
        seen.append(scope["path"])

    middleware = emcp.BoundaryMiddleware(_inner, config=emcp.ServerConfig())
    sent = []

    async def _send(message):
        sent.append(message)

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await middleware({"type": "http", "method": "POST", "path": path, "headers": [],
                      "client": ("127.0.0.1", 1)}, _receive, _send)
    assert seen == []
    assert sent[0]["status"] == 404


@pytest.mark.asyncio
async def test_boundary_streams_event_streams_without_buffering():
    """An SSE response is forwarded as it arrives and still bounded by the cap."""
    async def _inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/event-stream")]})
        for _ in range(3):
            await send({"type": "http.response.body", "body": b"data: x\n\n",
                        "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    middleware = emcp.BoundaryMiddleware(_inner, config=emcp.ServerConfig())
    sent = []

    async def _send(message):
        sent.append(message)

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await middleware({"type": "http", "method": "POST", "path": "/mcp", "headers": [],
                      "client": ("127.0.0.1", 1)}, _receive, _send)
    assert sent[0]["type"] == "http.response.start"
    bodies = [m for m in sent if m["type"] == "http.response.body"]
    assert len(bodies) == 4, "stream was buffered instead of forwarded"


def test_http_boundary_bounds_the_request_body(http_app):
    from starlette.testclient import TestClient

    app = http_app(max_request_bytes=2048)
    with TestClient(app) as client:
        oversized = {"jsonrpc": "2.0", "id": 3, "method": "tools/list",
                     "params": {"padding": "x" * 8192}}
        resp = client.post("/mcp", headers=HEADERS, json=oversized)
        assert resp.status_code == 413
        assert resp.json()["error"]["code"] == "REQUEST_TOO_LARGE"


def test_http_boundary_bounds_a_streamed_request_body(http_app):
    from starlette.testclient import TestClient

    app = http_app(max_request_bytes=2048)

    def _chunks():
        for _ in range(8):
            yield b"x" * 1024

    with TestClient(app) as client:
        resp = client.post("/mcp", headers=HEADERS, content=_chunks())
        assert resp.status_code == 413


def test_http_boundary_rate_limits_protocol_requests(http_app):
    """initialize / tools-list are rate limited too, not just tool calls."""
    from starlette.testclient import TestClient

    app = http_app(rate_limit_per_minute=3)
    with TestClient(app) as client:
        statuses = [
            client.post("/mcp", headers=HEADERS, json=LIST_BODY).status_code
            for _ in range(5)
        ]
    assert statuses[-1] == 429
    assert statuses.count(429) >= 2


def test_http_boundary_caps_the_response(http_app):
    from starlette.testclient import TestClient

    app = http_app(max_response_bytes=200)
    with TestClient(app) as client:
        resp = client.post("/mcp", headers=HEADERS, json=LIST_BODY)
        assert resp.status_code == 413
        assert resp.json()["error"]["code"] == "RESPONSE_TOO_LARGE"


def test_http_boundary_keeps_dns_rebinding_protection(monkeypatch, kanban_home):
    """A verified token from an unexpected Host is still refused."""
    from starlette.testclient import TestClient

    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_TOKEN", TOKEN)
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_ALLOWED_HOSTS", raising=False)
    app = emcp.build_asgi_app(read_model=_read_model())
    with TestClient(app) as client:
        resp = client.post("/mcp", headers=HEADERS, json=LIST_BODY)
        assert resp.status_code == 421


def test_http_boundary_is_asgi_and_mounts_at_mcp(http_app):
    app = http_app()
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/mcp" in paths
    assert callable(app)


def test_http_boundary_audits_denials_without_content(http_app, caplog):
    from starlette.testclient import TestClient

    with caplog.at_level(logging.INFO, logger=emcp.AUDIT_LOGGER_NAME):
        with TestClient(http_app()) as client:
            client.post("/mcp/x", headers=HEADERS, json=LIST_BODY)
    records = [r for r in caplog.records if r.name == emcp.AUDIT_LOGGER_NAME]
    blob = " ".join(r.getMessage() for r in records)
    assert "event=http_request" in blob
    assert "decision=DENY" in blob
    assert "ROUTE_NOT_ALLOWED" in blob
    assert TOKEN not in blob


# ---------------------------------------------------------------------------
# Per-call guards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limit_fails_closed(kanban_home):
    server = _server(rate_limit_per_minute=2)
    ok1 = _structured(await server.call_tool("list_boards", {}))
    ok2 = _structured(await server.call_tool("list_boards", {}))
    denied = _structured(await server.call_tool("list_boards", {}))
    assert "error" not in ok1 and "error" not in ok2
    assert denied["error"]["code"] == "RATE_LIMITED"


@pytest.mark.asyncio
async def test_response_size_cap_fails_closed(kanban_home):
    server = _server(max_response_bytes=64)
    payload = _structured(await server.call_tool("list_boards", {}))
    assert payload["error"]["code"] == "RESPONSE_TOO_LARGE"


@pytest.mark.asyncio
async def test_every_call_is_audited_without_leaking_content(kanban_home, caplog):
    with caplog.at_level(logging.INFO, logger=emcp.AUDIT_LOGGER_NAME):
        await _server().call_tool("get_task_summary", {"public_task_id": kanban_home})
    records = [r for r in caplog.records if r.name == emcp.AUDIT_LOGGER_NAME]
    assert records, "no audit record emitted"
    blob = " ".join(r.getMessage() for r in records)
    assert "event=tool_call" in blob
    assert "tool=get_task_summary" in blob
    assert "decision=ALLOW" in blob
    assert "Zeus live ops slice" not in blob


@pytest.mark.asyncio
async def test_unexpected_failure_logs_only_a_safe_error_class(kanban_home, caplog):
    """A forced exception must not put a traceback, message or path in the log."""
    secret_message = "/home/ubuntu/.hermes/kanban.db token=super-secret-value"

    class _Boom(erm.ExecutiveReadModel):
        def list_boards(self, include_archived: bool = False) -> dict:
            raise ValueError(secret_message)

    server = emcp.build_mcp_server(
        read_model=_Boom(clock=lambda: NOW, identity_salt=b"unit-test-salt",
                         usage_collector=lambda: {"available": False, "providers": []}),
        config=emcp.ServerConfig(local_trusted=True),
    )
    with caplog.at_level(logging.DEBUG, logger=emcp.AUDIT_LOGGER_NAME):
        payload = _structured(await server.call_tool("list_boards", {}))

    assert payload["error"]["code"] == "INTERNAL_ERROR"
    assert secret_message not in json.dumps(payload)
    records = [r for r in caplog.records if r.name == emcp.AUDIT_LOGGER_NAME]
    blob = " ".join(r.getMessage() for r in records)
    assert "error_class=ValueError" in blob
    for forbidden in ("/home/ubuntu", "token=super-secret-value", "Traceback",
                      "executive_read_model.py", "super-secret-value"):
        assert forbidden not in blob, forbidden
    assert not any(r.exc_info for r in records)


@pytest.mark.asyncio
async def test_unknown_board_is_a_structured_fail_closed_error(kanban_home):
    payload = _structured(await _server().call_tool("get_board_summary",
                                                    {"board_slug": "nope"}))
    assert payload["error"]["code"] == "UNKNOWN_BOARD"
    assert "traceback" not in json.dumps(payload).lower()


@pytest.mark.asyncio
async def test_oversized_limit_is_rejected_before_reading(kanban_home):
    """Rejected either by the bounded schema or by the read model — never served."""
    from mcp.server.fastmcp.exceptions import ToolError

    try:
        payload = _structured(await _server().call_tool("list_tasks", {"limit": 5000}))
    except ToolError as exc:
        assert "limit" in str(exc)
    else:
        assert payload["error"]["code"] in ("INVALID_LIMIT", "INVALID_ARGUMENTS")


@pytest.mark.asyncio
async def test_tampered_cursor_is_rejected_through_the_tool(kanban_home):
    payload = _structured(await _server().call_tool(
        "list_tasks", {"cursor": "dGFtcGVyZWQ.notasignature"}))
    assert payload["error"]["code"] == "INVALID_CURSOR"


@pytest.mark.asyncio
async def test_list_filters_accept_bounded_arrays(kanban_home):
    payload = _structured(await _server().call_tool(
        "list_tasks", {"workflow_status": ["RUNNING", "REVIEW"], "limit": 5}))
    assert "error" not in payload
    assert payload["returned"] >= 1


# ---------------------------------------------------------------------------
# Process source binding
# ---------------------------------------------------------------------------


def test_process_source_is_unbound_by_default(monkeypatch):
    monkeypatch.delenv(emcp.PROCESS_SOURCE_ENV, raising=False)
    assert emcp.resolve_process_source() is None


def test_process_source_binds_the_allowlisted_workspace_detector():
    source = emcp.resolve_process_source({emcp.PROCESS_SOURCE_ENV: "workspace"})
    assert isinstance(source, erm.WorkspaceProcessSource)


def test_unknown_process_source_mode_fails_closed():
    with pytest.raises(emcp.ConfigurationError):
        emcp.resolve_process_source({emcp.PROCESS_SOURCE_ENV: "scan-everything"})


# ---------------------------------------------------------------------------
# Live in-memory MCP client session over real Kanban data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_client_session_drives_all_eight_tools(kanban_home):
    from mcp.shared.memory import create_connected_server_and_client_session

    server = _server()
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        listed = await client.list_tools()
        assert {t.name for t in listed.tools} == set(EXPECTED_TOOLS)

        calls = {
            "list_boards": {},
            "get_board_summary": {"board_slug": "default"},
            "get_lane_status": {"board_slug": "default", "lane": "PRODUCT_LANE_1"},
            "list_tasks": {"board_slug": "default", "limit": 5},
            # Resolved by public id alone — no board_slug.
            "get_task_summary": {"public_task_id": kanban_home},
            "get_worker_status": {"board_slug": "default"},
            "get_owner_confirm_queue": {"board_slug": "default"},
            "get_usage_and_output_summary": {"period": "24h"},
        }
        for name, args in calls.items():
            res = await client.call_tool(name, args)
            assert res.isError is False, f"{name} failed: {res.content}"
            data = res.structuredContent
            assert data["measured_at"] == NOW, name
            assert data["data_quality"] in erm.DATA_QUALITIES, name
            assert data["data_marking"]["content_class"] == "UNTRUSTED_BOARD_DATA", name


@pytest.mark.asyncio
async def test_client_cannot_reach_an_undeclared_tool(kanban_home):
    from mcp.shared.memory import create_connected_server_and_client_session

    server = _server()
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        res = await client.call_tool("update_task", {"task_id": "t_x"})
        assert res.isError is True
