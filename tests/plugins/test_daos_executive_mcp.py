"""Protocol-surface contracts for the DAOS Zeus Live Operations MCP server.

The server is a read-only ASGI Streamable HTTP MCP application over the
canonical Kanban ledger. These tests pin the surface itself: the exact tool
inventory, zero mutation reachability, bounded schemas, deny-by-default auth
against a server-controlled scope, audit/rate/size boundaries, and a real
in-memory MCP client session driving all eight tools against real Kanban data.
"""

from __future__ import annotations

import json
import logging
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

NOW = 1_770_000_000


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    conn = kb.connect()
    try:
        tid = kb.create_task(
            conn, title="Zeus live ops slice", tenant="alpha", assignee="athena",
        )
        conn.execute(
            "UPDATE tasks SET status='running', claim_lock='c1', worker_pid=4242 WHERE id=?",
            (tid,),
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


def _read_model():
    return erm.ExecutiveReadModel(
        clock=lambda: NOW,
        pid_probe=lambda pid: True,
        identity_salt=b"unit-test-salt",
        usage_collector=lambda: {"available": False, "providers": []},
    )


def _server(**over):
    kw = {
        "read_model": _read_model(),
        "config": emcp.ServerConfig(local_trusted=True, **over),
    }
    return emcp.build_mcp_server(**kw)


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

    for tool in tools.values():
        schema = tool.inputSchema
        assert schema.get("additionalProperties") is False, tool.name

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
    result = await server.call_tool("list_boards", {})
    payload = _structured(result)
    assert payload["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_client_declared_scope_is_ignored(kanban_home):
    """A client-supplied scope argument can never grant access."""
    server = emcp.build_mcp_server(read_model=_read_model(), config=emcp.ServerConfig())
    result = await server.call_tool("list_boards", {"scope": "daos.executive.read"})
    payload = _structured(result)
    assert payload["error"]["code"] in ("UNAUTHORIZED", "INVALID_ARGUMENTS")


def test_token_verifier_grants_only_the_read_scope(monkeypatch):
    import anyio

    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_TOKEN", "s3cret-owner-token")
    verifier = emcp.ExecutiveTokenVerifier.from_env()

    good = anyio.run(verifier.verify_token, "s3cret-owner-token")
    assert good is not None
    assert good.scopes == [emcp.REQUIRED_SCOPE]
    assert good.token == "s3cret-owner-token"
    assert "s3cret-owner-token" not in good.client_id

    assert anyio.run(verifier.verify_token, "wrong-token") is None
    assert anyio.run(verifier.verify_token, "") is None


def test_unconfigured_verifier_denies_every_token(monkeypatch):
    import anyio

    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN", raising=False)
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_TOKEN_FILE", raising=False)
    verifier = emcp.ExecutiveTokenVerifier(tokens=())
    assert anyio.run(verifier.verify_token, "anything") is None


def test_streamable_http_app_rejects_unauthenticated_requests(monkeypatch, kanban_home):
    from starlette.testclient import TestClient

    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_TOKEN", "s3cret-owner-token")
    app = emcp.build_asgi_app(read_model=_read_model())
    with TestClient(app) as client:
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert resp.status_code == 401
        bad = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer not-the-token",
                     "Accept": "application/json, text/event-stream"},
        )
        assert bad.status_code == 401


def test_streamable_http_app_serves_a_verified_caller(monkeypatch, kanban_home):
    """The boundary is deny-by-default, not deny-always: a verified token works."""
    from starlette.testclient import TestClient

    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_TOKEN", "s3cret-owner-token")
    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_ALLOWED_HOSTS", "testserver")
    app = emcp.build_asgi_app(read_model=_read_model())
    headers = {
        "Authorization": "Bearer s3cret-owner-token",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    with TestClient(app) as client:
        init = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "zeus-test", "version": "1"},
            },
        })
        assert init.status_code == 200, init.text
        listed = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        })
        assert listed.status_code == 200, listed.text
        names = {t["name"] for t in listed.json()["result"]["tools"]}
        assert names == set(EXPECTED_TOOLS)


def test_streamable_http_app_keeps_dns_rebinding_protection(monkeypatch, kanban_home):
    """A verified token from an unexpected Host is still refused."""
    from starlette.testclient import TestClient

    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_TOKEN", "s3cret-owner-token")
    monkeypatch.delenv("DAOS_EXECUTIVE_MCP_ALLOWED_HOSTS", raising=False)
    app = emcp.build_asgi_app(read_model=_read_model())
    with TestClient(app) as client:
        resp = client.post("/mcp", headers={
            "Authorization": "Bearer s3cret-owner-token",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        assert resp.status_code == 421


def test_streamable_http_app_is_asgi_and_mounts_at_mcp(monkeypatch, kanban_home):
    monkeypatch.setenv("DAOS_EXECUTIVE_MCP_TOKEN", "s3cret-owner-token")
    app = emcp.build_asgi_app(read_model=_read_model())
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/mcp" in paths
    assert callable(app)


# ---------------------------------------------------------------------------
# Request guards: rate limit, response size, audit
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
    assert "get_task_summary" in blob
    assert "decision=ALLOW" in blob
    assert "Zeus live ops slice" not in blob


@pytest.mark.asyncio
async def test_unknown_board_is_a_structured_fail_closed_error(kanban_home):
    result = await _server().call_tool("get_board_summary", {"board_slug": "nope"})
    payload = _structured(result)
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


# ---------------------------------------------------------------------------
# Live in-memory MCP client session over real Kanban data
# ---------------------------------------------------------------------------


def _structured(result):
    """Normalise FastMCP's (content, structured) tool return into a dict."""
    if isinstance(result, tuple):
        _content, structured = result
    else:  # pragma: no cover - defensive
        structured = result
    return structured


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
            "get_lane_status": {"board_slug": "default", "lane": "alpha"},
            "list_tasks": {"board_slug": "default", "limit": 5},
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
