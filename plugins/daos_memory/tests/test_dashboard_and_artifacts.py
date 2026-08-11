from __future__ import annotations

import json
from pathlib import Path
import tomllib

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugins.daos_memory.dashboard.plugin_api import create_router


ROOT = Path(__file__).resolve().parents[1]


def proxy_client(handler):
    app = FastAPI()
    app.include_router(create_router(
        service_url="http://memory.internal",
        owner_token="owner-secret",
        timeout_seconds=1.0,
        transport=httpx.MockTransport(handler),
    ))
    return TestClient(app)


def test_proxy_keeps_owner_token_server_side_and_rotation_secret_is_one_response():
    seen = []

    def handler(request):
        seen.append(request)
        assert request.headers["authorization"] == "Bearer owner-secret"
        if request.url.path.endswith("/rotate"):
            return httpx.Response(200, json={"agent_id": "zeus", "bootstrap_key": "one-time-secret", "expires_at": "soon", "max_uses": 1})
        return httpx.Response(200, json={"items": [{"agent_id": "zeus", "status": "ACTIVE", "last_access_at": None}]})

    client = proxy_client(handler)
    listed = client.get("/agents")
    assert listed.status_code == 200
    assert "owner-secret" not in listed.text
    assert "bootstrap_key" not in listed.text
    rotated = client.post("/agents/zeus/rotate")
    assert rotated.json()["bootstrap_key"] == "one-time-secret"
    assert "owner-secret" not in rotated.text
    assert all("owner-secret" not in str(request.url) for request in seen)


def test_proxy_fails_closed_when_service_is_unavailable():
    def handler(request):
        raise httpx.ConnectError("offline", request=request)

    client = proxy_client(handler)
    response = client.get("/memory", params={"view": "current"})
    assert response.status_code == 503
    assert response.json()["detail"] == "memory service unavailable"
    assert "offline" not in response.text


def test_dashboard_artifacts_define_top_level_memory_views():
    manifest = json.loads((ROOT / "dashboard" / "manifest.json").read_text())
    assert manifest["tab"]["path"] == "/memory"
    script = (ROOT / "dashboard" / "dist" / "index.js").read_text()
    for view in ("Current", "Decisions", "Policies", "Agent Notes", "History", "Agent Access"):
        assert view in script
    assert "owner-secret" not in script


def test_migration_has_only_required_core_tables_and_hashed_credential_columns():
    sql = (ROOT / "migrations" / "001_daos_memory_v01.sql").read_text().lower()
    for table in ("context_events", "canonical_policies", "agent_registry", "context_relations"):
        assert f"create table daos_memory.{table}" in sql
    assert "bootstrap_key_hash" in sql
    assert "access_token_hash" in sql
    assert "bootstrap_key text" not in sql
    assert "access_token text" not in sql
    assert "delete from" not in sql


def test_systemd_template_is_separate_bounded_and_hardened():
    unit = (ROOT / "systemd" / "daos-memory.service").read_text()
    assert "uvicorn" in unit
    assert "MemoryMax=" in unit
    assert "TimeoutStartSec=" in unit
    assert "EnvironmentFile=" in unit
    assert "NoNewPrivileges=true" in unit
    assert "Environment=HERMES_CONFIG_PATH=/etc/daos-memory/config.yaml" in unit
    assert "hermes gateway" not in unit.lower()


def test_wheel_package_data_declares_only_daos_runtime_artifacts():
    pyproject = tomllib.loads((ROOT.parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    plugin_data = pyproject["tool"]["setuptools"]["package-data"]["plugins"]
    for artifact in (
        "daos_memory/migrations/001_daos_memory_v01.sql",
        "daos_memory/systemd/daos-memory.service",
        "daos_memory/requirements.txt",
    ):
        assert artifact in plugin_data
