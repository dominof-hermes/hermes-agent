"""Dashboard-authenticated, fail-closed proxy to the isolated memory service.

The dashboard host applies its normal session authentication before mounting
this router. The owner token exists only in this server-side module and is
never returned by list/read responses.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import yaml
from fastapi import APIRouter, HTTPException, Query


def create_router(*, service_url: str, owner_token: str, timeout_seconds: float, transport=None) -> APIRouter:
    router = APIRouter()
    base = service_url.rstrip("/")

    async def call(method: str, path: str, *, params=None, json=None, allow_bootstrap_key: bool = False):
        if not owner_token or not base.startswith(("http://", "https://")):
            raise HTTPException(status_code=503, detail="memory service unavailable")
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds, transport=transport) as client:
                response = await client.request(
                    method, f"{base}{path}", params=params, json=json,
                    headers={"Authorization": f"Bearer {owner_token}"},
                )
            if response.status_code >= 500:
                raise HTTPException(status_code=503, detail="memory service unavailable")
            if response.status_code >= 400:
                raise HTTPException(status_code=response.status_code, detail="memory service request rejected")
            data = response.json()
            return _redact(data, allow_bootstrap_key=allow_bootstrap_key)
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError):
            raise HTTPException(status_code=503, detail="memory service unavailable") from None

    @router.get("/health")
    async def health():
        return await call("GET", "/health")

    @router.get("/agents")
    async def agents():
        return await call("GET", "/v1/admin/agents")

    @router.post("/agents/{agent_id}/rotate")
    async def rotate(agent_id: str):
        return await call("POST", f"/v1/admin/agents/{agent_id}/rotate", json={}, allow_bootstrap_key=True)

    @router.post("/agents/{agent_id}/revoke")
    async def revoke(agent_id: str):
        return await call("POST", f"/v1/admin/agents/{agent_id}/revoke")

    @router.get("/memory")
    async def memory(
        view: str = Query(default="current", pattern="^(current|decisions|policies|agent_notes|history|knowledge_vault)$"),
        product: str | None = Query(default=None, max_length=120),
        topic: str | None = Query(default=None, max_length=160),
        limit: int = Query(default=25, ge=1, le=50),
    ):
        params = {"view": view, "product": product, "topic": topic, "limit": limit}
        return await call("GET", "/v1/admin/events", params={key: value for key, value in params.items() if value is not None})

    @router.get("/events/{event_id}")
    async def event_detail(event_id: UUID):
        return await call("GET", f"/v1/admin/events/{event_id}")

    @router.get("/events/{event_id}/knowledge")
    async def event_knowledge(event_id: UUID):
        return await call("GET", f"/v1/admin/events/{event_id}/knowledge")

    @router.get("/sources/{source_id}")
    async def source_detail(source_id: UUID):
        return await call("GET", f"/v1/admin/sources/{source_id}")

    @router.post("/decisions/{decision_id}/approve")
    async def approve(decision_id: UUID, body: dict[str, Any] | None = None):
        return await call("POST", f"/v1/admin/decisions/{decision_id}/approve", json=body or {})

    @router.post("/decisions/{decision_id}/reject")
    async def reject(decision_id: UUID, body: dict[str, Any] | None = None):
        return await call("POST", f"/v1/admin/decisions/{decision_id}/reject", json=body or {})

    @router.post("/policies")
    async def create_policy(body: dict[str, Any]):
        return await call("POST", "/v1/admin/policies", json=body)

    @router.get("/policies")
    async def policies():
        return await call("GET", "/v1/admin/policies")

    return router


def _redact(value: Any, *, allow_bootstrap_key: bool = False) -> Any:
    if isinstance(value, list):
        return [_redact(item, allow_bootstrap_key=allow_bootstrap_key) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        lowered = key.lower()
        if any(marker in lowered for marker in ("owner_token", "token_hash", "key_hash", "access_token")):
            continue
        if "bootstrap_key" in lowered and not allow_bootstrap_key:
            continue
        result[key] = _redact(item, allow_bootstrap_key=allow_bootstrap_key)
    return result


def _runtime_config() -> tuple[str, float]:
    try:
        from hermes_constants import get_hermes_home

        path = Path(get_hermes_home()) / "config.yaml"
    except Exception:
        path = Path.home() / ".hermes" / "config.yaml"
    raw = {}
    if path.is_file():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw = loaded.get("daos_memory") or {}
    service_url = str(raw.get("service_url", "http://127.0.0.1:8791"))
    timeout = max(0.1, min(30.0, float(raw.get("request_timeout_seconds", 3.0))))
    return service_url, timeout


_service_url, _timeout = _runtime_config()
router = create_router(
    service_url=_service_url,
    owner_token=os.environ.get("DAOS_MEMORY_OWNER_TOKEN", ""),
    timeout_seconds=_timeout,
)
