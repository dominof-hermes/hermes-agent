"""Separate FastAPI entrypoint for DAOS Shared Memory / Context Service v0.1."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from .auth import credential_matches, hash_credential, new_credential
from .config import Settings
from .models import BootstrapRequest, EventWrite, RotateRequest

_FORBIDDEN_QUERY_KEYS = {"key", "token", "access_token", "bootstrap_key", "owner_token"}
_AGENT_AUTHORITIES = {"AGENT_ASSESSMENT", "HYPOTHESIS", "OPERATIONAL_STATE"}


def create_app(*, settings: Settings, store: Any, clock: Callable[[], datetime] | None = None) -> FastAPI:
    now = clock or (lambda: datetime.now(timezone.utc))

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        close = getattr(store, "close", None)
        if close:
            await close()

    app = FastAPI(title="DAOS Memory Service", version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def reject_url_credentials(request: Request, call_next):
        if _FORBIDDEN_QUERY_KEYS.intersection(request.query_params.keys()):
            return JSONResponse(status_code=400, content={"detail": "credentials are accepted in Authorization header only"})
        return await call_next(request)

    async def bounded(awaitable):
        try:
            return await asyncio.wait_for(awaitable, timeout=settings.query_timeout_seconds)
        except (TimeoutError, asyncio.TimeoutError):
            raise HTTPException(status_code=503, detail="memory service unavailable") from None

    def bearer(authorization: str | None) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer authentication required")
        value = authorization[7:]
        if not value or len(value) > 512:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credential")
        return value

    async def owner_auth(authorization: str | None = Header(default=None)) -> None:
        if not credential_matches(bearer(authorization), settings.owner_token):
            raise HTTPException(status_code=401, detail="invalid credential")

    async def agent_auth(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        token_hash = hash_credential(bearer(authorization), settings.credential_pepper)
        agent = await bounded(store.authenticate_access(token_hash, now()))
        if not agent:
            raise HTTPException(status_code=401, detail="invalid or expired access token")
        return agent

    @app.get("/health")
    async def health():
        try:
            await bounded(store.health())
        except HTTPException:
            return JSONResponse(status_code=503, content={"status": "degraded", "database": "unavailable"})
        except Exception:
            return JSONResponse(status_code=503, content={"status": "degraded", "database": "unavailable"})
        return {"status": "ok", "database": "ok"}

    @app.post("/v1/bootstrap")
    async def bootstrap(body: BootstrapRequest, authorization: str | None = Header(default=None)):
        key_hash = hash_credential(bearer(authorization), settings.credential_pepper)
        agent = await bounded(store.consume_bootstrap(body.agent_id, key_hash, now()))
        if not agent:
            raise HTTPException(status_code=401, detail="invalid, expired, used, or revoked bootstrap key")
        access_token = new_credential("daos_access")
        access_expires_at = now() + timedelta(seconds=settings.access_ttl_seconds)
        categories = ["GLOBAL", *[str(v).upper() for v in agent.get("role_categories", [])]]
        policies = await bounded(store.get_policies(categories, 20))
        events = await bounded(store.read_current(body.product, body.topic, min(settings.max_results, 20)))
        global_principles = [_compact_policy(p) for p in policies if p.get("category") == "GLOBAL"][:10]
        role_principles = [_compact_policy(p) for p in policies if p.get("category") != "GLOBAL"][:10]
        decisions = [_compact_event(e) for e in events
                     if e.get("memory_type") == "DECISION"
                     and e.get("authority_level") in {"OWNER_DECISION", "VERIFIED_EVIDENCE"}][:5]
        next_actions = [_compact_event(e) for e in events if e.get("memory_type") == "NEXT_ACTION"][:5]
        excluded = {e["id"] for e in decisions + next_actions}
        current = [_compact_event(e) for e in events if str(e.get("id")) not in excluded][:10]
        payload = {
            "agent_id": body.agent_id,
            "access_token": access_token,
            "access_expires_at": access_expires_at,
            "scopes": ["memory:read", "memory:write"],
            "global_principles": global_principles,
            "role_principles": role_principles,
            "current_context": current,
            "owner_decisions": decisions,
            "next_actions": next_actions,
            "history": [],
        }
        _enforce_bootstrap_size(payload, settings.max_bootstrap_bytes)
        await bounded(store.set_access_token(
            body.agent_id,
            hash_credential(access_token, settings.credential_pepper),
            access_expires_at,
        ))
        return payload

    @app.get("/v1/current")
    async def read_current(
        product: str | None = Query(default=None, max_length=120),
        topic: str | None = Query(default=None, max_length=160),
        limit: int = Query(default=25, ge=1),
        agent: dict[str, Any] = Depends(agent_auth),
    ):
        del agent
        rows = await bounded(store.read_current(product, topic, min(limit, settings.max_results)))
        return {"items": rows, "count": len(rows)}

    @app.get("/v1/history")
    async def search_history(
        product: str | None = Query(default=None, max_length=120),
        topic: str | None = Query(default=None, max_length=160),
        query: str | None = Query(default=None, max_length=240),
        limit: int = Query(default=25, ge=1),
        agent: dict[str, Any] = Depends(agent_auth),
    ):
        del agent
        if not any((product, topic, query)):
            raise HTTPException(status_code=400, detail="history requires a product, topic, or query filter")
        rows = await bounded(store.search_history(product, topic, query, min(limit, settings.max_results)))
        return {"items": rows, "count": len(rows)}

    @app.post("/v1/events", status_code=201)
    async def write_event(body: EventWrite, agent: dict[str, Any] = Depends(agent_auth)):
        _authorize_write(agent, body)
        event = _agent_event(agent, body)
        return await bounded(store.write_event(event))

    @app.get("/v1/events/{event_id}")
    async def read_event(event_id: UUID, agent: dict[str, Any] = Depends(agent_auth)):
        del agent
        row = await bounded(store.read_event(str(event_id)))
        if not row:
            raise HTTPException(status_code=404, detail="event not found")
        return row

    @app.post("/v1/events/{event_id}/supersede")
    async def supersede(event_id: UUID, body: EventWrite, agent: dict[str, Any] = Depends(agent_auth)):
        _authorize_write(agent, body)
        event = _agent_event(agent, body)
        if event["status"] != "CURRENT":
            raise HTTPException(status_code=409, detail="historical imports cannot supersede current events")
        row = await bounded(store.supersede_event(
            str(event_id), agent["agent_id"], event,
        ))
        if not row:
            raise HTTPException(status_code=404, detail="current event not found")
        return row

    @app.get("/v1/admin/agents", dependencies=[Depends(owner_auth)])
    async def list_agents():
        rows = await bounded(store.list_agents(min(settings.max_results, 100)))
        safe_keys = (
            "agent_id", "status", "role_categories", "allowed_memory_types",
            "last_access_at", "bootstrap_expires_at", "bootstrap_uses_remaining", "updated_at",
        )
        return {"items": [{key: row.get(key) for key in safe_keys} for row in rows]}

    @app.post("/v1/admin/agents/{agent_id}/rotate", dependencies=[Depends(owner_auth)])
    async def rotate_agent(agent_id: str, body: RotateRequest | None = None):
        body = body or RotateRequest()
        max_uses = body.max_uses or settings.max_bootstrap_uses
        ttl = body.ttl_seconds or settings.bootstrap_ttl_seconds
        key = new_credential("daos_bootstrap")
        expires = now() + timedelta(seconds=ttl)
        agent = await bounded(store.rotate_bootstrap(agent_id, hash_credential(key, settings.credential_pepper), expires, max_uses))
        if not agent:
            raise HTTPException(status_code=404, detail="agent not found")
        return {"agent_id": agent_id, "bootstrap_key": key, "expires_at": expires, "max_uses": max_uses}

    @app.post("/v1/admin/agents/{agent_id}/revoke", dependencies=[Depends(owner_auth)])
    async def revoke_agent(agent_id: str):
        agent = await bounded(store.revoke_agent(agent_id))
        if not agent:
            raise HTTPException(status_code=404, detail="agent not found")
        return {"agent_id": agent_id, "status": "REVOKED"}

    @app.get("/v1/admin/events", dependencies=[Depends(owner_auth)])
    async def admin_events(
        view: str = Query(default="current", pattern="^(current|decisions|agent_notes|history)$"),
        product: str | None = Query(default=None, max_length=120),
        topic: str | None = Query(default=None, max_length=160),
        limit: int = Query(default=25, ge=1),
    ):
        rows = await bounded(store.admin_events(view, product, topic, min(limit, settings.max_results)))
        return {"items": rows, "count": len(rows)}

    @app.get("/v1/admin/policies", dependencies=[Depends(owner_auth)])
    async def admin_policies():
        rows = await bounded(store.get_policies(["GLOBAL", "STRATEGY", "DEVELOPMENT", "EXECUTION", "RESEARCH", "MEMORY_WRITE"], settings.max_results))
        return {"items": rows, "count": len(rows)}

    return app


def _authorize_write(agent: dict[str, Any], body: EventWrite) -> None:
    if body.memory_type not in set(agent.get("allowed_memory_types") or []):
        raise HTTPException(status_code=403, detail="memory type is outside this agent's writer scope")
    if body.authority_level not in _AGENT_AUTHORITIES:
        raise HTTPException(status_code=403, detail="agents cannot assert protected authority levels")


def _agent_event(agent: dict[str, Any], body: EventWrite) -> dict[str, Any]:
    values = body.model_dump()
    temporal_fields = ("occurred_at", "effective_from", "effective_to", "source_session_at")
    historical_import = any(values.get(field) is not None for field in temporal_fields)
    return {
        **values, "actor": agent["agent_id"], "actor_role": agent["agent_id"].upper(),
        "status": "HISTORY" if historical_import else "CURRENT", "supersedes_id": None,
    }


def _compact_event(event: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id", "created_at", "occurred_at", "effective_from", "effective_to",
        "source_session_at", "product", "topic", "memory_type", "event_type",
        "title", "summary", "status", "authority_level", "actor", "work_id", "source_ref",
    )
    compact = {key: event.get(key) for key in keys}
    compact["summary"] = str(compact.get("summary") or "")[:400]
    return compact


def _compact_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": policy.get("id"),
        "category": policy.get("category"),
        "title": policy.get("title"),
        "content": str(policy.get("content") or "")[:400],
        "status": policy.get("status"),
        "priority": policy.get("priority"),
    }


def _enforce_bootstrap_size(payload: dict[str, Any], max_bytes: int) -> None:
    encoded = json.dumps(jsonable_encoder(payload), separators=(",", ":")).encode("utf-8")
    if len(encoded) > max_bytes:
        raise HTTPException(status_code=503, detail="bounded bootstrap payload unavailable")
