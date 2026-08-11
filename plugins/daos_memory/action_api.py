"""Authenticated GPT Action adapter for the DAOS Zeus Shared Memory contract."""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import secrets
import stat
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import UUID

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .service.models import MAX_METADATA_JSON_BYTES


BASE_PATH = "/zeus-memory/v1"
MAX_REQUEST_BODY_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 90_000
ACTION_PATHS = frozenset({
    f"{BASE_PATH}/bootstrap",
    f"{BASE_PATH}/current",
    f"{BASE_PATH}/history",
    f"{BASE_PATH}/events",
    f"{BASE_PATH}/event",
})


class ActionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BootstrapBody(ActionBody):
    bootstrap_key: str = Field(min_length=16, max_length=512)
    product: str | None = Field(default=None, max_length=120)
    topic: str | None = Field(default=None, max_length=160)


class ContextBody(ActionBody):
    context_id: str = Field(min_length=32, max_length=128)


class CurrentBody(ContextBody):
    product: str | None = Field(default=None, max_length=120)
    topic: str | None = Field(default=None, max_length=160)
    limit: int = Field(default=25, ge=1, le=25)


class HistoryBody(CurrentBody):
    query: str | None = Field(default=None, max_length=240)


class WriteBody(ContextBody):
    product: str = Field(min_length=1, max_length=120)
    topic: str = Field(min_length=1, max_length=160)
    memory_type: Literal["STRATEGY", "ASSESSMENT", "SESSION_SUMMARY"]
    event_type: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=240)
    summary: str = Field(min_length=1, max_length=1200)
    content: str = Field(min_length=1, max_length=8000)
    authority_level: Literal["AGENT_ASSESSMENT", "HYPOTHESIS", "OPERATIONAL_STATE"]
    thread_id: str | None = Field(default=None, max_length=160)
    work_id: str | None = Field(default=None, max_length=160)
    source_ref: str | None = Field(default=None, max_length=500)
    occurred_at: AwareDatetime | None = None
    effective_from: AwareDatetime | None = None
    effective_to: AwareDatetime | None = None
    source_session_at: AwareDatetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def event_type_is_canonical(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("event_type must not be blank")
        return normalized

    @model_validator(mode="after")
    def temporal_contract_is_valid(self):
        if self.event_type.upper() == "HISTORY_IMPORT":
            if self.occurred_at is None or self.source_session_at is None:
                raise ValueError("HISTORY_IMPORT requires occurred_at and source_session_at")
        if self.effective_to is not None:
            start = self.effective_from or self.occurred_at
            if start is None:
                raise ValueError("effective_to requires effective_from or occurred_at")
            if self.effective_to < start:
                raise ValueError("effective_to must not precede effective_from or occurred_at")
        return self

    @field_validator("metadata")
    @classmethod
    def metadata_is_bounded_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_METADATA_JSON_BYTES:
            raise ValueError("metadata exceeds bounded JSON size")
        return value


class EventBody(ContextBody):
    event_id: UUID


class MemoryUpstream(Protocol):
    async def bootstrap(
        self, bootstrap_key: str, product: str | None, topic: str | None
    ) -> dict[str, Any]: ...

    async def read_current(
        self, access_token: str, product: str | None, topic: str | None, limit: int
    ) -> dict[str, Any]: ...

    async def search_history(
        self,
        access_token: str,
        product: str | None,
        topic: str | None,
        query: str | None,
        limit: int,
    ) -> dict[str, Any]: ...

    async def write_event(
        self, access_token: str, event: dict[str, Any]
    ) -> dict[str, Any]: ...

    async def read_event(
        self, access_token: str, event_id: str
    ) -> dict[str, Any]: ...


class UpstreamHTTPError(RuntimeError):
    def __init__(self, status_code: int):
        super().__init__("memory upstream request failed")
        self.status_code = status_code


class HttpMemoryUpstream:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 3.0,
        max_response_bytes: int = 90_000,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    async def _request(
        self,
        method: str,
        path: str,
        token: str,
        *,
        payload: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        def send() -> dict[str, Any]:
            url = self.base_url + path
            if query:
                encoded = urllib.parse.urlencode({
                    key: value for key, value in query.items() if value is not None
                })
                if encoded:
                    url += "?" + encoded
            data = None
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
            if payload is not None:
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                headers["Content-Type"] = "application/json"
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    raw = response.read(self.max_response_bytes + 1)
            except urllib.error.HTTPError as exc:
                raise UpstreamHTTPError(exc.code) from None
            except (OSError, TimeoutError, urllib.error.URLError):
                raise UpstreamHTTPError(503) from None
            if len(raw) > self.max_response_bytes:
                raise UpstreamHTTPError(503)
            try:
                parsed = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise UpstreamHTTPError(503) from None
            if not isinstance(parsed, dict):
                raise UpstreamHTTPError(503)
            return parsed

        return await asyncio.to_thread(send)

    async def bootstrap(self, bootstrap_key, product, topic):
        return await self._request(
            "POST",
            "/v1/bootstrap",
            bootstrap_key,
            payload={"agent_id": "zeus", "product": product, "topic": topic},
        )

    async def read_current(self, access_token, product, topic, limit):
        return await self._request(
            "GET",
            "/v1/current",
            access_token,
            query={"product": product, "topic": topic, "limit": limit},
        )

    async def search_history(self, access_token, product, topic, query, limit):
        return await self._request(
            "GET",
            "/v1/history",
            access_token,
            query={"product": product, "topic": topic, "query": query, "limit": limit},
        )

    async def write_event(self, access_token, event):
        return await self._request(
            "POST", "/v1/events", access_token, payload=event
        )

    async def read_event(self, access_token, event_id):
        return await self._request(
            "GET", f"/v1/events/{event_id}", access_token
        )


class _Context:
    def __init__(self, access_token: str, expires_at: datetime):
        self.access_token = access_token
        self.expires_at = expires_at


class _ContextVault:
    def __init__(
        self,
        clock: Callable[[], datetime],
        max_contexts: int = 128,
    ):
        self._clock = clock
        self._max_contexts = max_contexts
        self._items: dict[str, _Context] = {}

    def create(self, access_token: str, expires_at: datetime) -> str:
        now = self._clock()
        self._items = {
            key: value for key, value in self._items.items() if value.expires_at > now
        }
        while len(self._items) >= self._max_contexts:
            self._items.pop(next(iter(self._items)))
        context_id = secrets.token_urlsafe(32)
        self._items[context_id] = _Context(access_token, expires_at)
        return context_id

    def access_token(self, context_id: str) -> str | None:
        context = self._items.get(context_id)
        if context is None:
            return None
        if context.expires_at <= self._clock():
            self._items.pop(context_id, None)
            return None
        return context.access_token


class _ActionBoundaryMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int,
        tokens: tuple[str, ...],
    ):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.tokens = tokens

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") not in ACTION_PATHS:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        if not _authorized(authorization, self.tokens):
            await _error(401, "UNAUTHORIZED", "Bearer token required")(
                scope, receive, send
            )
            return

        if scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                content_length = int(raw_length)
            except ValueError:
                await _error(400, "INVALID_REQUEST", "Request body length is invalid")(
                    scope, receive, send
                )
                return
            if content_length < 0:
                await _error(400, "INVALID_REQUEST", "Request body length is invalid")(
                    scope, receive, send
                )
                return
            if content_length > self.max_body_bytes:
                await _error(413, "REQUEST_TOO_LARGE", "Request body exceeds the allowed size")(
                    scope, receive, send
                )
                return

        chunks: list[bytes] = []
        received = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                await _error(400, "INVALID_REQUEST", "Request body is incomplete")(
                    scope, receive, send
                )
                return
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > self.max_body_bytes:
                await _error(413, "REQUEST_TOO_LARGE", "Request body exceeds the allowed size")(
                    scope, receive, send
                )
                return
            chunks.append(chunk)
            more_body = bool(message.get("more_body", False))

        body = b"".join(chunks)
        replayed = False

        async def bounded_receive() -> Message:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, bounded_receive, send)


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"ok": False, "error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store"},
    )


def _bearer(value: str | None) -> str | None:
    if not value or not value.startswith("Bearer "):
        return None
    token = value[7:]
    if not token or len(token) > 512 or token != token.strip():
        return None
    return token


def _authorized(value: str | None, tokens: tuple[str, ...]) -> bool:
    candidate = _bearer(value)
    return candidate is not None and hmac.compare_digest(candidate, tokens[0])


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("invalid upstream expiration")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("invalid upstream expiration")
    return parsed.astimezone(timezone.utc)


def _bounded(payload: dict[str, Any]) -> JSONResponse:
    response = JSONResponse(payload, headers={"Cache-Control": "no-store"})
    if len(response.body) <= MAX_RESPONSE_BYTES:
        return response
    return _error(503, "RESPONSE_TOO_LARGE", "Memory response is temporarily unavailable")


def _upstream_failure(exc: UpstreamHTTPError) -> JSONResponse:
    if exc.status_code == 400:
        return _error(400, "INVALID_REQUEST", "Memory request was rejected")
    if exc.status_code == 401:
        return _error(401, "CONTEXT_EXPIRED", "Memory context is invalid or expired")
    if exc.status_code == 403:
        return _error(403, "FORBIDDEN", "Zeus writer scope denied this event")
    if exc.status_code == 404:
        return _error(404, "NOT_FOUND", "Memory event was not found")
    return _error(503, "MEMORY_UNAVAILABLE", "Memory service is temporarily unavailable")


def _bootstrap_identifiers(payload: dict[str, Any]) -> tuple[list[str], list[str]]:
    rows: list[dict[str, Any]] = []
    for key in ("current_context", "owner_decisions", "next_actions"):
        value = payload.get(key, [])
        if isinstance(value, list):
            rows.extend(row for row in value if isinstance(row, dict))
    event_ids = [str(row["id"]) for row in rows if row.get("id")]
    source_refs = [str(row["source_ref"]) for row in rows if row.get("source_ref")]
    return event_ids, source_refs


def build_asgi_app(
    *,
    upstream: MemoryUpstream,
    tokens: Sequence[str],
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    token_set = tuple(tokens)
    if len(token_set) != 1 or not token_set[0]:
        raise RuntimeError("Zeus Memory Action requires exactly one server token")
    now = clock or (lambda: datetime.now(timezone.utc))
    vault = _ContextVault(now)
    app = FastAPI(
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
        redirect_slashes=False,
    )

    app.add_middleware(
        _ActionBoundaryMiddleware,
        max_body_bytes=MAX_REQUEST_BODY_BYTES,
        tokens=token_set,
    )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _exc: RequestValidationError):
        return _error(400, "INVALID_REQUEST", "Request does not match the Memory Action contract")

    @app.exception_handler(405)
    async def method_not_allowed(_request: Request, _exc: Exception):
        return _error(405, "METHOD_NOT_ALLOWED", "Method is not allowed")

    @app.post(f"{BASE_PATH}/bootstrap", include_in_schema=False)
    async def memory_bootstrap(
        body: BootstrapBody,
        authorization: str | None = Header(default=None),
    ):
        if not _authorized(authorization, token_set):
            return _error(401, "UNAUTHORIZED", "Bearer token required")
        try:
            result = await upstream.bootstrap(body.bootstrap_key, body.product, body.topic)
            access_token = result.get("access_token")
            expires_at = _parse_timestamp(result.get("access_expires_at"))
            if not isinstance(access_token, str) or not access_token or expires_at <= now():
                raise ValueError("invalid upstream bootstrap")
            context_id = vault.create(access_token, expires_at)
            safe = {key: value for key, value in result.items() if key != "access_token"}
            event_ids, source_refs = _bootstrap_identifiers(safe)
            return _bounded({
                **safe,
                "context_id": context_id,
                "bootstrap_event_ids": event_ids,
                "bootstrap_source_refs": source_refs,
            })
        except UpstreamHTTPError as exc:
            if exc.status_code == 401:
                return _error(401, "BOOTSTRAP_REJECTED", "Bootstrap Key is invalid, expired, used, or revoked")
            return _upstream_failure(exc)
        except Exception:
            return _error(503, "MEMORY_UNAVAILABLE", "Memory bootstrap is temporarily unavailable")

    def context_token(authorization: str | None, context_id: str):
        if not _authorized(authorization, token_set):
            return None, _error(401, "UNAUTHORIZED", "Bearer token required")
        access_token = vault.access_token(context_id)
        if access_token is None:
            return None, _error(401, "CONTEXT_EXPIRED", "Memory context is invalid or expired")
        return access_token, None

    @app.post(f"{BASE_PATH}/current", include_in_schema=False)
    async def memory_read_current(
        body: CurrentBody,
        authorization: str | None = Header(default=None),
    ):
        access_token, failure = context_token(authorization, body.context_id)
        if failure:
            return failure
        try:
            return _bounded(await upstream.read_current(
                access_token, body.product, body.topic, body.limit
            ))
        except UpstreamHTTPError as exc:
            return _upstream_failure(exc)
        except Exception:
            return _error(503, "MEMORY_UNAVAILABLE", "Current memory is temporarily unavailable")

    @app.post(f"{BASE_PATH}/history", include_in_schema=False)
    async def memory_search_history(
        body: HistoryBody,
        authorization: str | None = Header(default=None),
    ):
        access_token, failure = context_token(authorization, body.context_id)
        if failure:
            return failure
        if not any((body.product, body.topic, body.query)):
            return _error(400, "FILTER_REQUIRED", "History requires a product, topic, or query")
        try:
            return _bounded(await upstream.search_history(
                access_token, body.product, body.topic, body.query, body.limit
            ))
        except UpstreamHTTPError as exc:
            return _upstream_failure(exc)
        except Exception:
            return _error(503, "MEMORY_UNAVAILABLE", "Memory history is temporarily unavailable")

    @app.post(f"{BASE_PATH}/events", include_in_schema=False)
    async def memory_write(
        body: WriteBody,
        authorization: str | None = Header(default=None),
    ):
        access_token, failure = context_token(authorization, body.context_id)
        if failure:
            return failure
        event = body.model_dump(mode="json", exclude={"context_id"}, exclude_none=True)
        event["source_interface"] = "chatgpt_zeus_action"
        try:
            return _bounded(await upstream.write_event(access_token, event))
        except UpstreamHTTPError as exc:
            return _upstream_failure(exc)
        except Exception:
            return _error(503, "MEMORY_UNAVAILABLE", "Memory write is temporarily unavailable")

    @app.post(f"{BASE_PATH}/event", include_in_schema=False)
    async def memory_read_event(
        body: EventBody,
        authorization: str | None = Header(default=None),
    ):
        access_token, failure = context_token(authorization, body.context_id)
        if failure:
            return failure
        try:
            return _bounded(await upstream.read_event(access_token, str(body.event_id)))
        except UpstreamHTTPError as exc:
            return _upstream_failure(exc)
        except Exception:
            return _error(503, "MEMORY_UNAVAILABLE", "Memory event is temporarily unavailable")

    @app.get("/health", include_in_schema=False)
    async def health():
        return {"status": "ok", "service": "daos-zeus-memory-action"}

    @app.get("/zeus-memory/openapi.yaml", include_in_schema=False)
    async def openapi_schema():
        return FileResponse(
            Path(__file__).parent / "openapi" / "zeus_memory_action.yaml",
            media_type="application/yaml",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/zeus-memory/privacy", include_in_schema=False)
    async def privacy_policy():
        return PlainTextResponse(
            "DAOS Zeus Shared Memory Action Privacy Policy\n\n"
            "This owner-only Action sends the one-time Bootstrap Key and requested memory "
            "operations to the self-hosted DAOS Memory Service. Memory writes are persisted "
            "in the DAOS Shared Memory database. The adapter does not persist Bootstrap Keys "
            "or internal access tokens and does not disclose them in responses. An opaque "
            "context handle is retained in process memory only until expiration or restart. "
            "No data is sold or shared with third parties other than transmission through "
            "OpenAI when the Owner invokes the configured GPT Action. Contact: DAOS Owner "
            "through the established private operating channel.\n",
            headers={"Cache-Control": "no-store"},
        )

    return app


def _load_single_token(path: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise RuntimeError("Action token file must be a private regular file")
        if info.st_uid != os.geteuid():
            raise RuntimeError("Action token file owner must match the service user")
        raw = os.read(fd, 513)
    finally:
        os.close(fd)
    if len(raw) > 512:
        raise RuntimeError("Action token is invalid")
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise RuntimeError("Action token is invalid") from None
    if len(token) < 32 or any(ch.isspace() for ch in token):
        raise RuntimeError("Action token is invalid")
    return token


def build_runtime_app() -> FastAPI:
    token_file = os.environ.get("DAOS_MEMORY_ACTION_TOKEN_FILE", "")
    upstream_url = os.environ.get("DAOS_MEMORY_UPSTREAM_URL", "http://172.18.0.1:8791")
    parsed = urllib.parse.urlsplit(upstream_url)
    if (
        not token_file
        or parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "172.18.0.1"}
        or parsed.port != 8791
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("Zeus Memory Action runtime configuration is invalid")
    return build_asgi_app(
        upstream=HttpMemoryUpstream(upstream_url),
        tokens=(_load_single_token(token_file),),
    )


def main() -> None:
    import uvicorn

    host = os.environ.get("DAOS_MEMORY_ACTION_HOST", "172.18.0.1")
    port = int(os.environ.get("DAOS_MEMORY_ACTION_PORT", "8793"))
    uvicorn.run(
        build_runtime_app(),
        host=host,
        port=port,
        workers=1,
        access_log=True,
        timeout_keep_alive=5,
        limit_concurrency=32,
    )


if __name__ == "__main__":
    main()
