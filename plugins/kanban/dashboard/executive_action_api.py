"""Authenticated, read-only GPT Action gateway for Zeus executive status."""

from __future__ import annotations

import re
from typing import Optional, Sequence

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

from plugins.kanban.dashboard.executive_mcp import (
    AuthNotConfigured,
    ExecutiveTokenVerifier,
)
from plugins.kanban.dashboard.executive_read_model import ExecutiveReadModel, SafeReadError


STATUS_PATH = "/executive/status"
BOARDS_PATH = "/executive/boards"
TASKS_PATH = "/executive/tasks"
DEFAULT_BOARD_SLUG = "geumhwa-ai-dx"
MAX_PUBLIC_RESPONSE_BYTES = 100_000
_PAGE_LIMITS = (20, 10, 5, 1)
_BOARD_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SAFE_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

_TASK_FIELDS = (
    "public_task_id", "title", "board", "lane", "priority", "workflow_status",
    "execution_status", "assignment_status", "assignee", "active_worker", "reviewer",
    "started_at", "last_heartbeat_at", "last_product_output_at", "deadline", "blocked",
    "blocker_summary", "owner_confirm_status", "next_action", "updated_at",
    "canonical_receipt", "external_process_detected", "heartbeat_age_seconds",
    "process_verified", "runtime_deadline_at", "product_maturity",
    "product_output_count", "source_freshness", "data_quality", "consistency_status",
    "verification_note",
)
_TASK_PAGE_FIELDS = (
    "tool", "board", "returned", "limit", "next_cursor", "has_more",
    "scan_truncated", "unsupported_filters",
)
_WORKER_FIELDS = (
    "worker_id", "role", "provider", "model", "board", "lane", "public_task_id",
    "task_title", "execution_status", "canonical_receipt", "external_process_detected",
    "process_verified", "started_at", "ended_at", "last_heartbeat_at",
    "heartbeat_age_seconds", "runtime_deadline_at", "last_product_output_at",
    "exit_state", "measured_at", "data_quality", "source_freshness",
)


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "ok": False,
            "error": {"code": code, "message": message},
            "read_only": True,
        },
    )


def _authenticate_header(value: Optional[str]) -> Optional[str]:
    if not value or not value.startswith("Bearer "):
        return None
    token = value[7:]
    if not token or token != token.strip() or any(ch.isspace() for ch in token):
        return None
    return token


def _select(source: dict, fields: Sequence[str]) -> dict:
    return {field: source[field] for field in fields if field in source}


def _freshness(source: dict) -> dict:
    return _select(
        source,
        ("source_freshness", "data_quality", "consistency_status", "last_activity_at"),
    )


def _read_metadata(source: dict, *, coverage: dict, boundary: str) -> dict:
    return {
        "freshness": _freshness(source),
        "coverage": coverage,
        "source_gaps": source.get("source_gaps", []),
        "measured_at": source.get("measured_at", "UNAVAILABLE"),
        "snapshot_boundary": {
            "kind": boundary,
            "last_activity_at": source.get("last_activity_at", "UNAVAILABLE"),
        },
    }


def _bounded_response(payload: dict) -> JSONResponse:
    response = JSONResponse(payload)
    if len(response.body) <= MAX_PUBLIC_RESPONSE_BYTES:
        return response
    return _error(503, "RESPONSE_TOO_LARGE", "Executive read is temporarily unavailable")


def _page_payload(result: dict, *, cursor: Optional[str], requested_limit: int) -> dict:
    tasks = [_select(item, _TASK_FIELDS) for item in result.get("tasks", [])]
    projected = {**_select(result, _TASK_PAGE_FIELDS), "tasks": tasks}
    actual_limit = result.get("limit", requested_limit)
    return {
        **projected,
        **_read_metadata(
            result,
            coverage={
                "tasks": "COMPLETE"
                if cursor is None and not result.get("has_more") else "PAGED"
            },
            boundary="TASK_KEYSET_AT_READ",
        ),
        "degraded_limit": actual_limit,
        "truncated": actual_limit < requested_limit,
        "read_only": True,
    }


def _aggregate(model: ExecutiveReadModel, board_slug: str, limit: int) -> dict:
    board = dict(model.get_board_summary(board_slug))
    tasks = model.list_tasks(board_slug=board_slug, limit=limit)
    workers = dict(model.get_worker_status(board_slug=board_slug, limit=limit))
    usage = model.get_usage_and_output_summary(period="24h", board_slug=board_slug)
    owner_gate = dict(model.get_owner_confirm_queue(board_slug=board_slug, limit=limit))

    worker_count = workers.get("count")
    worker_truncation = {
        "truncated": "UNVERIFIED" if worker_count == limit else False,
        "next_cursor": "UNAVAILABLE",
        "reason": (
            "The canonical worker read model has no cursor; reaching the limit means "
            "additional workers cannot be ruled out."
            if worker_count == limit
            else "All matching workers fit within the bounded response."
        ),
    }
    owner_truncation = {
        "truncated": "UNAVAILABLE",
        "next_cursor": "UNAVAILABLE",
    }

    blocker_items = board.get("blockers", [])
    blocker_total = board.get("blocked_task_count", "UNAVAILABLE")
    blocker_truncated = (
        isinstance(blocker_total, int) and blocker_total > len(blocker_items)
    )
    blocked = {
        "items": blocker_items,
        "returned": len(blocker_items),
        "count": blocker_total,
        "truncated": blocker_truncated,
        "next_cursor": "UNAVAILABLE",
        "data_quality": board.get("data_quality", "UNAVAILABLE"),
    }
    return {
        "project": _select(board, (
            "board_id", "board_slug", "board_name", "project_status", "overall_status",
            "task_count", "active_task_count", "blocked_task_count", "stalled_task_count",
            "active_worker_count", "workflow_counts", "unmapped_workflow_statuses",
            "execution_counts", "last_activity_at",
        )),
        "lane": {
            "product_lane": board.get("product_lane", "UNAVAILABLE"),
            "product_lanes": board.get("product_lanes", []),
            **_freshness(board),
        },
        "task": {
            "board": tasks.get("board", board_slug),
            "items": [_select(item, _TASK_FIELDS) for item in tasks.get("tasks", [])],
            **_select(tasks, (
                "returned", "limit", "next_cursor", "has_more", "scan_truncated",
                "unsupported_filters",
            )),
        },
        "worker": {
            "board": workers.get("board", board_slug),
            "items": [_select(item, _WORKER_FIELDS) for item in workers.get("workers", [])],
            **_select(workers, ("count", "limit", "unsupported_filters")),
            "truncation": worker_truncation,
        },
        "usage": _select(
            usage, ("period", "period_seconds", "boards", "usage", "output", "usage_note")
        ),
        "blocked": blocked,
        "owner_confirm": {
            **_select(owner_gate, (
                "board", "entries", "count", "limit", "owner_confirm_status",
                "queue_basis", "required_fields",
            )),
            "truncation": owner_truncation,
        },
        "freshness": {
            "project": _freshness(board),
            "task": _freshness(tasks),
            "worker": _freshness(workers),
            "usage": _freshness(usage),
            "blocked": _freshness(board),
            "owner_confirm": _freshness(owner_gate),
        },
        "measured_at": board["measured_at"],
    }


def build_asgi_app(
    *,
    read_model: Optional[ExecutiveReadModel] = None,
    tokens: Optional[Sequence[str]] = None,
) -> FastAPI:
    """Build the exact authenticated GET-only Action surface."""
    verifier = (
        ExecutiveTokenVerifier(tuple(tokens))
        if tokens is not None
        else ExecutiveTokenVerifier.from_env()
    )
    if len(verifier.tokens) != 1:
        raise AuthNotConfigured(
            "Executive Action bearer authentication requires exactly one server token"
        )

    model = read_model or ExecutiveReadModel()
    app = FastAPI(
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
        redirect_slashes=False,
    )

    @app.exception_handler(405)
    async def method_not_allowed(_request: Request, _exc: HTTPException):
        return _error(405, "METHOD_NOT_ALLOWED", "Method is not allowed")

    async def authorized(authorization: Optional[str]) -> bool:
        token = _authenticate_header(authorization)
        return token is not None and await verifier.verify_token(token) is not None

    def read_error(exc: Exception) -> JSONResponse:
        if isinstance(exc, SafeReadError):
            code = exc.code if _SAFE_ERROR_CODE.fullmatch(exc.code or "") else "READ_FAILED"
            return _error(400, code, "Executive read is unavailable for this request")
        return _error(503, "SERVICE_UNAVAILABLE", "Executive read is temporarily unavailable")

    def parse_limit(value: str) -> int:
        if not isinstance(value, str) or not value.isascii() or not value.isdigit():
            raise SafeReadError("INVALID_LIMIT", "limit is invalid")
        limit = int(value)
        if not 1 <= limit <= 20:
            raise SafeReadError("INVALID_LIMIT", "limit is invalid")
        return limit

    @app.get(STATUS_PATH, include_in_schema=False)
    async def get_executive_status(
        authorization: Optional[str] = Header(default=None),
        board_slug: str = DEFAULT_BOARD_SLUG,
    ):
        if not await authorized(authorization):
            return _error(401, "UNAUTHORIZED", "Bearer token required")
        if not isinstance(board_slug, str) or not _BOARD_SLUG.fullmatch(board_slug):
            return _error(400, "INVALID_BOARD", "Board identifier is invalid")

        try:
            for limit in _PAGE_LIMITS:
                response = JSONResponse(_aggregate(model, board_slug, limit))
                if len(response.body) < MAX_PUBLIC_RESPONSE_BYTES:
                    return response
            return _error(
                503,
                "RESPONSE_TOO_LARGE",
                "Executive status is temporarily unavailable",
            )
        except SafeReadError as exc:
            code = exc.code if _SAFE_ERROR_CODE.fullmatch(exc.code or "") else "READ_FAILED"
            return _error(400, code, "Executive status is unavailable for this request")
        except Exception:
            return _error(
                503,
                "SERVICE_UNAVAILABLE",
                "Executive status is temporarily unavailable",
            )

    @app.get(BOARDS_PATH, include_in_schema=False)
    async def get_executive_boards(
        authorization: Optional[str] = Header(default=None),
        include_archived: str = "false",
    ):
        if not await authorized(authorization):
            return _error(401, "UNAUTHORIZED", "Bearer token required")
        if include_archived not in {"true", "false"}:
            return _error(400, "INVALID_ARGUMENTS", "include_archived is invalid")
        try:
            result = model.list_boards(include_archived=include_archived == "true")
            payload = {
                "boards": result.get("boards", []),
                "board_count": result.get("board_count", 0),
                **_read_metadata(
                    result,
                    coverage={"boards": "COMPLETE"},
                    boundary="BOARD_CATALOG_AT_READ",
                ),
                "read_only": True,
            }
            return _bounded_response(payload)
        except Exception as exc:
            return read_error(exc)

    @app.get(TASKS_PATH, include_in_schema=False)
    async def get_executive_tasks(
        authorization: Optional[str] = Header(default=None),
        board_slug: Optional[str] = None,
        limit: str = "10",
        cursor: Optional[str] = None,
    ):
        if not await authorized(authorization):
            return _error(401, "UNAUTHORIZED", "Bearer token required")
        if board_slug is None:
            return _error(400, "INVALID_BOARD", "board_slug is required")
        try:
            requested_limit = parse_limit(limit)
            for page_limit in range(requested_limit, 0, -1):
                result = model.list_tasks(
                    board_slug=board_slug, limit=page_limit, cursor=cursor,
                )
                response = JSONResponse(_page_payload(
                    result, cursor=cursor, requested_limit=requested_limit,
                ))
                if len(response.body) <= MAX_PUBLIC_RESPONSE_BYTES:
                    return response
            return _error(503, "RESPONSE_TOO_LARGE", "Executive read is temporarily unavailable")
        except Exception as exc:
            return read_error(exc)

    @app.get(f"{TASKS_PATH}/{{public_task_id}}", include_in_schema=False)
    async def get_executive_task(
        public_task_id: str,
        authorization: Optional[str] = Header(default=None),
        board_slug: Optional[str] = None,
    ):
        if not await authorized(authorization):
            return _error(401, "UNAUTHORIZED", "Bearer token required")
        if board_slug is None:
            return _error(400, "INVALID_BOARD", "board_slug is required")
        try:
            return _bounded_response(model.get_task_journal(public_task_id, board_slug))
        except Exception as exc:
            return read_error(exc)

    @app.get(f"{TASKS_PATH}/{{public_task_id}}/comments", include_in_schema=False)
    async def get_executive_task_comments(
        public_task_id: str,
        authorization: Optional[str] = Header(default=None),
        board_slug: Optional[str] = None,
        limit: str = "10",
        cursor: Optional[str] = None,
    ):
        if not await authorized(authorization):
            return _error(401, "UNAUTHORIZED", "Bearer token required")
        if board_slug is None:
            return _error(400, "INVALID_BOARD", "board_slug is required")
        try:
            requested_limit = parse_limit(limit)
            for page_limit in range(requested_limit, 0, -1):
                payload = model.list_task_comments(
                    public_task_id, board_slug, limit=page_limit, cursor=cursor,
                )
                payload["degraded_limit"] = page_limit
                payload["truncated"] = page_limit < requested_limit
                response = JSONResponse(payload)
                if len(response.body) <= MAX_PUBLIC_RESPONSE_BYTES:
                    return response
            return _error(503, "RESPONSE_TOO_LARGE", "Executive read is temporarily unavailable")
        except Exception as exc:
            return read_error(exc)

    app.state.executive_read_model = model
    return app
