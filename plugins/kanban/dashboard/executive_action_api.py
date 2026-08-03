"""Authenticated, read-only GPT Action gateway for Zeus executive status."""

from __future__ import annotations

import re
from typing import Optional, Sequence

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

from plugins.kanban.dashboard.executive_mcp import (
    AuthNotConfigured,
    ExecutiveTokenVerifier,
)
from plugins.kanban.dashboard.executive_read_model import ExecutiveReadModel, SafeReadError


STATUS_PATH = "/executive/status"
DEFAULT_BOARD_SLUG = "geumhwa-ai-dx"
MAX_PUBLIC_RESPONSE_BYTES = 100_000
_PAGE_LIMITS = (20, 10, 5, 1)
_BOARD_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SAFE_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


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


def _aggregate(model: ExecutiveReadModel, board_slug: str, limit: int) -> dict:
    board = dict(model.get_board_summary(board_slug))
    tasks = model.list_tasks(board_slug=board_slug, limit=limit)
    workers = dict(model.get_worker_status(board_slug=board_slug, limit=limit))
    usage = model.get_usage_and_output_summary(period="24h", board_slug=board_slug)
    owner_gate = dict(model.get_owner_confirm_queue(board_slug=board_slug, limit=limit))

    worker_count = workers.get("count")
    workers["truncation"] = {
        "truncated": "UNVERIFIED" if worker_count == limit else False,
        "next_cursor": "UNAVAILABLE",
        "reason": (
            "The canonical worker read model has no cursor; reaching the limit means "
            "additional workers cannot be ruled out."
            if worker_count == limit
            else "All matching workers fit within the bounded response."
        ),
    }
    owner_gate["truncation"] = {
        "truncated": "UNAVAILABLE",
        "next_cursor": "UNAVAILABLE",
    }

    blocker_items = board.get("blockers", [])
    blocker_total = board.get("blocked_task_count", "UNAVAILABLE")
    blocker_truncated = (
        isinstance(blocker_total, int) and blocker_total > len(blocker_items)
    )
    blockers = {
        "items": blocker_items,
        "returned": len(blocker_items),
        "total": blocker_total,
        "truncated": blocker_truncated,
        "next_cursor": "UNAVAILABLE",
        "data_marking": board.get("data_marking", "UNAVAILABLE"),
        "data_quality": board.get("data_quality", "UNAVAILABLE"),
    }
    active_workers = board.get("active_workers", [])
    active_worker_total = board.get("active_worker_count", "UNAVAILABLE")
    board["truncation"] = {
        "blockers": blocker_truncated,
        "active_workers": (
            isinstance(active_worker_total, int)
            and active_worker_total > len(active_workers)
        ),
        "next_cursor": "UNAVAILABLE",
    }
    return {
        "ok": True,
        "read_only": True,
        "board": board,
        "tasks": tasks,
        "workers": workers,
        "usage": usage,
        "blockers": blockers,
        "owner_gate": owner_gate,
        "metadata": {
            "board_slug": board_slug,
            "response_limit_bytes": MAX_PUBLIC_RESPONSE_BYTES,
            "item_limit": limit,
            "source": "ExecutiveReadModel",
        },
    }


def build_asgi_app(
    *,
    read_model: Optional[ExecutiveReadModel] = None,
    tokens: Optional[Sequence[str]] = None,
) -> FastAPI:
    """Build the single-route Action app; refuse an unconfigured boundary."""
    verifier = (
        ExecutiveTokenVerifier(tuple(tokens))
        if tokens is not None
        else ExecutiveTokenVerifier.from_env()
    )
    if not verifier.tokens:
        raise AuthNotConfigured("Executive Action bearer authentication is not configured")

    model = read_model or ExecutiveReadModel()
    app = FastAPI(
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
        redirect_slashes=False,
    )

    @app.get(STATUS_PATH, include_in_schema=False)
    async def get_executive_status(
        authorization: Optional[str] = Header(default=None),
        board_slug: str = DEFAULT_BOARD_SLUG,
    ):
        token = _authenticate_header(authorization)
        if token is None:
            return _error(401, "UNAUTHORIZED", "Bearer token required")
        if await verifier.verify_token(token) is None:
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

    app.state.executive_read_model = model
    return app
