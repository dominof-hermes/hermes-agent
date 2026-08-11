#!/usr/bin/env python3
"""Private, read-only host Gateway health bridge for the containerized Dashboard."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


DEFAULT_STATE_PATH = Path("/home/ubuntu/.hermes/gateway_state.json")
DEFAULT_PROC_ROOT = Path("/proc")


def _unavailable() -> tuple[int, dict[str, Any]]:
    return 503, {"status": "unavailable", "gateway_state": "stopped"}


def _process_fingerprint_matches(pid: int, expected_start_time: object, proc_root: Path) -> bool:
    try:
        expected = int(expected_start_time)
        current = int((proc_root / str(pid) / "stat").read_text(encoding="utf-8").split()[21])
    except (OSError, IndexError, TypeError, ValueError):
        return False
    return expected > 0 and current == expected


def _is_gateway_process(pid: int, proc_root: Path) -> bool:
    try:
        argv = (proc_root / str(pid) / "cmdline").read_bytes().split(b"\0")
    except (OSError, ValueError):
        return False
    wanted = [b"hermes_cli.main", b"gateway", b"run"]
    return any(argv[index : index + len(wanted)] == wanted for index in range(len(argv)))


def gateway_health(
    *,
    state_path: Path = DEFAULT_STATE_PATH,
    proc_root: Path = DEFAULT_PROC_ROOT,
) -> tuple[int, dict[str, Any]]:
    """Return a bounded health document after validating the live host PID."""
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
        pid = int(raw.get("pid"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return _unavailable()

    if (
        raw.get("gateway_state") != "running"
        or pid <= 1
        or not _process_fingerprint_matches(pid, raw.get("start_time"), proc_root)
        or not _is_gateway_process(pid, proc_root)
    ):
        return _unavailable()

    try:
        active_agents = max(0, min(1024, int(raw.get("active_agents", 0))))
    except (TypeError, ValueError):
        active_agents = 0

    platforms: dict[str, dict[str, str]] = {}
    for name, value in (raw.get("platforms") or {}).items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        state = value.get("state")
        if isinstance(state, str):
            platforms[name[:64]] = {"state": state[:64]}

    updated_at = raw.get("updated_at")
    body: dict[str, Any] = {
        "status": "ok",
        "gateway_state": "running",
        "pid": pid,
        "active_agents": active_agents,
        "platforms": platforms,
        "updated_at": updated_at if isinstance(updated_at, str) else None,
    }
    return 200, body


class HealthHandler(BaseHTTPRequestHandler):
    server_version = "DAOSGatewayHealth/0.1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] not in {"/health", "/health/detailed"}:
            self._json(404, {"status": "not_found"})
            return
        status, body = gateway_health(
            state_path=self.server.state_path,  # type: ignore[attr-defined]
            proc_root=self.server.proc_root,  # type: ignore[attr-defined]
        )
        if self.path.split("?", 1)[0] == "/health" and status == 200:
            body = {"status": "ok"}
        self._json(status, body)

    def _json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="172.18.0.1")
    parser.add_argument("--port", type=int, default=8792)
    parser.add_argument("--state-path", type=Path, default=DEFAULT_STATE_PATH)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), HealthHandler)
    server.state_path = args.state_path  # type: ignore[attr-defined]
    server.proc_root = DEFAULT_PROC_ROOT  # type: ignore[attr-defined]
    server.serve_forever()


if __name__ == "__main__":
    main()
