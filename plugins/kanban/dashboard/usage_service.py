"""Read-only Usage P0 service for the DAOS Kanban dashboard.

Provider values come from the official local CodexBar CLI.  PASS/STOP
comes from usage-coach's own ``guard status`` preview against the exact same
raw snapshot, so this layer does not duplicate policy.  Only the five
owner-facing fields are returned; account identity and coaching prose never
cross the API boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

PROVIDERS = ("claude", "codex")
WINDOW_LABELS = {300: "5h", 10080: "7d", 1440: "daily"}
CODEXBAR_VERSION = "0.46.0"
CODEXBAR_SHA256 = {
    ("linux", "aarch64"): "8834491117b887e9ac53da88f1d5b4bf2f14d2ff30dfaab1639075659035e4f3",
    ("linux", "arm64"): "8834491117b887e9ac53da88f1d5b4bf2f14d2ff30dfaab1639075659035e4f3",
}
USAGE_COACH_COMMIT = "bcfe3beaea457c247a624e73481444e4f2e287ec"
USAGE_COACH_SHA256 = "1e1cfd400d8493b2f1ea888e9a3ffa51ebe463022fa53e0d2b919b3bb8cf9298"


def _unavailable(provider: str) -> dict[str, Any]:
    return {
        "provider": provider.title(),
        "current_usage": "UNAVAILABLE",
        "reset_at": "UNAVAILABLE",
        "coach": "UNAVAILABLE",
        "last_updated": "UNAVAILABLE",
    }


def _run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        check=False,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_executable(name: str, expected_sha256: str) -> str:
    candidate = shutil.which(name)
    if not candidate:
        raise RuntimeError(f"{name} unavailable")
    resolved = Path(candidate).resolve(strict=True)
    if not resolved.is_file() or _sha256(resolved) != expected_sha256:
        raise RuntimeError(f"{name} provenance mismatch")
    return str(resolved)


def _resolve_verified_tools() -> tuple[str, str]:
    platform_key = (platform.system().lower(), platform.machine().lower())
    expected_codexbar = CODEXBAR_SHA256.get(platform_key)
    if not expected_codexbar:
        raise RuntimeError("official CodexBar build is not pinned for this platform")
    codexbar = _verified_executable("codexbar", expected_codexbar)
    version = _run([codexbar, "--version"], timeout=10)
    if version.returncode != 0 or version.stdout.strip() != f"CodexBar {CODEXBAR_VERSION}":
        raise RuntimeError("CodexBar version mismatch")
    coach = _verified_executable("coach", USAGE_COACH_SHA256)
    return codexbar, coach


def _collect_raw(
    provider: str,
    *,
    timeout: int,
    codexbar: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cmd = [
        codexbar,
        "usage",
        "--provider",
        provider,
        "--format",
        "json",
        "--pretty",
    ]
    if provider == "codex":
        cmd.extend(("--source", "cli"))
    result = _run(cmd, timeout=timeout + 5)
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("provider usage unavailable")
    data = json.loads(result.stdout)
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        raise RuntimeError("provider payload is malformed")
    usage = data[0].get("usage")
    if not isinstance(usage, dict):
        raise RuntimeError("provider usage is missing")
    return data, usage


def _windows(usage: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    current: list[dict[str, Any]] = []
    resets: list[dict[str, Any]] = []
    has_weekly = False
    for key in ("primary", "secondary", "tertiary"):
        window = usage.get(key)
        if not isinstance(window, dict):
            continue
        duration = window.get("windowMinutes")
        used = window.get("usedPercent")
        if not isinstance(duration, int) or not isinstance(used, (int, float)):
            continue
        label = WINDOW_LABELS.get(duration, f"{duration}m")
        current.append({"window": label, "used_percent": float(used)})
        reset = window.get("resetsAt")
        if isinstance(reset, str) and reset:
            resets.append({"window": label, "at": reset})
        if duration == 10080:
            has_weekly = True
    if not current:
        raise RuntimeError("no valid provider windows")
    return current, resets, has_weekly


def _coach_preview(
    provider: str,
    raw: list[dict[str, Any]],
    *,
    timeout: int,
    has_weekly: bool,
    coach: str,
) -> str:
    # A missing weekly window is not PASS.  usage-coach's fail-open contract is
    # correct for task execution, but the operator display must say UNAVAILABLE
    # rather than misrepresent an unmeasured provider as approved.
    if not has_weekly:
        return "UNAVAILABLE"
    with tempfile.TemporaryDirectory(prefix="daos-usage-") as directory:
        snapshot = Path(directory) / f"{provider}.json"
        snapshot.write_text(json.dumps(raw), encoding="utf-8")
        snapshot.chmod(0o600)
        result = _run(
            [coach, "guard", "status", "--file", f"{snapshot}:{provider}"],
            timeout=timeout,
        )
    if result.returncode != 0:
        return "UNAVAILABLE"
    output = result.stdout
    if "지금이면 정지" in output:
        return "STOP"
    if "지금이면 통과" in output:
        return "PASS"
    return "UNAVAILABLE"


def _provider_row(
    provider: str,
    *,
    timeout: int,
    codexbar: str,
    coach: str,
) -> dict[str, Any]:
    try:
        raw, usage = _collect_raw(provider, timeout=timeout, codexbar=codexbar)
        current, resets, has_weekly = _windows(usage)
        updated = usage.get("updatedAt")
        if not isinstance(updated, str) or not updated:
            updated = "UNAVAILABLE"
        return {
            "provider": provider.title(),
            "current_usage": current,
            "reset_at": resets if resets else "UNAVAILABLE",
            "coach": _coach_preview(
                provider,
                raw,
                timeout=timeout,
                has_weekly=has_weekly,
                coach=coach,
            ),
            "last_updated": updated,
        }
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return _unavailable(provider)


def collect_usage_dashboard(*, timeout: int = 45) -> dict[str, Any]:
    """Return the P0 public shape; failures remain data, never HTTP errors."""
    try:
        codexbar, coach = _resolve_verified_tools()
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        rows = [_unavailable(provider) for provider in PROVIDERS]
    else:
        rows = [
            _provider_row(
                provider,
                timeout=timeout,
                codexbar=codexbar,
                coach=coach,
            )
            for provider in PROVIDERS
        ]
    return {
        "available": any(row["current_usage"] != "UNAVAILABLE" for row in rows),
        "providers": rows,
    }
