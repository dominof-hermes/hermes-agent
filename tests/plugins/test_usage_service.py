from __future__ import annotations

import json
import os
from pathlib import Path

from plugins.kanban.dashboard import usage_service


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def test_collect_usage_dashboard_exposes_exactly_five_owner_fields(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(
        bin_dir / "codexbar",
        """#!/usr/bin/env python3
import json, sys
provider = sys.argv[sys.argv.index('--provider') + 1]
if provider == 'claude':
    usage = {
      'primary': {'usedPercent': 17, 'windowMinutes': 300, 'resetsAt': '2026-08-01T22:20:00Z'},
      'secondary': {'usedPercent': 6, 'windowMinutes': 10080, 'resetsAt': '2026-08-07T08:00:00Z'},
      'updatedAt': '2026-08-01T22:01:38Z',
      'accountEmail': 'must-not-leak@example.com'
    }
else:
    usage = {
      'primary': {'usedPercent': 12, 'windowMinutes': 10080, 'resetsAt': '2026-08-08T03:37:18Z'},
      'secondary': None,
      'updatedAt': '2026-08-01T22:01:39Z'
    }
print(json.dumps([{'provider': provider, 'usage': usage}]))
""",
    )
    _write_executable(
        bin_dir / "coach",
        """#!/usr/bin/env python3
print('요금가드: off')
print('  지금이면 통과')
""",
    )
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setattr(
        usage_service,
        "_resolve_verified_tools",
        lambda: (str(bin_dir / "codexbar"), str(bin_dir / "coach")),
    )

    result = usage_service.collect_usage_dashboard(timeout=5)

    assert result["available"] is True
    assert [row["provider"] for row in result["providers"]] == ["Claude", "Codex"]
    expected_keys = {"provider", "current_usage", "reset_at", "coach", "last_updated"}
    assert all(set(row) == expected_keys for row in result["providers"])
    assert result["providers"][0]["current_usage"] == [
        {"window": "5h", "used_percent": 17.0},
        {"window": "7d", "used_percent": 6.0},
    ]
    assert result["providers"][0]["reset_at"] == [
        {"window": "5h", "at": "2026-08-01T22:20:00Z"},
        {"window": "7d", "at": "2026-08-07T08:00:00Z"},
    ]
    assert result["providers"][0]["coach"] == "PASS"
    assert result["providers"][1]["coach"] == "PASS"
    serialized = json.dumps(result)
    assert "must-not-leak" not in serialized
    assert "email" not in serialized.lower()
    assert "plan" not in serialized.lower()


def test_collect_usage_dashboard_fails_open_as_unavailable(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(
        bin_dir / "codexbar",
        """#!/usr/bin/env python3
import sys
print('provider unavailable', file=sys.stderr)
raise SystemExit(1)
""",
    )
    _write_executable(
        bin_dir / "coach",
        """#!/usr/bin/env python3
print('  지금이면 통과')
""",
    )
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setattr(
        usage_service,
        "_resolve_verified_tools",
        lambda: (str(bin_dir / "codexbar"), str(bin_dir / "coach")),
    )

    result = usage_service.collect_usage_dashboard(timeout=5)

    assert result["available"] is False
    assert result["providers"] == [
        {
            "provider": "Claude",
            "current_usage": "UNAVAILABLE",
            "reset_at": "UNAVAILABLE",
            "coach": "UNAVAILABLE",
            "last_updated": "UNAVAILABLE",
        },
        {
            "provider": "Codex",
            "current_usage": "UNAVAILABLE",
            "reset_at": "UNAVAILABLE",
            "coach": "UNAVAILABLE",
            "last_updated": "UNAVAILABLE",
        },
    ]


def test_collect_usage_dashboard_rejects_unpinned_binary(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(
        bin_dir / "codexbar",
        """#!/usr/bin/env python3
print('CodexBar 0.46.0')
""",
    )
    _write_executable(
        bin_dir / "coach",
        """#!/usr/bin/env python3
print('지금이면 통과')
""",
    )
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setattr(usage_service.platform, "system", lambda: "Linux")
    monkeypatch.setattr(usage_service.platform, "machine", lambda: "aarch64")

    result = usage_service.collect_usage_dashboard(timeout=5)

    assert result["available"] is False
    assert all(row["coach"] == "UNAVAILABLE" for row in result["providers"])


def test_collect_usage_dashboard_uses_fresh_public_snapshot(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    snapshot = home / "usage" / "usage-p0.json"
    snapshot.parent.mkdir(parents=True)
    expected = {
        "available": True,
        "providers": [
            {
                "provider": "Claude",
                "current_usage": [{"window": "7d", "used_percent": 6.0}],
                "reset_at": [{"window": "7d", "at": "2026-08-07T07:59:00Z"}],
                "coach": "PASS",
                "last_updated": "2026-08-02T02:10:18Z",
            },
            {
                "provider": "Codex",
                "current_usage": [{"window": "7d", "used_percent": 13.0}],
                "reset_at": [{"window": "7d", "at": "2026-08-08T03:37:18Z"}],
                "coach": "PASS",
                "last_updated": "2026-08-02T02:10:20Z",
            },
        ],
    }
    snapshot.write_text(json.dumps(expected), encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(
        usage_service,
        "_resolve_verified_tools",
        lambda: (_ for _ in ()).throw(RuntimeError("container has no provider tools")),
    )

    assert usage_service.collect_usage_dashboard(timeout=5) == expected


def test_collect_usage_dashboard_rejects_stale_or_expanded_snapshot(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    snapshot = home / "usage" / "usage-p0.json"
    snapshot.parent.mkdir(parents=True)
    payload = {
        "available": True,
        "providers": [
            {
                "provider": "Claude",
                "current_usage": "UNAVAILABLE",
                "reset_at": "UNAVAILABLE",
                "coach": "UNAVAILABLE",
                "last_updated": "UNAVAILABLE",
                "accountEmail": "must-not-cross-boundary@example.com",
            }
        ],
    }
    snapshot.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(
        usage_service,
        "_resolve_verified_tools",
        lambda: (_ for _ in ()).throw(RuntimeError("container has no provider tools")),
    )

    expanded = usage_service.collect_usage_dashboard(timeout=5)
    assert expanded["available"] is False
    assert "accountEmail" not in json.dumps(expanded)

    huge = {
        "available": True,
        "providers": [
            {
                "provider": provider,
                "current_usage": [{"window": "7d", "used_percent": 10**400}],
                "reset_at": "UNAVAILABLE",
                "coach": "UNAVAILABLE",
                "last_updated": "UNAVAILABLE",
            }
            for provider in ("Claude", "Codex")
        ],
    }
    snapshot.write_text(json.dumps(huge), encoding="utf-8")
    malformed_number = usage_service.collect_usage_dashboard(timeout=5)
    assert malformed_number["available"] is False

    safe = {
        "available": False,
        "providers": [
            {
                "provider": "Claude",
                "current_usage": "UNAVAILABLE",
                "reset_at": "UNAVAILABLE",
                "coach": "UNAVAILABLE",
                "last_updated": "UNAVAILABLE",
            },
            {
                "provider": "Codex",
                "current_usage": "UNAVAILABLE",
                "reset_at": "UNAVAILABLE",
                "coach": "UNAVAILABLE",
                "last_updated": "UNAVAILABLE",
            },
        ],
    }
    snapshot.write_text(json.dumps(safe), encoding="utf-8")
    old = snapshot.stat().st_mtime - usage_service.SNAPSHOT_MAX_AGE_SECONDS - 1
    os.utime(snapshot, (old, old))

    stale = usage_service.collect_usage_dashboard(timeout=5)
    assert stale["available"] is False
    assert all(row["last_updated"] == "UNAVAILABLE" for row in stale["providers"])
