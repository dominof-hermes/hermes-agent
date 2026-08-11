"""DAOS Memory service configuration.

Non-secret behavior is read from ``daos_memory`` in Hermes ``config.yaml``.
Only the PostgreSQL URL and owner token may be injected by environment
variables. The owner token also keys credential hashing and is never persisted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Settings:
    database_url: str
    owner_token: str
    credential_pepper: str
    service_url: str = "http://127.0.0.1:8791"
    request_timeout_seconds: float = 3.0
    query_timeout_seconds: float = 2.0
    bootstrap_ttl_seconds: int = 300
    access_ttl_seconds: int = 900
    max_bootstrap_uses: int = 1
    max_bootstrap_bytes: int = 24_000
    max_results: int = 50

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "Settings":
        path = Path(config_path or os.environ.get("HERMES_CONFIG_PATH", Path.home() / ".hermes" / "config.yaml"))
        raw: dict[str, Any] = {}
        if path.is_file():
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            raw = loaded.get("daos_memory") or {}
        database_url = os.environ.get("DAOS_MEMORY_DATABASE_URL", "")
        owner_token = os.environ.get("DAOS_MEMORY_OWNER_TOKEN", "")
        # The owner token also keys the at-rest HMAC. This keeps secret injection
        # to the two owner-approved values (database URL and owner token).
        pepper = owner_token
        if not database_url or not owner_token:
            raise RuntimeError("DAOS Memory secret configuration is incomplete")
        return cls(
            database_url=database_url,
            owner_token=owner_token,
            credential_pepper=pepper,
            service_url=str(raw.get("service_url", cls.service_url)),
            request_timeout_seconds=_bounded_float(raw.get("request_timeout_seconds", cls.request_timeout_seconds), 0.1, 30.0),
            query_timeout_seconds=_bounded_float(raw.get("query_timeout_seconds", cls.query_timeout_seconds), 0.1, 10.0),
            bootstrap_ttl_seconds=_bounded_int(raw.get("bootstrap_ttl_seconds", cls.bootstrap_ttl_seconds), 30, 3600),
            access_ttl_seconds=_bounded_int(raw.get("access_ttl_seconds", cls.access_ttl_seconds), 60, 86400),
            max_bootstrap_uses=_bounded_int(raw.get("max_bootstrap_uses", cls.max_bootstrap_uses), 1, 5),
            max_bootstrap_bytes=_bounded_int(raw.get("max_bootstrap_bytes", cls.max_bootstrap_bytes), 4096, 65536),
            max_results=_bounded_int(raw.get("max_results", cls.max_results), 1, 100),
        )


def _bounded_int(value: Any, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def _bounded_float(value: Any, low: float, high: float) -> float:
    return max(low, min(high, float(value)))
