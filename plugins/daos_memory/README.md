# DAOS Shared Memory / Context Service v0.1

Work ID: `DAOS-MEM-260811-01`

An edge plugin with an isolated FastAPI process and PostgreSQL schema. It does
not add a Hermes core/model tool and never runs inside the Hermes Gateway.

## Components

- `service/main.py`: uvicorn entrypoint; fixed `/v1` API, bearer-header auth.
- `service/store.py`: asyncpg pool with command/query timeouts and hard limits.
- `migrations/001_daos_memory_v01.sql`: `daos_memory` schema and four core tables.
- `dashboard/`: dashboard-authenticated proxy and top-level `/memory` UI.
- `systemd/daos-memory.service`: bounded/hardened service template.
- `systemd/gateway_health.py` + `daos-gateway-health.service`: private,
  bridge-scoped host Gateway liveness bridge for a containerized Dashboard. It
  validates the host Gateway PID/command and exposes only bounded `/health` and
  `/health/detailed` data; it does not proxy Gateway sessions or credentials.

## Configure

The hardened system service cannot read home directories (`ProtectHome=true`).
Put its behavioral settings in `/etc/daos-memory/config.yaml`; the unit sets
`HERMES_CONFIG_PATH` to that file:

```yaml
daos_memory:
  service_url: http://127.0.0.1:8791
  request_timeout_seconds: 3
  query_timeout_seconds: 2
  bootstrap_ttl_seconds: 300
  access_ttl_seconds: 900
  max_bootstrap_uses: 1
  max_bootstrap_bytes: 24000
  max_results: 50
```

The dashboard process is separate and continues to read `daos_memory.service_url`
and `daos_memory.request_timeout_seconds` from the dashboard user's normal
`~/.hermes/config.yaml`. Keep those two routing values aligned with the service
configuration.

Only secrets go in the systemd `EnvironmentFile` (mode `0600`):

```sh
DAOS_MEMORY_DATABASE_URL=postgresql://USER:PASSWORD@HOST/DB
DAOS_MEMORY_OWNER_TOKEN=<random-owner-token>
```

The dashboard process needs `DAOS_MEMORY_OWNER_TOKEN` via its own secret
injection. The proxy never sends it to the browser. Do not place any credential
in a URL, command argument, `config.yaml`, or logs.

## Install/run (operator steps; not applied by this change)

1. Create a dedicated virtualenv and install `requirements.txt`.
2. Review and apply `migrations/001_daos_memory_v01.sql` with a migration role.
3. Install the reviewed unit template, environment file, and service user.
4. Start `daos-memory.service`, then verify `GET /health` returns database `ok`.
5. Enable/reload the bundled dashboard plugin and open `/memory`.

The checked-in systemd paths are templates; adapt `/opt/...`, user/group, and
secret-file paths to the host. Bind to loopback behind the existing TLS reverse
proxy. Do not expose uvicorn directly.

## API contract

Agent endpoints are fixed:

- `POST /v1/bootstrap` — one-use/short-lived bootstrap bearer key; returns a
  bounded Current-first payload and short-lived scoped access token.
- `GET /v1/current`
- `GET /v1/history` — requires a product/topic/query filter.
- `POST /v1/events`
- `POST /v1/events/{id}/supersede`

Owner endpoints under `/v1/admin` rotate/revoke access and feed the authenticated
dashboard proxy. Rotation is the only response that contains a plaintext
bootstrap key. Registry persistence contains hashes only. Revocation clears
both bootstrap and access credential state. There is no delete endpoint;
superseded events remain searchable.

Event metadata is accepted only as a JSON object whose compact UTF-8 encoding
is at most 4096 bytes.

## Operational checks

```sh
systemctl status daos-memory.service
curl --fail --silent http://127.0.0.1:8791/health
journalctl -u daos-memory.service --since today
```

Expected failure behavior: dashboard proxy returns `503 memory service
unavailable`; agents report `UNAVAILABLE/BLOCKED`. Never bypass the proxy or
fall back to stale/unverified data. Rotate/revoke from **Memory → Agent Access**;
the new key is displayed once and copy state is cleared when leaving the view.

## Tests

```sh
uv run --with pytest --with asyncpg python -m pytest plugins/daos_memory/tests -q
```

No production deploy or database migration is performed by this repository
change.
