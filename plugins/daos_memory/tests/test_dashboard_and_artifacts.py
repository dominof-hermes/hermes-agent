from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tomllib

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugins.daos_memory.dashboard.plugin_api import create_router


ROOT = Path(__file__).resolve().parents[1]


def proxy_client(handler):
    app = FastAPI()
    app.include_router(create_router(
        service_url="http://memory.internal",
        owner_token="owner-secret",
        timeout_seconds=1.0,
        transport=httpx.MockTransport(handler),
    ))
    return TestClient(app)


def test_proxy_keeps_owner_token_server_side_and_rotation_secret_is_one_response():
    seen = []

    def handler(request):
        seen.append(request)
        assert request.headers["authorization"] == "Bearer owner-secret"
        if request.url.path.endswith("/rotate"):
            return httpx.Response(200, json={"agent_id": "zeus", "bootstrap_key": "one-time-secret", "expires_at": "soon", "max_uses": 1})
        return httpx.Response(200, json={"items": [{"agent_id": "zeus", "status": "ACTIVE", "last_access_at": None}]})

    client = proxy_client(handler)
    listed = client.get("/agents")
    assert listed.status_code == 200
    assert "owner-secret" not in listed.text
    assert "bootstrap_key" not in listed.text
    rotated = client.post("/agents/zeus/rotate")
    assert rotated.json()["bootstrap_key"] == "one-time-secret"
    assert "owner-secret" not in rotated.text
    assert all("owner-secret" not in str(request.url) for request in seen)


def test_proxy_fails_closed_when_service_is_unavailable():
    def handler(request):
        raise httpx.ConnectError("offline", request=request)

    client = proxy_client(handler)
    response = client.get("/memory", params={"view": "current"})
    assert response.status_code == 503
    assert response.json()["detail"] == "memory service unavailable"
    assert "offline" not in response.text


def test_memory_proxy_omits_unset_filters_and_preserves_explicit_values():
    seen_queries = []

    def handler(request):
        seen_queries.append(dict(request.url.params))
        return httpx.Response(200, json={"items": [], "count": 0})

    client = proxy_client(handler)
    default_response = client.get("/memory", params={"view": "current", "limit": 20})
    filtered_response = client.get(
        "/memory",
        params={"view": "history", "product": "hermes", "topic": "release", "limit": 10},
    )

    assert default_response.status_code == 200
    assert filtered_response.status_code == 200
    assert seen_queries == [
        {"view": "current", "limit": "20"},
        {"view": "history", "product": "hermes", "topic": "release", "limit": "10"},
    ]


def test_dashboard_event_detail_proxy_is_owner_authenticated_and_read_only():
    event_id = "11111111-1111-4111-8111-111111111111"
    seen = []

    def handler(request):
        seen.append(request)
        assert request.method == "GET"
        assert request.url.path == f"/v1/admin/events/{event_id}"
        assert request.headers["authorization"] == "Bearer owner-secret"
        return httpx.Response(200, json={"id": event_id, "title": "Direct event", "content": "Full content"})

    response = proxy_client(handler).get(f"/events/{event_id}")

    assert response.status_code == 200
    assert response.json()["id"] == event_id
    assert len(seen) == 1


def test_dashboard_knowledge_and_source_proxies_are_owner_authenticated_gets():
    event_id = "11111111-1111-4111-8111-111111111111"
    source_id = "22222222-2222-4222-8222-222222222222"
    seen = []

    def handler(request):
        seen.append(request)
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer owner-secret"
        if request.url.path.endswith("/knowledge"):
            return httpx.Response(200, json={"event_id": event_id, "evidence_status": "grounded", "sources": [], "related_events": [], "relations": []})
        return httpx.Response(200, json={"id": source_id, "content": "raw"})

    client = proxy_client(handler)
    assert client.get(f"/events/{event_id}/knowledge").status_code == 200
    assert client.get(f"/sources/{source_id}").status_code == 200
    assert [request.url.path for request in seen] == [
        f"/v1/admin/events/{event_id}/knowledge", f"/v1/admin/sources/{source_id}"
    ]


def test_dashboard_artifacts_define_top_level_memory_views():
    manifest = json.loads((ROOT / "dashboard" / "manifest.json").read_text())
    assert manifest["tab"]["path"] == "/memory"
    script = (ROOT / "dashboard" / "dist" / "index.js").read_text()
    for view in ("Current", "Decisions", "Policies", "Agent Notes", "History", "Knowledge Vault", "Agent Access"):
        assert view in script
    assert "owner-secret" not in script


def test_repository_semantics_migration_is_simple_destructive_and_preserves_agent_access():
    sql = (ROOT / "migrations" / "004_repository_semantics.sql").read_text().lower()
    for table in ("current_contexts", "decisions", "agent_notes", "canonical_policies"):
        assert f"daos_memory.{table}" in sql
    assert "pending_owner_confirm" in sql
    assert "approved" in sql and "rejected" in sql and "superseded" in sql
    assert "truncate table" in sql
    assert "agent_registry" not in sql.split("truncate table", 1)[1].split(";", 1)[0]
    assert "vector" not in sql and "embedding" not in sql


def test_dashboard_has_owner_decision_policy_and_copy_contracts():
    script = (ROOT / "dashboard" / "dist" / "index.js").read_text()
    for label in ("Approve", "Reject", "Create Policy", "Copy Key", "Copy Start Command", "Copied"):
        assert label in script
    assert "/decisions/" in script
    assert "/policies" in script
    assert "Auto-generate" not in script


def test_event_rows_open_one_shared_read_only_detail_drawer_with_full_content():
    script = (ROOT / "dashboard" / "dist" / "index.js").read_text()
    style = (ROOT / "dashboard" / "dist" / "style.css").read_text()

    table_source = script[script.index("function EventTable"):script.index("function EventDetail")]
    detail_source = script[script.index("function EventDetail"):script.index("function PolicyTable")]
    for label in (
        "Event ID", "Product", "Topic", "Title", "Summary", "Full Content",
        "Memory Type", "Event Type", "Status", "Authority Level", "Actor",
        "Actor Role", "Source Interface", "Source Ref", "Stored At", "Occurred At",
        "Effective From", "Effective To", "Source Session At", "Updated At",
        "Supersedes", "Related Event",
    ):
        assert label in detail_source
    assert "item.content" not in table_source
    assert "item.content" in detail_source
    assert "item.occurred_at" in detail_source
    assert "item.effective_from" in detail_source
    assert "item.source_session_at" in detail_source
    assert "onClick" in table_source
    assert "onKeyDown" in table_source
    assert 'role: "button"' in table_source
    assert 'role: "dialog"' in detail_source
    assert "Read-only event detail" in detail_source
    assert "api(" not in detail_source
    assert "dm-drawer" in style
    assert "dm-detail-content" in style


def test_event_detail_uses_direct_url_and_browser_history_without_mutation_controls():
    source = (ROOT / "dashboard" / "dist" / "index.js").read_text()
    program = f"""
      const replacements = [];
      global.window = {{
        __HERMES_PLUGIN_SDK__: {{ React: {{}} }},
        __HERMES_PLUGINS__: {{ register: function () {{}} }},
        location: {{ pathname: "/memory/events/11111111-1111-4111-8111-111111111111" }},
        history: {{
          state: null,
          replaceState: function (state, title, path) {{ this.state = state; replacements.push(path); window.location.pathname = path; }}
        }},
        dispatchEvent: function () {{}}
      }};
      global.PopStateEvent = function () {{}};
      global.document = {{ activeElement: null }};
      eval({json.dumps(source)});
      const hooks = window.__DAOS_MEMORY_INTERNALS__;
      const id = "11111111-1111-4111-8111-111111111111";
      if (hooks.eventPath(id) !== "/memory/events/" + id) throw new Error("event path mismatch");
      if (hooks.eventIdFromPath("/memory/events/" + id) !== id) throw new Error("deep link parse failed");
      if (hooks.initialEventId !== id) throw new Error("initial event not captured");
      if (replacements[0] !== "/memory") throw new Error("shell bootstrap did not claim memory route");
      if (hooks.eventIdFromPath("/memory/events/not-a-uuid") !== null) throw new Error("invalid id accepted");
      if (hooks.eventIdFromPath("/memory") !== null) throw new Error("list route parsed as detail");
      const other = "22222222-2222-4222-8222-222222222222";
      const sourceId = "33333333-3333-4333-8333-333333333333";
      const cases = [
        [{{ from_event_id: id, to_event_id: other }}, "event", other],
        [{{ from_event_id: other, to_event_id: id }}, "event", other],
        [{{ from_event_id: id, to_source_id: sourceId }}, "source", sourceId],
        [{{ from_source_id: sourceId, to_event_id: id }}, "source", sourceId]
      ];
      cases.forEach(function (entry) {{
        const target = hooks.relationTargetFor(id, entry[0]);
        if (!target || target.kind !== entry[1] || target.id !== entry[2]) throw new Error("opposite relation endpoint mismatch");
      }});
      if (hooks.sourceIdFromPath(hooks.sourcePath(sourceId)) !== sourceId) throw new Error("source route mismatch");
    """
    result = subprocess.run(["node", "-e", program], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr

    assert "history.pushState" in source
    assert "history.replaceState" in source
    assert 'addEventListener("popstate"' in source
    assert 'removeEventListener("popstate"' in source
    assert 'api("/events/" + encodeURIComponent(eventId)' in source
    assert 'href: eventPath(item.id)' in source
    assert "Edit" not in source
    assert "Delete" not in source
    for label in ("Related Knowledge", "Source Documents", "Relations", "insufficient_evidence"):
        assert label in source
    assert 'api("/events/" + encodeURIComponent(item.id) + "/knowledge"' in source
    assert 'api("/sources/" + encodeURIComponent(sourceId)' in source
    assert "/memory/sources/" in source
    assert '"aria-label": relation.relation_type + " " + endpoint(relation)' in source
    assert 'target.kind === "event" ? eventPath(target.id) : sourcePath(target.id)' in source
    knowledge_loader = source.split("function loadKnowledge(item)", 1)[1].split("function loadDirectEvent", 1)[0]
    assert 'setEventKnowledgeStatus("loading")' in knowledge_loader
    assert 'setEventKnowledgeStatus("ready")' in knowledge_loader
    assert 'setEventKnowledgeStatus("unavailable")' in knowledge_loader
    assert "insufficient_evidence" not in knowledge_loader
    assert "Knowledge provenance unavailable (fail closed)." in source


def test_dashboard_internal_coordinators_abort_stale_requests_and_trap_dialog_focus():
    source = (ROOT / "dashboard" / "dist" / "index.js").read_text()
    program = f"""
      global.AbortController = class {{
        constructor() {{ this.signal = {{ aborted: false }}; }}
        abort() {{ this.signal.aborted = true; }}
      }};
      global.window = {{
        __HERMES_PLUGIN_SDK__: {{ React: {{}} }},
        __HERMES_PLUGINS__: {{ register: function () {{}} }}
      }};
      global.document = {{ activeElement: null }};
      eval({json.dumps(source)});
      const hooks = window.__DAOS_MEMORY_INTERNALS__;
      if (!hooks) throw new Error("missing testable coordinators");

      const channel = hooks.createLatestRequestChannel();
      const first = channel.start();
      const second = channel.start();
      if (!first.signal.aborted) throw new Error("previous request was not aborted");
      if (channel.isCurrent(first.generation)) throw new Error("stale generation stayed current");
      if (!channel.isCurrent(second.generation)) throw new Error("new generation is not current");
      channel.invalidate();
      if (!second.signal.aborted || channel.isCurrent(second.generation)) throw new Error("invalidate failed");

      let closed = 0;
      let prevented = 0;
      const firstFocus = {{ focus: function () {{ document.activeElement = firstFocus; }} }};
      const lastFocus = {{ focus: function () {{ document.activeElement = lastFocus; }} }};
      document.activeElement = lastFocus;
      hooks.handleDialogKey(
        {{ key: "Tab", shiftKey: false, preventDefault: function () {{ prevented += 1; }} }},
        [firstFocus, lastFocus], function () {{ closed += 1; }}
      );
      if (document.activeElement !== firstFocus || prevented !== 1) throw new Error("forward trap failed");
      hooks.handleDialogKey(
        {{ key: "Tab", shiftKey: true, preventDefault: function () {{ prevented += 1; }} }},
        [firstFocus, lastFocus], function () {{ closed += 1; }}
      );
      if (document.activeElement !== lastFocus || prevented !== 2) throw new Error("reverse trap failed");
      const outsideFocus = {{ focus: function () {{ document.activeElement = outsideFocus; }} }};
      document.activeElement = outsideFocus;
      hooks.handleDialogKey(
        {{ key: "Tab", shiftKey: false, preventDefault: function () {{ prevented += 1; }} }},
        [firstFocus, lastFocus], function () {{ closed += 1; }}
      );
      if (document.activeElement !== firstFocus || prevented !== 3) throw new Error("outside forward trap failed");
      document.activeElement = outsideFocus;
      hooks.handleDialogKey(
        {{ key: "Tab", shiftKey: true, preventDefault: function () {{ prevented += 1; }} }},
        [firstFocus, lastFocus], function () {{ closed += 1; }}
      );
      if (document.activeElement !== lastFocus || prevented !== 4) throw new Error("outside reverse trap failed");
      hooks.handleDialogKey(
        {{ key: "Escape", preventDefault: function () {{ prevented += 1; }} }},
        [firstFocus, lastFocus], function () {{ closed += 1; }}
      );
      if (closed !== 1 || prevented !== 5) throw new Error("escape close failed");
    """
    result = subprocess.run(["node", "-e", program], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "requestChannelRef.current.start()" in source
    assert "returnFocus" in source
    for start_marker, end_marker in (("function rotate", "function revoke"), ("function revoke", "let body")):
        action_source = source[source.index(start_marker):source.index(end_marker)]
        assert "actionChannelRef.current.start()" in action_source
        assert "if (actionBusyRef.current) return" in action_source
        assert "actionBusyRef.current = true" in action_source
        assert "signal: action.signal" in action_source
        assert "actionChannelRef.current.isCurrent(action.generation)" in action_source
        assert "viewRef.current !== actionView" in action_source
    assert "actionBusyRef.current = false" in source
    assert "disabled: busy" in source


def test_migration_has_only_required_core_tables_and_hashed_credential_columns():
    sql = (ROOT / "migrations" / "001_daos_memory_v01.sql").read_text().lower()
    for table in ("context_events", "canonical_policies", "agent_registry", "context_relations"):
        assert f"create table daos_memory.{table}" in sql
    assert "bootstrap_key_hash" in sql
    assert "access_token_hash" in sql
    assert "bootstrap_key text" not in sql
    assert "access_token text" not in sql
    assert "delete from" not in sql


def test_temporal_validity_migration_is_additive_backfilled_and_fail_safe():
    sql = (ROOT / "migrations" / "002_event_temporal_validity.sql").read_text().lower()
    for column in ("occurred_at", "effective_from", "effective_to", "source_session_at"):
        assert f"add column if not exists {column}" in sql
    assert "update daos_memory.context_events" in sql
    assert "occurred_at = created_at" in sql
    assert "effective_from = created_at" in sql
    assert "source_session_at = created_at" in sql
    assert "set not null" in sql
    assert "history" in sql and "closed" in sql
    assert "effective_to is null or effective_to >= effective_from" in sql
    assert "drop table" not in sql
    assert "delete from" not in sql


def test_source_grounded_knowledge_migration_is_additive_and_canonical():
    sql = (ROOT / "migrations" / "003_source_grounded_knowledge.sql").read_text().lower()
    assert "create table daos_memory.knowledge_sources" in sql
    assert "create table daos_memory.knowledge_relations" in sql
    for column in ("content_hash", "access_scope", "security_level", "redaction_status", "source_session_at"):
        assert column in sql
    for relation in ("summarizes", "derived_from", "source_of", "related_to", "supersedes", "evidence_for", "decided_by", "implemented_by"):
        assert relation in sql
    assert "references daos_memory.context_events" in sql
    assert "references daos_memory.knowledge_sources" in sql
    assert "grant select, insert on daos_memory.knowledge_sources, daos_memory.knowledge_relations to daos_memory_runtime" in sql
    assert "grant update" not in sql and "grant delete" not in sql
    assert "drop table" not in sql and "delete from" not in sql and "update daos_memory.context_events" not in sql



def test_systemd_template_is_separate_bounded_and_hardened():
    unit = (ROOT / "systemd" / "daos-memory.service").read_text()
    assert "uvicorn" in unit
    assert "MemoryMax=" in unit
    assert "TimeoutStartSec=" in unit
    assert "EnvironmentFile=" in unit
    assert "NoNewPrivileges=true" in unit
    assert "Environment=HERMES_CONFIG_PATH=/etc/daos-memory/config.yaml" in unit
    assert "hermes gateway" not in unit.lower()


def test_zeus_action_systemd_is_private_bounded_and_uses_a_secret_file():
    unit = (ROOT / "systemd" / "daos-zeus-memory-action.service").read_text()
    assert "User=daos-memory" in unit
    assert "DAOS_MEMORY_ACTION_TOKEN_FILE=/etc/daos-memory/zeus-action.token" in unit
    assert "DAOS_MEMORY_UPSTREAM_URL=http://172.18.0.1:8791" in unit
    assert "plugins.daos_memory.action_api" in unit
    assert "MemoryMax=" in unit
    assert "NoNewPrivileges=true" in unit
    assert "172.18.0.1" in unit
    assert "172.18.0.0/16" in unit
    assert "br-a0bd2b780836" in unit
    assert "ExecStartPre=+" in unit
    assert "ExecStopPost=+" in unit
    assert "8793" in unit
    assert "token=" not in unit.lower()


def test_zeus_action_nginx_locations_are_exact_host_gated_and_bounded():
    config = (ROOT / "nginx" / "zeus_memory_locations.conf").read_text()
    for path in (
        "/zeus-memory/v1/bootstrap",
        "/zeus-memory/v1/current",
        "/zeus-memory/v1/history",
        "/zeus-memory/v1/events",
        "/zeus-memory/v1/event",
    ):
        assert f"location = {path}" in config
    assert 'if ($host !~ "^(ax[.]dominof[.]com|memory[.]dominof[.]com)$") { return 404; }' in config
    assert config.count("if ($request_method != POST) { return 405; }") == 5
    assert "location ^~ /zeus-memory/" in config
    assert "location ~* ^/zeus-memory" in config
    assert "client_max_body_size 16k" in config
    assert "proxy_pass http://172.18.0.1:8793" in config
    assert "proxy_read_timeout 40s" in config
    assert "Authorization" not in config


def test_memory_domain_vhost_is_dedicated_tls_only_and_fail_closed():
    config = (ROOT / "nginx" / "memory_dominof_vhost.conf").read_text()
    assert config.count("server_name memory.dominof.com;") == 2
    assert "listen 80;" in config
    assert "return 301 https://$host$request_uri;" in config
    assert "listen 443 ssl;" in config
    assert "ssl_certificate /etc/letsencrypt/live/npm-memory/fullchain.pem;" in config
    assert "ssl_certificate_key /etc/letsencrypt/live/npm-memory/privkey.pem;" in config
    assert "include /data/nginx/custom/zeus_memory_locations_memory[.]conf;" in config
    assert "location / { return 404; }" in config
    assert "server_proxy" not in config


def test_memory_domain_certificate_has_durable_bounded_renewal():
    service = (ROOT / "systemd" / "daos-memory-domain-cert-renew.service").read_text()
    timer = (ROOT / "systemd" / "daos-memory-domain-cert-renew.timer").read_text()
    assert "Type=oneshot" in service
    assert "docker exec dominof-nginx-proxy-manager certbot renew" in service
    assert "--cert-name npm-memory" in service
    assert '--deploy-hook "nginx -s reload"' in service
    assert "OnCalendar=" in timer
    assert "Persistent=true" in timer
    assert "RandomizedDelaySec=" in timer
    assert "WantedBy=timers.target" in timer


def test_wheel_package_data_declares_only_daos_runtime_artifacts():
    pyproject = tomllib.loads((ROOT.parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    plugin_data = pyproject["tool"]["setuptools"]["package-data"]["plugins"]
    for artifact in (
        "daos_memory/migrations/001_daos_memory_v01.sql",
        "daos_memory/migrations/002_event_temporal_validity.sql",
        "daos_memory/migrations/003_source_grounded_knowledge.sql",
        "daos_memory/systemd/daos-memory.service",
        "daos_memory/systemd/daos-zeus-memory-action.service",
        "daos_memory/openapi/zeus_memory_action.yaml",
        "daos_memory/nginx/zeus_memory_locations.conf",
        "daos_memory/nginx/memory_dominof_vhost.conf",
        "daos_memory/systemd/daos-memory-domain-cert-renew.service",
        "daos_memory/systemd/daos-memory-domain-cert-renew.timer",
        "daos_memory/requirements.txt",
    ):
        assert artifact in plugin_data


def test_shell_plugin_routes_keep_nested_canonical_urls_mounted():
    app_source = (ROOT.parents[1] / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
    assert "function pluginRoutePath(path: string)" in app_source
    assert app_source.count("path: pluginRoutePath(m.tab.path)") == 2


def test_dockerfile_restores_built_web_dist_after_source_copy():
    dockerfile = (ROOT.parents[1] / "Dockerfile").read_text(encoding="utf-8")
    preserve = "cp -a hermes_cli/web_dist /tmp/hermes_web_dist"
    source_copy = "COPY --link --chmod=a+rX,go-w . ."
    restore = "mv /tmp/hermes_web_dist hermes_cli/web_dist"
    assert preserve in dockerfile
    assert restore in dockerfile
    assert dockerfile.index(preserve) < dockerfile.index(source_copy) < dockerfile.index(restore)
