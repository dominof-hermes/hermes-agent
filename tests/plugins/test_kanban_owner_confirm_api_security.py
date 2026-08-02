"""Owner Confirm V2 security tests — externally reachable API surface.

The blockers these close are all *reachability* blockers: the DB layer can be
correct and the gate still be worthless if the generic PATCH/bulk/DELETE
surface can walk a card out of it. Everything here goes through the mounted
router, i.e. exactly what a browser, a worker or a script holding the session
token can call.

No live DB, no network: each test runs against an isolated ``HERMES_HOME``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from hermes_cli import kanban_db as kb


API = "/api/plugins/kanban"


def _load_plugin_router():
    repo_root = Path(__file__).resolve().parents[2]
    plugin_file = repo_root / "plugins" / "kanban" / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location(
        "hermes_dashboard_plugin_kanban_ocv2_test", plugin_file,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.router


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


@pytest.fixture
def client(kanban_home):
    app = FastAPI()
    app.include_router(_load_plugin_router(), prefix=API)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------

GOOD_SOURCE_SHA = hashlib.sha1(b"daos-owner-confirm-v2-api").hexdigest()
ROLLBACK = "직전 릴리스 태그로 즉시 되돌리고 재검증합니다"

GATE_KIND = {
    "ready_for_push": "product_release",
    "ready_for_deploy": "product_release",
    "owner_confirm_required": "customer_report",
}
GATE_STATUSES = ("ready_for_push", "ready_for_deploy", "owner_confirm_required")


def owner_gate(oc_kind: str = "product_release", **overrides) -> dict:
    gate = {
        "oc_kind": oc_kind,
        "artifact_kind": "source_sha",
        "artifact_sha": GOOD_SOURCE_SHA,
        "destination": "production",
        "rollback": ROLLBACK,
        "evidence": {
            stage: {
                "summary": summary,
                "ref": ref,
                "artifact_sha": GOOD_SOURCE_SHA,
            }
            for stage, summary, ref in (
                ("implemented", "구현 완료, 변경 범위 검색 랭킹 모듈", "task:t_impl_1"),
                ("tested", "회귀 테스트 전량 통과", "run:4821"),
                ("reviewed", "리뷰 승인, 지적 사항 없음", "event:9931"),
            )
        },
        "card": {
            "why": "고객 대상 릴리스라 대표 승인이 필요합니다",
            "impact": "검색 응답 품질이 전 고객에게 즉시 반영됩니다",
            "rollback": ROLLBACK,
            "recommendation": "승인 권장",
            "summary_30s": "품질 개선 릴리스 1건, 되돌리기 준비 완료",
        },
    }
    gate.update(overrides)
    return gate


def make_task(client, title: str = "OC card") -> str:
    return client.post(f"{API}/tasks", json={"title": title}).json()["task"]["id"]


def park_in_gate(client, gate: str = "ready_for_push", *, with_request: bool = True) -> str:
    """Park a fresh card in ``gate`` and (optionally) pose the owner ask."""
    task_id = make_task(client)
    body: dict = {"status": gate}
    if with_request:
        body["owner_gate"] = owner_gate(GATE_KIND[gate])
    response = client.patch(f"{API}/tasks/{task_id}", json=body)
    assert response.status_code == 200, response.text
    return task_id


def task_of(client, task_id: str) -> dict:
    return client.get(f"{API}/tasks/{task_id}").json()["task"]


def events_of(client, task_id: str) -> list[dict]:
    return client.get(f"{API}/tasks/{task_id}").json()["events"]


def binding_of(client, task_id: str) -> str:
    oc = task_of(client, task_id)["owner_confirm"]
    assert oc["available"] is True, oc
    return oc["binding"]


# ---------------------------------------------------------------------------
# Blocker 1 — generic PATCH containment
# ---------------------------------------------------------------------------

# Every status a client could name on the generic surface, including the ones
# the reviewer called out by name.
ESCAPE_TARGETS = [
    "ready", "running", "review", "integrating", "done", "blocked",
    "archived", "todo", "triage", "scheduled", "backlog",
    "ready_for_push", "ready_for_deploy", "owner_confirm_required",
    "owner_confirmed",
]


@pytest.mark.parametrize("gate", GATE_STATUSES)
@pytest.mark.parametrize("target", ESCAPE_TARGETS)
def test_generic_patch_cannot_walk_a_card_out_of_its_gate(client, gate, target):
    if target == gate:
        pytest.skip("same-gate PATCH is a no-op, covered separately")
    task_id = park_in_gate(client, gate)
    before_events = events_of(client, task_id)

    response = client.patch(
        f"{API}/tasks/{task_id}",
        json={"status": target, "block_reason": "x", "summary": "x"},
    )

    assert response.status_code == 403, response.text
    assert task_of(client, task_id)["status"] == gate
    assert events_of(client, task_id) == before_events


@pytest.mark.parametrize("gate", GATE_STATUSES)
def test_patch_to_the_same_gate_status_is_still_allowed(client, gate):
    """Re-posing the ask in place is Hermes asking, not answering."""
    task_id = park_in_gate(client, gate)
    response = client.patch(f"{API}/tasks/{task_id}", json={"status": gate})
    assert response.status_code == 200, response.text
    assert task_of(client, task_id)["status"] == gate


def test_patch_gate_to_ready_fails_and_dispatcher_claim_stays_impossible(client, kanban_home):
    """The probe the review asked for, end to end.

    ``ready`` is the one status the dispatcher selects, so this is the exact
    escape that would have turned a Level-3 gate into ordinary queued work.
    """
    task_id = park_in_gate(client, "ready_for_push")

    response = client.patch(f"{API}/tasks/{task_id}", json={"status": "ready"})

    assert response.status_code == 403, response.text
    assert "owner" in response.json()["detail"].lower()

    # The card never reaches the dispatcher's selection set...
    assert task_of(client, task_id)["status"] == "ready_for_push"
    board = client.get(f"{API}/board").json()
    ready = next(c for c in board["columns"] if c["name"] == "ready")
    assert task_id not in [t["id"] for t in ready["tasks"]]

    # ...a dispatch tick does not promote or spawn it...
    dispatched = client.post(f"{API}/dispatch?dry_run=false&max=8")
    assert dispatched.status_code == 200
    assert task_of(client, task_id)["status"] == "ready_for_push"

    # ...and a direct claim is refused at the DB layer too.
    with kb.connect() as conn:
        assert kb.claim_task(conn, task_id) is None
        assert kb.claim_review_task(conn, task_id) is None
        assert kb.recompute_ready(conn) == 0
        assert kb.get_task(conn, task_id).status == "ready_for_push"


def test_generic_patch_cannot_enter_owner_confirmed(client):
    task_id = park_in_gate(client, "ready_for_push")
    response = client.patch(f"{API}/tasks/{task_id}", json={"status": "owner_confirmed"})
    assert response.status_code == 403
    assert "owner-decision" in response.json()["detail"]
    assert task_of(client, task_id)["status"] == "ready_for_push"


@pytest.mark.parametrize("target", ESCAPE_TARGETS)
def test_generic_patch_cannot_leave_owner_confirmed(client, target):
    task_id = park_in_gate(client, "ready_for_push")
    approve(client, task_id, "ready_for_push")
    before_events = events_of(client, task_id)

    response = client.patch(f"{API}/tasks/{task_id}", json={"status": target})

    assert response.status_code == 403, response.text
    assert task_of(client, task_id)["status"] == "owner_confirmed"
    assert events_of(client, task_id) == before_events


@pytest.mark.parametrize("gate", GATE_STATUSES)
@pytest.mark.parametrize("target", ["ready", "done", "blocked", "todo", "owner_confirmed"])
def test_bulk_update_cannot_walk_a_card_out_of_its_gate(client, gate, target):
    task_id = park_in_gate(client, gate)

    response = client.post(
        f"{API}/tasks/bulk", json={"ids": [task_id], "status": target},
    )

    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["ok"] is False
    assert "owner" in result["error"].lower()
    assert task_of(client, task_id)["status"] == gate


def test_bulk_update_cannot_leave_owner_confirmed(client):
    task_id = park_in_gate(client, "ready_for_push")
    approve(client, task_id, "ready_for_push")

    response = client.post(
        f"{API}/tasks/bulk", json={"ids": [task_id], "status": "ready"},
    )

    assert response.json()["results"][0]["ok"] is False
    assert task_of(client, task_id)["status"] == "owner_confirmed"


def test_bulk_partial_failure_does_not_hold_ordinary_cards_hostage(client):
    """Containment is per-card: an ordinary sibling in the same batch moves."""
    gated = park_in_gate(client, "ready_for_push")
    ordinary = make_task(client, "ordinary")

    results = client.post(
        f"{API}/tasks/bulk", json={"ids": [gated, ordinary], "status": "review"},
    ).json()["results"]

    by_id = {r["id"]: r for r in results}
    assert by_id[gated]["ok"] is False
    assert by_id[ordinary]["ok"] is True
    assert task_of(client, gated)["status"] == "ready_for_push"
    assert task_of(client, ordinary)["status"] == "review"


def test_entering_a_gate_from_ordinary_work_is_still_allowed(client):
    """Containment must not break Hermes posing the question."""
    task_id = make_task(client)
    response = client.patch(f"{API}/tasks/{task_id}", json={"status": "ready_for_push"})
    assert response.status_code == 200, response.text
    assert task_of(client, task_id)["status"] == "ready_for_push"


# ---------------------------------------------------------------------------
# Blocker 2 — destruction / audit preservation over the API
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("gate", GATE_STATUSES)
def test_delete_endpoint_refuses_a_gated_card(client, gate):
    task_id = park_in_gate(client, gate)

    response = client.delete(f"{API}/tasks/{task_id}")

    assert response.status_code == 403, response.text
    assert task_of(client, task_id)["status"] == gate
    assert any(
        e["kind"] == kb.OWNER_CONFIRM_REQUESTED_EVENT for e in events_of(client, task_id)
    )


def test_delete_endpoint_refuses_a_confirmed_card(client):
    task_id = park_in_gate(client, "ready_for_push")
    approve(client, task_id, "ready_for_push")

    assert client.delete(f"{API}/tasks/{task_id}").status_code == 403
    assert task_of(client, task_id)["status"] == "owner_confirmed"


@pytest.mark.parametrize("decision", ["reject", "hold"])
def test_delete_endpoint_refuses_a_card_with_decision_history(client, decision):
    task_id = park_in_gate(client, "ready_for_push")
    decide(client, task_id, decision, "ready_for_push", reason="추가 근거가 필요합니다")

    response = client.delete(f"{API}/tasks/{task_id}")

    assert response.status_code == 403, response.text
    kinds = {e["kind"] for e in events_of(client, task_id)}
    assert kinds & {kb.OWNER_REJECTED_EVENT, kb.OWNER_HOLD_EVENT}


@pytest.mark.parametrize("gate", GATE_STATUSES)
def test_archive_via_patch_and_bulk_refuses_a_gated_card(client, gate):
    task_id = park_in_gate(client, gate)

    patched = client.patch(f"{API}/tasks/{task_id}", json={"status": "archived"})
    assert patched.status_code == 403, patched.text

    bulk = client.post(f"{API}/tasks/bulk", json={"ids": [task_id], "archive": True})
    assert bulk.json()["results"][0]["ok"] is False
    assert "owner" in bulk.json()["results"][0]["error"].lower()

    assert task_of(client, task_id)["status"] == gate


def test_bulk_archive_refuses_a_confirmed_card(client):
    task_id = park_in_gate(client, "ready_for_push")
    approve(client, task_id, "ready_for_push")

    bulk = client.post(f"{API}/tasks/bulk", json={"ids": [task_id], "archive": True})

    assert bulk.json()["results"][0]["ok"] is False
    assert task_of(client, task_id)["status"] == "owner_confirmed"


def test_delete_endpoint_still_removes_an_ordinary_card(client):
    task_id = make_task(client, "ordinary")
    assert client.delete(f"{API}/tasks/{task_id}").status_code == 200
    assert client.get(f"{API}/tasks/{task_id}").status_code == 404


# ---------------------------------------------------------------------------
# Blocker 3 — atomicity of the combined status + owner_gate PATCH
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "broken_gate",
    [
        {"artifact_sha": "deadbee"},
        {"card": {"why": "짧음"}},
        {"evidence": "not-an-object"},
        {"oc_kind": "source_change"},
        {"unknown_field": 1},
        "not-an-object",
        {"card": {
            "why": "담당자 010-1234-5678 확인 필요",
            "impact": "영향 있음",
            "rollback": ROLLBACK,
            "recommendation": "보류",
            "summary_30s": "요약",
        }},
    ],
)
def test_malformed_owner_gate_leaves_status_and_events_unchanged(client, broken_gate):
    """A rejected ask must not leave the card parked in a gate it cannot exit."""
    task_id = make_task(client)
    before_task = task_of(client, task_id)
    before_events = events_of(client, task_id)

    response = client.patch(
        f"{API}/tasks/{task_id}",
        json={"status": "ready_for_push", "owner_gate": broken_gate},
    )

    assert response.status_code in (400, 409, 422), response.text
    after_task = task_of(client, task_id)
    assert after_task["status"] == before_task["status"]
    assert events_of(client, task_id) == before_events


def test_malformed_owner_gate_does_not_apply_the_sibling_fields(client):
    """Validation is complete *before* any mutation — assignee, priority and
    title in the same PATCH must not land either."""
    task_id = make_task(client)
    before_task = task_of(client, task_id)
    before_events = events_of(client, task_id)

    response = client.patch(
        f"{API}/tasks/{task_id}",
        json={
            "status": "ready_for_deploy",
            "priority": 99,
            "title": "renamed by a half-applied patch",
            "owner_gate": owner_gate(artifact_sha="deadbee"),
        },
    )

    assert response.status_code == 400, response.text
    after_task = task_of(client, task_id)
    assert after_task["status"] == before_task["status"]
    assert after_task["priority"] == before_task["priority"]
    assert after_task["title"] == before_task["title"]
    assert events_of(client, task_id) == before_events


def test_unknown_status_is_refused_before_any_sibling_field_lands(client):
    task_id = make_task(client)
    before = task_of(client, task_id)

    response = client.patch(
        f"{API}/tasks/{task_id}",
        json={"status": "not_a_status", "priority": 42, "title": "renamed"},
    )

    assert response.status_code == 400
    after = task_of(client, task_id)
    assert after["priority"] == before["priority"]
    assert after["title"] == before["title"]


def test_empty_title_is_refused_before_the_status_lands(client):
    task_id = make_task(client)
    before_task = task_of(client, task_id)

    response = client.patch(
        f"{API}/tasks/{task_id}", json={"status": "review", "title": "   "},
    )

    assert response.status_code == 400
    assert task_of(client, task_id)["status"] == before_task["status"]


def test_a_valid_combined_patch_parks_and_records_in_one_step(client):
    task_id = make_task(client)

    response = client.patch(
        f"{API}/tasks/{task_id}",
        json={"status": "ready_for_push", "owner_gate": owner_gate()},
    )

    assert response.status_code == 200, response.text
    oc = response.json()["task"]["owner_confirm"]
    assert oc["available"] is True
    assert oc["gate_status"] == "ready_for_push"
    assert oc["artifact_sha"] == GOOD_SOURCE_SHA
    assert oc["artifact_short"] == GOOD_SOURCE_SHA[:12]
    assert task_of(client, task_id)["status"] == "ready_for_push"


def test_owner_gate_on_a_non_gate_card_is_refused_without_mutation(client):
    task_id = make_task(client)
    before_task = task_of(client, task_id)
    before_events = events_of(client, task_id)

    response = client.patch(f"{API}/tasks/{task_id}", json={"owner_gate": owner_gate()})

    assert response.status_code == 409, response.text
    assert task_of(client, task_id)["status"] == before_task["status"]
    assert events_of(client, task_id) == before_events


# ---------------------------------------------------------------------------
# Blockers 4 + 5 over the API — sanitized rejections
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_sha", ["deadbee", "1f0c4a9d2b7e", "0" * 40])
def test_api_refuses_an_inexact_artifact_digest(client, bad_sha):
    task_id = make_task(client)
    before_task = task_of(client, task_id)
    response = client.patch(
        f"{API}/tasks/{task_id}",
        json={"status": "ready_for_push", "owner_gate": owner_gate(artifact_sha=bad_sha)},
    )
    assert response.status_code == 400
    assert "artifact_sha" in response.json()["detail"]
    assert task_of(client, task_id)["status"] == before_task["status"]


@pytest.mark.parametrize(
    "text",
    [
        "승인 문의는 daesan.jo@gmail.com 으로 회신 바랍니다",
        "담당자 연락처 010-1234-5678 입니다",
        "고객 주민등록번호 900101-1234567 확인 완료",
        "산출물은 /home/ubuntu/hermes/artifacts/ 에 있습니다",
        "배포 대상 10.0.12.34 입니다",
        "연결 문자열 postgresql://svc@db-prod/app 사용",
        "role: db_owner 권한으로 실행",
    ],
)
def test_api_returns_a_sanitized_error_for_disclosing_card_text(client, text):
    task_id = make_task(client)
    before_task = task_of(client, task_id)
    gate = owner_gate()
    gate["card"]["impact"] = text

    response = client.patch(
        f"{API}/tasks/{task_id}",
        json={"status": "ready_for_push", "owner_gate": gate},
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail.startswith("card.impact")
    assert text not in detail
    assert task_of(client, task_id)["status"] == before_task["status"]


# ---------------------------------------------------------------------------
# The dedicated decision + execution endpoints
# ---------------------------------------------------------------------------


def decide(client, task_id: str, decision: str, expected_status: str, **extra):
    body = {
        "decision": decision,
        "expected_status": expected_status,
        "binding": binding_of(client, task_id),
    }
    body.update(extra)
    response = client.post(f"{API}/tasks/{task_id}/owner-decision", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def approve(client, task_id: str, expected_status: str):
    return decide(client, task_id, "approve", expected_status)


@pytest.mark.parametrize("gate", GATE_STATUSES)
def test_owner_decision_is_the_only_way_into_confirmed(client, gate):
    task_id = park_in_gate(client, gate)
    approve(client, task_id, gate)
    assert task_of(client, task_id)["status"] == "owner_confirmed"


def test_owner_decision_refuses_a_stale_binding(client):
    task_id = park_in_gate(client, "ready_for_push")

    response = client.post(
        f"{API}/tasks/{task_id}/owner-decision",
        json={
            "decision": "approve",
            "expected_status": "ready_for_push",
            "binding": "0" * 64,
        },
    )

    assert response.status_code == 400
    assert task_of(client, task_id)["status"] == "ready_for_push"


def test_owner_decision_refuses_a_card_with_no_recorded_request(client):
    task_id = park_in_gate(client, "ready_for_push", with_request=False)

    response = client.post(
        f"{API}/tasks/{task_id}/owner-decision",
        json={
            "decision": "approve",
            "expected_status": "ready_for_push",
            "binding": "0" * 64,
        },
    )

    assert response.status_code == 400
    assert task_of(client, task_id)["status"] == "ready_for_push"


def test_post_approve_progression_uses_the_execution_endpoint(client):
    task_id = park_in_gate(client, "ready_for_push")
    approval = approve(client, task_id, "ready_for_push")["owner_decision"]

    response = client.post(
        f"{API}/tasks/{task_id}/owner-execution",
        json={
            "binding": approval["binding"],
            "gate_type": approval["gate_type"],
            "artifact_sha": approval["artifact_sha"],
            "outcome": "performed",
        },
    )

    assert response.status_code == 200, response.text
    assert task_of(client, task_id)["status"] == "integrating"


@pytest.mark.parametrize(
    "override",
    [
        {"binding": "0" * 64},
        {"gate_type": "deploy"},
        {"artifact_sha": hashlib.sha1(b"other").hexdigest()},
        {"outcome": "performed-ish"},
    ],
)
def test_execution_endpoint_refuses_anything_but_the_bound_action(client, override):
    task_id = park_in_gate(client, "ready_for_push")
    approval = approve(client, task_id, "ready_for_push")["owner_decision"]
    body = {
        "binding": approval["binding"],
        "gate_type": approval["gate_type"],
        "artifact_sha": approval["artifact_sha"],
        "outcome": "performed",
    }
    body.update(override)
    before_events = events_of(client, task_id)

    response = client.post(f"{API}/tasks/{task_id}/owner-execution", json=body)

    assert response.status_code in (400, 409), response.text
    assert task_of(client, task_id)["status"] == "owner_confirmed"
    assert events_of(client, task_id) == before_events


def test_execution_endpoint_refuses_a_card_that_was_never_confirmed(client):
    task_id = park_in_gate(client, "ready_for_push")

    response = client.post(
        f"{API}/tasks/{task_id}/owner-execution",
        json={
            "binding": binding_of(client, task_id),
            "gate_type": "push",
            "artifact_sha": GOOD_SOURCE_SHA,
            "outcome": "performed",
        },
    )

    assert response.status_code == 409
    assert task_of(client, task_id)["status"] == "ready_for_push"


def test_hold_leaves_the_card_in_the_gate_and_records_the_reason(client):
    task_id = park_in_gate(client, "owner_confirm_required")
    decide(
        client, task_id, "hold", "owner_confirm_required",
        reason="다음 주 이사회 이후 재검토",
    )

    task = task_of(client, task_id)
    assert task["status"] == "owner_confirm_required"
    assert task["owner_confirm"]["hold"]["reason"] == "다음 주 이사회 이후 재검토"


def test_reject_routes_to_typed_blocked_and_stays_there(client, kanban_home):
    task_id = park_in_gate(client, "ready_for_push")
    decide(client, task_id, "reject", "ready_for_push", reason="근거가 부족합니다")

    assert task_of(client, task_id)["status"] == "blocked"
    # A dispatch tick must not quietly re-queue an owner-rejected card.
    client.post(f"{API}/dispatch?dry_run=false&max=8")
    assert task_of(client, task_id)["status"] == "blocked"


def test_board_kpi_counts_the_waiting_gate_card(client):
    park_in_gate(client, "ready_for_push")
    kpi = client.get(f"{API}/board").json()["owner_confirm_kpi"]
    assert kpi["waiting"] == 1
    assert kpi["aged_7d"] == 0
    assert kpi["unknown_age"] == 0


# ---------------------------------------------------------------------------
# Adjacent surfaces (blocker 6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("gate", GATE_STATUSES)
def test_reclaim_cannot_move_a_gated_card(client, gate):
    """``reclaim`` only releases a *running* claim — a gated card has none."""
    task_id = park_in_gate(client, gate)

    reclaimed = client.post(f"{API}/tasks/{task_id}/reclaim", json={"reason": "x"})
    assert reclaimed.status_code == 409

    assert task_of(client, task_id)["status"] == gate


def test_assignee_and_priority_edits_remain_available_on_a_gated_card(client):
    """Containment is about *status and destruction*, not about freezing the
    card: metadata edits an owner might make while deciding still work."""
    task_id = park_in_gate(client, "ready_for_push")

    response = client.patch(f"{API}/tasks/{task_id}", json={"priority": 5})

    assert response.status_code == 200, response.text
    task = task_of(client, task_id)
    assert task["priority"] == 5
    assert task["status"] == "ready_for_push"
    assert task["owner_confirm"]["available"] is True
