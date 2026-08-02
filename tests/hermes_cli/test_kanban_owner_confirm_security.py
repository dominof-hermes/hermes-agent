"""Owner Confirm V2 security tests — DB layer (``hermes_cli.kanban_db``).

These cover the independent-review blockers that closed V1 as FAIL:

* exact artifact digests (no abbreviated ``deadbee``, no placeholders),
* PII / non-disclosure scrubbing of owner-facing text,
* fail-closed destruction so approval/reject/hold audit events survive,
* atomic validation (a malformed ask leaves status and events untouched),
* a dedicated exact-action execution path for post-approve progression.

Nothing here touches a live DB: every test runs against an isolated
``HERMES_HOME`` created by the ``kanban_home`` fixture.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    """Isolated HERMES_HOME with an empty kanban DB."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

# Real digests, never a placeholder: a 40-hex Git SHA-1 object name and a
# 64-hex SHA-256 document digest.
GOOD_SOURCE_SHA = hashlib.sha1(b"daos-owner-confirm-v2").hexdigest()
GOOD_DOC_SHA = hashlib.sha256(b"daos-owner-confirm-v2").hexdigest()

ROLLBACK = "직전 릴리스 태그로 즉시 되돌리고 재검증합니다"


def owner_card(**overrides) -> dict:
    card = {
        "why": "고객 대상 릴리스라 대표 승인이 필요합니다",
        "impact": "검색 응답 품질이 전 고객에게 즉시 반영됩니다",
        "rollback": ROLLBACK,
        "recommendation": "승인 권장",
        "summary_30s": "품질 개선 릴리스 1건, 되돌리기 준비 완료",
    }
    card.update(overrides)
    return card


def owner_evidence(artifact_sha: str = GOOD_SOURCE_SHA, **overrides) -> dict:
    evidence = {
        "implemented": {
            "summary": "구현 완료, 변경 범위 검색 랭킹 모듈",
            "ref": "task:t_impl_1",
            "artifact_sha": artifact_sha,
        },
        "tested": {
            "summary": "회귀 테스트 전량 통과",
            "ref": "run:4821",
            "artifact_sha": artifact_sha,
        },
        "reviewed": {
            "summary": "리뷰 승인, 지적 사항 없음",
            "ref": "event:9931",
            "artifact_sha": artifact_sha,
        },
    }
    evidence.update(overrides)
    return evidence


def gate_request(**overrides) -> dict:
    req = {
        "oc_kind": "product_release",
        "artifact_kind": "source_sha",
        "artifact_sha": GOOD_SOURCE_SHA,
        "destination": "production",
        "rollback": ROLLBACK,
        "evidence": owner_evidence(),
        "card": owner_card(),
    }
    req.update(overrides)
    return req


def park(conn, task_id: str, status: str) -> None:
    """Move a task straight to ``status`` at the DB layer (test setup only)."""
    conn.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, task_id))
    conn.commit()


def gated_task(conn, *, status: str = "ready_for_push", **overrides) -> str:
    task_id = kb.create_task(conn, title="OC gate card")
    park(conn, task_id, status)
    kb.request_owner_confirm(conn, task_id, **gate_request(**overrides))
    return task_id


def event_rows(conn, task_id: str) -> list[tuple]:
    return [
        (r["id"], r["kind"], r["payload"], r["created_at"])
        for r in conn.execute(
            "SELECT id, kind, payload, created_at FROM task_events "
            "WHERE task_id = ? ORDER BY id",
            (task_id,),
        ).fetchall()
    ]


def task_row(conn, task_id: str) -> dict:
    row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    return dict(row) if row is not None else {}


# ---------------------------------------------------------------------------
# Blocker 4 — exact artifact digest
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_sha",
    [
        "deadbee",              # the abbreviation the reviewer called out
        "deadbeef",             # 8
        "1f0c4a9d2b7e",         # 12, git's default short form
        GOOD_SOURCE_SHA[:39],   # one short of a full SHA-1
        GOOD_SOURCE_SHA + "0",  # one long
        GOOD_SOURCE_SHA[:32],   # an MD5-length digest
        GOOD_DOC_SHA[:56],      # between the two accepted lengths
    ],
)
def test_abbreviated_source_sha_is_refused(kanban_home, bad_sha):
    """Only a canonical full digest binds an approval to one exact artifact."""
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="abbrev sha")
        park(conn, task_id, "ready_for_push")
        before_events = event_rows(conn, task_id)

        with pytest.raises(kb.OwnerConfirmMetadataError) as exc:
            kb.request_owner_confirm(
                conn, task_id, **gate_request(artifact_sha=bad_sha)
            )

        assert "artifact_sha" in str(exc.value)
        # Fail-closed: nothing recorded, status untouched.
        assert event_rows(conn, task_id) == before_events
        assert kb.get_task(conn, task_id).status == "ready_for_push"


@pytest.mark.parametrize(
    "artifact_kind,sha",
    [
        ("source_sha", GOOD_SOURCE_SHA),        # 40-hex Git SHA-1 object name
        ("source_sha", GOOD_DOC_SHA),           # 64-hex Git SHA-256 object name
        ("document_sha256", GOOD_DOC_SHA),      # 64-hex document digest
    ],
)
def test_canonical_full_digests_are_accepted(kanban_home, artifact_kind, sha):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="full sha")
        park(conn, task_id, "ready_for_push")
        payload = kb.request_owner_confirm(
            conn, task_id,
            **gate_request(
                artifact_kind=artifact_kind,
                artifact_sha=sha,
                evidence=owner_evidence(sha),
            ),
        )
    assert payload["artifact_sha"] == sha
    assert payload["artifact_kind"] == artifact_kind


def test_document_sha256_refuses_a_40_hex_git_sha(kanban_home):
    """A document digest is SHA-256 only — a 40-hex value is the wrong kind."""
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="doc kind")
        park(conn, task_id, "owner_confirm_required")
        with pytest.raises(kb.OwnerConfirmMetadataError):
            kb.request_owner_confirm(
                conn, task_id,
                **gate_request(
                    oc_kind="customer_report",
                    artifact_kind="document_sha256",
                    artifact_sha=GOOD_SOURCE_SHA,
                    evidence=owner_evidence(GOOD_SOURCE_SHA),
                ),
            )


@pytest.mark.parametrize(
    "placeholder",
    [
        "0" * 40,
        "0" * 64,
        "f" * 40,
        "deadbeef" * 5,        # 40 hex, but a repeated placeholder token
        "deadbeef" * 8,        # 64 hex, same
        "ab" * 20,
        "0123" * 10,
    ],
)
def test_placeholder_digests_are_refused(kanban_home, placeholder):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="placeholder sha")
        park(conn, task_id, "ready_for_push")
        with pytest.raises(kb.OwnerConfirmMetadataError) as exc:
            kb.request_owner_confirm(
                conn, task_id,
                **gate_request(
                    artifact_sha=placeholder,
                    evidence=owner_evidence(placeholder),
                ),
            )
    assert "placeholder" in str(exc.value)


@pytest.mark.parametrize(
    "bad_sha",
    ["  ", "g" * 40, GOOD_SOURCE_SHA[:-1] + "z", "0x" + GOOD_SOURCE_SHA[2:], None, 12345],
)
def test_non_hex_artifact_sha_is_refused(kanban_home, bad_sha):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="non-hex sha")
        park(conn, task_id, "ready_for_push")
        with pytest.raises(kb.OwnerConfirmMetadataError):
            kb.request_owner_confirm(
                conn, task_id, **gate_request(artifact_sha=bad_sha)
            )


def test_artifact_sha_is_normalized_before_binding(kanban_home):
    """Case and surrounding whitespace normalize; the binding is over the
    canonical lowercase form so two spellings cannot yield two bindings."""
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="normalized sha")
        park(conn, task_id, "ready_for_push")
        payload = kb.request_owner_confirm(
            conn, task_id,
            **gate_request(
                artifact_sha=f"  {GOOD_SOURCE_SHA.upper()}  ",
                evidence=owner_evidence(GOOD_SOURCE_SHA.upper()),
            ),
        )
    assert payload["artifact_sha"] == GOOD_SOURCE_SHA
    for stage in kb.OWNER_EVIDENCE_STAGES:
        assert payload["evidence"][stage]["artifact_sha"] == GOOD_SOURCE_SHA


def test_evidence_bound_to_a_different_artifact_is_refused(kanban_home):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="mismatched evidence")
        park(conn, task_id, "ready_for_push")
        with pytest.raises(kb.OwnerConfirmMetadataError):
            kb.request_owner_confirm(
                conn, task_id,
                **gate_request(evidence=owner_evidence(GOOD_DOC_SHA)),
            )


# ---------------------------------------------------------------------------
# Blocker 5 — PII / non-disclosure
# ---------------------------------------------------------------------------

DISCLOSING_TEXTS = [
    # email
    "승인 문의는 daesan.jo@gmail.com 으로 회신 바랍니다",
    "contact ops-lead@daos-internal.co.kr before approving",
    # phone
    "담당자 연락처 010-1234-5678 입니다",
    "긴급 시 02-3456-7890 으로 연락 주세요",
    "call +82 10 1234 5678 for rollback",
    "고객센터 1588-0000 안내",
    # Korean resident registration number
    "고객 주민등록번호 900101-1234567 확인 완료",
    "신원 확인 001231-4567890 처리됨",
    # credentials / secrets
    "deploy uses api_key rotation",
    "set Authorization: Bearer for the release",
    "키 값 ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 교체",
    "AWS 키 AKIAIOSFODNN7EXAMPLE 교체 필요",
    "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0 갱신",
    "-----BEGIN RSA PRIVATE KEY-----",
    # raw filesystem paths
    "산출물은 /home/ubuntu/hermes/artifacts/ 에 있습니다",
    "로그 경로 /var/log 확인",
    "설정 파일 C:\\Program Files\\daos 확인",
    "빌드 산출물 ~/build/ 배포",
    # URLs
    "자세한 내용은 https://internal.daos.example/runbook 참고",
    "ssh://buildbox 접속 후 실행",
    # IP / host / port
    "배포 대상 10.0.12.34 입니다",
    "DB 노드 192.168.0.1 교체",
    "접속 지점 db-prod.internal 확인",
    "게이트웨이 api.daos-internal.example:8443 로 전환",
    # DB / role
    "연결 문자열 postgresql://svc@db-prod/app 사용",
    "Data Source=prod-sql;Initial Catalog=app 확인",
    "role: db_owner 권한으로 실행",
    "GRANT ALL 부여 후 배포",
    "service_account 로 실행됩니다",
    "arn:aws:iam::123456789012:role/deployer 사용",
    # internal card id (pre-existing rule, kept)
    "선행 카드 t_a6acd07d 완료 후 진행",
]


@pytest.mark.parametrize("text", DISCLOSING_TEXTS)
def test_owner_card_text_refuses_disclosure(kanban_home, text):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="disclosure")
        park(conn, task_id, "ready_for_push")
        before_events = event_rows(conn, task_id)

        with pytest.raises(kb.OwnerConfirmMetadataError) as exc:
            kb.request_owner_confirm(
                conn, task_id, **gate_request(card=owner_card(why=text))
            )

        message = str(exc.value)
        # Sanitized error: names the field and the category, never echoes the
        # offending value back into logs or the API response body.
        assert message.startswith("card.why")
        assert text not in message
        for fragment in text.split():
            if len(fragment) > 6:
                assert fragment not in message
        assert event_rows(conn, task_id) == before_events


@pytest.mark.parametrize("text", DISCLOSING_TEXTS)
def test_evidence_summary_refuses_disclosure(kanban_home, text):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="evidence disclosure")
        park(conn, task_id, "ready_for_push")
        evidence = owner_evidence()
        evidence["tested"]["summary"] = text

        with pytest.raises(kb.OwnerConfirmMetadataError) as exc:
            kb.request_owner_confirm(
                conn, task_id, **gate_request(evidence=evidence)
            )

        assert str(exc.value).startswith("evidence.tested.summary")
        assert text not in str(exc.value)


ORDINARY_BUSINESS_TEXTS = [
    "고객사 요청으로 검색 품질 개선 릴리스를 진행합니다",
    "매출 3,000,000원 규모의 계약 건 종결 보고",
    "2026-08-02 출시 예정, 되돌리기 절차 준비 완료",
    "A/B 테스트 결과 전환율 12.4% 개선",
    "CI/CD 파이프라인 정비 후 재배포",
    "Q3 목표 대비 진척률 87% 달성",
    "리뷰 2건, 지적 사항 0건으로 승인 권장",
    "This release changes customer-visible ranking behaviour only",
    "Rollback is a one-command revert to the previous tag",
    "Benchmark accuracy moved from 91.2 to 93.8 across 240 queries",
    "운영 정책 변경: 다운로드 승인 절차를 2단계로 조정",
    "v1.2.3.4 빌드 기준으로 검증했습니다",
    "근무 시간 09:00-18:00 기준으로 배포 창을 잡았습니다",
    "docs/adr/0007-owner-confirm.md 에 결정 배경을 정리했습니다",
    "P/L 개선 효과는 다음 분기부터 반영됩니다",
    "파트너사 3곳과 협의 완료, 이슈 없음",
    "Impact: 40% fewer support tickets, measured over 2 weeks",
]


@pytest.mark.parametrize("text", ORDINARY_BUSINESS_TEXTS)
def test_ordinary_business_text_is_accepted(kanban_home, text):
    """No broad false positives on ordinary Korean/English business prose."""
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="ordinary text")
        park(conn, task_id, "ready_for_push")
        payload = kb.request_owner_confirm(
            conn, task_id, **gate_request(card=owner_card(why=text))
        )
    assert payload["card"]["why"] == " ".join(text.split())


def test_evidence_refs_stay_bounded_and_reauthorization_oriented(kanban_home):
    """Evidence carries allowlisted handles, never inline detail or a URL."""
    assert set(kb.OWNER_EVIDENCE_REF_SCHEMES) == {
        "task", "run", "event", "attachment", "commit", "doc",
    }
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="evidence refs")
        park(conn, task_id, "ready_for_push")
        for bad_ref in (
            "https://internal.example/run/1",
            "/var/log/run.log",
            "file:./run.log",
            "run:" + "x" * 200,
            "run:has spaces",
            "notascheme:1",
        ):
            evidence = owner_evidence()
            evidence["tested"]["ref"] = bad_ref
            with pytest.raises(kb.OwnerConfirmMetadataError):
                kb.request_owner_confirm(
                    conn, task_id, **gate_request(evidence=evidence)
                )


def test_reject_reason_is_scrubbed(kanban_home):
    with kb.connect() as conn:
        task_id = gated_task(conn)
        recorded = kb.latest_owner_confirm_request(conn, task_id)
        with pytest.raises(kb.OwnerConfirmMetadataError) as exc:
            kb.owner_decide(
                conn, task_id,
                decision="reject",
                expected_status="ready_for_push",
                binding=recorded["binding"],
                reason="담당자 010-1234-5678 에게 확인 후 재요청",
            )
        assert "010-1234-5678" not in str(exc.value)
        assert kb.get_task(conn, task_id).status == "ready_for_push"


# ---------------------------------------------------------------------------
# Blocker 3 — atomicity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "gate", ["ready_for_push", "ready_for_deploy", "owner_confirm_required"]
)
def test_generic_block_cannot_escape_a_typed_owner_gate(kanban_home, gate):
    """Exact reviewed exploit: gate -> block -> unblock -> claim stays closed."""
    kinds = {
        "ready_for_push": "product_release",
        "ready_for_deploy": "product_release",
        "owner_confirm_required": "customer_report",
    }
    with kb.connect() as conn:
        task_id = gated_task(conn, status=gate, oc_kind=kinds[gate])
        before_events = event_rows(conn, task_id)

        assert kb.block_task(conn, task_id, reason="generic escape") is False
        assert kb.get_task(conn, task_id).status == gate
        assert kb.unblock_task(conn, task_id) is False
        assert kb.claim_task(conn, task_id) is None
        assert kb.get_task(conn, task_id).status == gate
        assert event_rows(conn, task_id) == before_events


def test_unblock_cannot_ready_a_blocked_card_with_owner_audit(kanban_home):
    """Defense in depth also protects legacy/corrupt blocked owner-audit rows."""
    with kb.connect() as conn:
        task_id = gated_task(conn)
        conn.execute("UPDATE tasks SET status = 'blocked' WHERE id = ?", (task_id,))
        before_events = event_rows(conn, task_id)

        assert kb.unblock_task(conn, task_id) is False
        assert kb.get_task(conn, task_id).status == "blocked"
        assert event_rows(conn, task_id) == before_events


@pytest.mark.parametrize(
    "broken",
    [
        {"card": owner_card(why="")},
        {"card": {"why": "짧음"}},
        {"card": owner_card(extra="not allowed")},
        {"evidence": {"implemented": owner_evidence()["implemented"]}},
        {"evidence": "not-an-object"},
        {"oc_kind": "source_change"},
        {"oc_kind": "not_in_the_allowlist"},
        {"destination": ""},
        {"rollback": "카드와 다른 롤백 설명"},
        {"artifact_kind": "made_up_kind"},
        {"requested_at": True},
        {"requested_at": -1},
    ],
)
def test_malformed_ask_leaves_task_byte_for_byte_unchanged(kanban_home, broken):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="atomic ask")
        park(conn, task_id, "ready_for_push")
        before_task = task_row(conn, task_id)
        before_events = event_rows(conn, task_id)

        with pytest.raises((kb.OwnerConfirmMetadataError, kb.OwnerConfirmStateError)):
            kb.request_owner_confirm(conn, task_id, **gate_request(**broken))

        assert task_row(conn, task_id) == before_task
        assert event_rows(conn, task_id) == before_events


def test_supersede_is_atomic_when_the_new_ask_is_malformed(kanban_home):
    """A confirmed card must not be knocked back to the gate by an ask that
    then fails validation — the status flip and the event are one unit."""
    with kb.connect() as conn:
        task_id = gated_task(conn)
        recorded = kb.latest_owner_confirm_request(conn, task_id)
        kb.owner_decide(
            conn, task_id,
            decision="approve",
            expected_status="ready_for_push",
            binding=recorded["binding"],
        )
        assert kb.get_task(conn, task_id).status == kb.OWNER_CONFIRMED_STATUS
        before_task = task_row(conn, task_id)
        before_events = event_rows(conn, task_id)

        with pytest.raises(kb.OwnerConfirmMetadataError):
            kb.request_owner_confirm(
                conn, task_id, **gate_request(artifact_sha="deadbee")
            )

        assert task_row(conn, task_id) == before_task
        assert event_rows(conn, task_id) == before_events


# ---------------------------------------------------------------------------
# Blocker 2 — destruction / audit preservation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "gate", ["ready_for_push", "ready_for_deploy", "owner_confirm_required"]
)
def test_delete_refuses_a_card_sitting_in_a_typed_gate(kanban_home, gate):
    kinds = {
        "ready_for_push": "product_release",
        "ready_for_deploy": "product_release",
        "owner_confirm_required": "customer_report",
    }
    with kb.connect() as conn:
        task_id = gated_task(conn, status=gate, oc_kind=kinds[gate])
        assert kb.owner_delete_locked(conn, task_id) is not None

        assert kb.delete_task(conn, task_id) is False

        assert kb.get_task(conn, task_id) is not None
        assert any(
            k == kb.OWNER_CONFIRM_REQUESTED_EVENT
            for _, k, _, _ in event_rows(conn, task_id)
        )


def test_delete_refuses_a_confirmed_card_and_keeps_the_approval(kanban_home):
    with kb.connect() as conn:
        task_id = gated_task(conn)
        recorded = kb.latest_owner_confirm_request(conn, task_id)
        kb.owner_decide(
            conn, task_id, decision="approve",
            expected_status="ready_for_push", binding=recorded["binding"],
        )

        assert kb.delete_task(conn, task_id) is False
        assert kb.get_task(conn, task_id).status == kb.OWNER_CONFIRMED_STATUS
        assert any(
            k == kb.OWNER_CONFIRMED_EVENT
            for _, k, _, _ in event_rows(conn, task_id)
        )


@pytest.mark.parametrize("decision", ["reject", "hold"])
def test_delete_refuses_any_card_with_owner_decision_history(kanban_home, decision):
    """A decided card carries audit that no generic cascade may erase."""
    with kb.connect() as conn:
        task_id = gated_task(conn)
        recorded = kb.latest_owner_confirm_request(conn, task_id)
        kb.owner_decide(
            conn, task_id, decision=decision,
            expected_status="ready_for_push", binding=recorded["binding"],
            reason="추가 근거가 필요합니다",
        )
        # Move the card well away from any gate status: the protection must
        # follow the audit history, not the current column.
        park(conn, task_id, "todo")
        assert kb.has_owner_decision_history(conn, task_id) is True

        assert kb.delete_task(conn, task_id) is False
        assert kb.get_task(conn, task_id) is not None
        kinds = [k for _, k, _, _ in event_rows(conn, task_id)]
        assert kb.OWNER_REJECTED_EVENT in kinds or kb.OWNER_HOLD_EVENT in kinds


def test_delete_archived_task_refuses_owner_decision_history(kanban_home):
    """Archive-then-delete must not become the laundering route for audit."""
    with kb.connect() as conn:
        task_id = gated_task(conn)
        recorded = kb.latest_owner_confirm_request(conn, task_id)
        kb.owner_decide(
            conn, task_id, decision="reject",
            expected_status="ready_for_push", binding=recorded["binding"],
            reason="근거 부족",
        )
        # A rejected card is ordinary blocked work and stays archivable —
        # archiving preserves every event row.
        assert kb.archive_task(conn, task_id) is True

        assert kb.delete_archived_task(conn, task_id) is False
        assert kb.get_task(conn, task_id) is not None
        assert any(
            k == kb.OWNER_REJECTED_EVENT
            for _, k, _, _ in event_rows(conn, task_id)
        )


@pytest.mark.parametrize(
    "gate", ["ready_for_push", "ready_for_deploy", "owner_confirm_required"]
)
def test_archive_refuses_a_card_awaiting_an_owner_decision(kanban_home, gate):
    kinds = {
        "ready_for_push": "product_release",
        "ready_for_deploy": "product_release",
        "owner_confirm_required": "customer_report",
    }
    with kb.connect() as conn:
        task_id = gated_task(conn, status=gate, oc_kind=kinds[gate])
        assert kb.owner_archive_locked(conn, task_id) is not None
        assert kb.archive_task(conn, task_id) is False
        assert kb.get_task(conn, task_id).status == gate


def test_archive_refuses_a_confirmed_card(kanban_home):
    with kb.connect() as conn:
        task_id = gated_task(conn)
        recorded = kb.latest_owner_confirm_request(conn, task_id)
        kb.owner_decide(
            conn, task_id, decision="approve",
            expected_status="ready_for_push", binding=recorded["binding"],
        )
        assert kb.archive_task(conn, task_id) is False
        assert kb.get_task(conn, task_id).status == kb.OWNER_CONFIRMED_STATUS


def test_delete_still_works_for_an_ordinary_card(kanban_home):
    """The guard is targeted — it must not freeze the whole board."""
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="ordinary")
        assert kb.owner_delete_locked(conn, task_id) is None
        assert kb.delete_task(conn, task_id) is True
        assert kb.get_task(conn, task_id) is None


def test_gc_events_never_prunes_owner_decision_audit(kanban_home):
    """The pre-existing 30-day event GC must step over owner-gate rows."""
    with kb.connect() as conn:
        task_id = gated_task(conn)
        recorded = kb.latest_owner_confirm_request(conn, task_id)
        kb.owner_decide(
            conn, task_id, decision="reject",
            expected_status="ready_for_push", binding=recorded["binding"],
            reason="근거 부족",
        )
        park(conn, task_id, "archived")
        conn.execute("UPDATE task_events SET created_at = 0 WHERE task_id = ?", (task_id,))
        conn.commit()

        kb.gc_events(conn, older_than_seconds=1)

        kinds = {k for _, k, _, _ in event_rows(conn, task_id)}
        assert kb.OWNER_CONFIRM_REQUESTED_EVENT in kinds
        assert kb.OWNER_REJECTED_EVENT in kinds


def test_rejected_card_is_not_auto_promoted_back_to_ready(kanban_home):
    """recompute_ready must not silently undo an owner rejection.

    Without this the dispatcher picks the card back up on the next tick and
    the rejection becomes advisory.
    """
    with kb.connect() as conn:
        task_id = gated_task(conn)
        recorded = kb.latest_owner_confirm_request(conn, task_id)
        kb.owner_decide(
            conn, task_id, decision="reject",
            expected_status="ready_for_push", binding=recorded["binding"],
            reason="근거 부족",
        )
        assert kb.get_task(conn, task_id).status == "blocked"

        kb.recompute_ready(conn)

        assert kb.get_task(conn, task_id).status == "blocked"
        assert kb.claim_task(conn, task_id) is None


# ---------------------------------------------------------------------------
# Blocker 1 — the exact-action execution path
# ---------------------------------------------------------------------------


def approved(conn, *, gate: str = "ready_for_push", oc_kind: str = "product_release"):
    task_id = gated_task(conn, status=gate, oc_kind=oc_kind)
    recorded = kb.latest_owner_confirm_request(conn, task_id)
    approval = kb.owner_decide(
        conn, task_id, decision="approve",
        expected_status=gate, binding=recorded["binding"],
    )
    return task_id, approval


@pytest.mark.parametrize(
    "gate,oc_kind,expected",
    [
        ("ready_for_push", "product_release", "integrating"),
        ("ready_for_deploy", "product_release", "done"),
        ("owner_confirm_required", "customer_report", "done"),
    ],
)
def test_execution_advances_a_confirmed_card_along_its_exact_gate(
    kanban_home, gate, oc_kind, expected
):
    with kb.connect() as conn:
        task_id, approval = approved(conn, gate=gate, oc_kind=oc_kind)

        record = kb.execute_owner_confirmed(
            conn, task_id,
            binding=approval["binding"],
            gate_type=approval["gate_type"],
            artifact_sha=approval["artifact_sha"],
            outcome="performed",
        )

        assert kb.get_task(conn, task_id).status == expected
        assert record["outcome"] == "performed"
        assert record["gate_status"] == gate
        assert any(
            k == kb.OWNER_EXECUTION_EVENT for _, k, _, _ in event_rows(conn, task_id)
        )


def test_execution_failure_routes_to_blocked_not_forward(kanban_home):
    with kb.connect() as conn:
        task_id, approval = approved(conn)

        kb.execute_owner_confirmed(
            conn, task_id,
            binding=approval["binding"],
            gate_type=approval["gate_type"],
            artifact_sha=approval["artifact_sha"],
            outcome="failed",
            note="푸시 중 충돌로 중단",
        )

        task = kb.get_task(conn, task_id)
        assert task.status == "blocked"
        assert task.block_kind == kb.OWNER_REJECT_BLOCK_KIND


@pytest.mark.parametrize(
    "kwargs",
    [
        {"binding": "0" * 64},
        {"gate_type": "deploy"},
        {"artifact_sha": GOOD_DOC_SHA},
        {"outcome": "partially"},
    ],
)
def test_execution_refuses_anything_but_the_exact_approved_action(kanban_home, kwargs):
    with kb.connect() as conn:
        task_id, approval = approved(conn)
        args = {
            "binding": approval["binding"],
            "gate_type": approval["gate_type"],
            "artifact_sha": approval["artifact_sha"],
            "outcome": "performed",
        }
        args.update(kwargs)
        before_task = task_row(conn, task_id)
        before_events = event_rows(conn, task_id)

        with pytest.raises((kb.OwnerConfirmMetadataError, kb.OwnerConfirmStateError)):
            kb.execute_owner_confirmed(conn, task_id, **args)

        assert task_row(conn, task_id) == before_task
        assert event_rows(conn, task_id) == before_events


@pytest.mark.parametrize(
    "status", ["ready_for_push", "ready", "review", "done", "blocked"]
)
def test_execution_refuses_a_card_that_was_never_confirmed(kanban_home, status):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="not confirmed")
        park(conn, task_id, status)
        with pytest.raises(kb.OwnerConfirmStateError):
            kb.execute_owner_confirmed(
                conn, task_id,
                binding="0" * 64, gate_type="push",
                artifact_sha=GOOD_SOURCE_SHA, outcome="performed",
            )
        assert kb.get_task(conn, task_id).status == status


def test_execution_cannot_be_replayed(kanban_home):
    with kb.connect() as conn:
        task_id, approval = approved(conn)
        kb.execute_owner_confirmed(
            conn, task_id,
            binding=approval["binding"], gate_type=approval["gate_type"],
            artifact_sha=approval["artifact_sha"], outcome="performed",
        )
        with pytest.raises(kb.OwnerConfirmStateError):
            kb.execute_owner_confirmed(
                conn, task_id,
                binding=approval["binding"], gate_type=approval["gate_type"],
                artifact_sha=approval["artifact_sha"], outcome="performed",
            )


def test_confirmed_status_is_never_claimable(kanban_home):
    with kb.connect() as conn:
        task_id, _ = approved(conn)
        assert kb.claim_task(conn, task_id) is None
        assert kb.claim_review_task(conn, task_id) is None
        assert kb.get_task(conn, task_id).status == kb.OWNER_CONFIRMED_STATUS


def test_execution_note_is_scrubbed(kanban_home):
    with kb.connect() as conn:
        task_id, approval = approved(conn)
        with pytest.raises(kb.OwnerConfirmMetadataError):
            kb.execute_owner_confirmed(
                conn, task_id,
                binding=approval["binding"], gate_type=approval["gate_type"],
                artifact_sha=approval["artifact_sha"], outcome="failed",
                note="실패 로그는 /var/log/hermes/push.log 참고",
            )
        assert kb.get_task(conn, task_id).status == kb.OWNER_CONFIRMED_STATUS


def test_execution_payload_carries_no_free_form_fields(kanban_home):
    with kb.connect() as conn:
        task_id, approval = approved(conn)
        record = kb.execute_owner_confirmed(
            conn, task_id,
            binding=approval["binding"], gate_type=approval["gate_type"],
            artifact_sha=approval["artifact_sha"], outcome="performed",
        )
        stored = json.loads(
            [p for _, k, p, _ in event_rows(conn, task_id)
             if k == kb.OWNER_EXECUTION_EVENT][-1]
        )
        assert set(stored) <= set(kb.OWNER_EXECUTION_PAYLOAD_FIELDS)
        assert set(record) <= set(kb.OWNER_EXECUTION_PAYLOAD_FIELDS)
