"""Tests for kanban lifecycle plugin hooks.

Verifies that claim/complete/block transitions fire the
kanban_task_claimed / kanban_task_completed / kanban_task_blocked plugin
hooks AFTER the board DB change is committed, with the documented kwargs,
and that a misbehaving hook callback never breaks the transition.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli.plugins import VALID_HOOKS, get_plugin_manager


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


@pytest.fixture
def captured_hooks(monkeypatch):
    """Register capturing callbacks for the three kanban lifecycle hooks.

    Patches the plugin manager's _hooks dict directly (the same registry
    invoke_hook reads) and restores it afterward.
    """
    mgr = get_plugin_manager()
    events: list[tuple[str, dict]] = []
    saved = {k: list(v) for k, v in mgr._hooks.items()}
    for hook in ("kanban_task_claimed", "kanban_task_completed", "kanban_task_blocked"):
        mgr._hooks.setdefault(hook, []).append(
            lambda _h=hook, **kw: events.append((_h, kw))
        )
    try:
        yield events
    finally:
        mgr._hooks = saved


def test_hooks_are_registered_as_valid():
    """The three lifecycle hook names are part of VALID_HOOKS."""
    assert "kanban_task_claimed" in VALID_HOOKS
    assert "kanban_task_completed" in VALID_HOOKS
    assert "kanban_task_blocked" in VALID_HOOKS


def test_claim_fires_hook(kanban_home, captured_hooks):
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="t", assignee="worker")
        claimed = kb.claim_task(conn, tid)
        assert claimed is not None
    finally:
        conn.close()
    fired = [e for e in captured_hooks if e[0] == "kanban_task_claimed"]
    assert len(fired) == 1
    kw = fired[0][1]
    assert kw["task_id"] == tid
    assert kw["assignee"] == "worker"
    assert "profile_name" in kw
    assert kw["run_id"] is not None


def test_complete_fires_hook_with_summary(kanban_home, captured_hooks):
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="t", assignee="worker")
        kb.claim_task(conn, tid)
        assert kb.complete_task(conn, tid, summary="all done")
    finally:
        conn.close()
    fired = [e for e in captured_hooks if e[0] == "kanban_task_completed"]
    assert len(fired) == 1
    kw = fired[0][1]
    assert kw["task_id"] == tid
    assert kw["summary"] == "all done"
    assert kw["assignee"] == "worker"


def test_block_fires_hook_with_reason(kanban_home, captured_hooks):
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="t", assignee="worker")
        kb.claim_task(conn, tid)
        assert kb.block_task(conn, tid, reason="needs human")
    finally:
        conn.close()
    fired = [e for e in captured_hooks if e[0] == "kanban_task_blocked"]
    assert len(fired) == 1
    kw = fired[0][1]
    assert kw["task_id"] == tid
    assert kw["reason"] == "needs human"


def test_no_hook_on_failed_transition(kanban_home, captured_hooks):
    """complete_task on an unclaimed/nonexistent task fires no hook."""
    conn = kb.connect()
    try:
        # Completing a task that doesn't exist returns False without firing.
        assert kb.complete_task(conn, "t_doesnotexist", summary="x") is False
    finally:
        conn.close()
    assert [e for e in captured_hooks if e[0] == "kanban_task_completed"] == []


def test_misbehaving_hook_does_not_break_transition(kanban_home, monkeypatch):
    """A hook callback that raises must not break the board transition."""
    mgr = get_plugin_manager()
    saved = {k: list(v) for k, v in mgr._hooks.items()}

    def _boom(**kw):
        raise RuntimeError("plugin exploded")

    mgr._hooks.setdefault("kanban_task_completed", []).append(_boom)
    try:
        conn = kb.connect()
        try:
            tid = kb.create_task(conn, title="t", assignee="worker")
            kb.claim_task(conn, tid)
            # Despite the raising hook, completion succeeds and persists.
            assert kb.complete_task(conn, tid, summary="ok") is True
            assert kb.get_task(conn, tid).status == "done"
        finally:
            conn.close()
    finally:
        mgr._hooks = saved


def test_nested_completion_side_effects_are_discarded_on_outer_rollback(
    kanban_home, captured_hooks
):
    """A sibling failure after complete cannot delete scratch or publish hooks."""
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="atomic", assignee="worker")
        task = kb.get_task(conn, tid)
        workspace = kb.resolve_workspace(task)
        kb.set_workspace_path(conn, tid, workspace)
        before_events = [(e.kind, e.payload) for e in kb.list_events(conn, tid)]

        with pytest.raises(RuntimeError, match="late sibling failure"):
            with kb.write_txn(conn):
                assert kb.complete_task(conn, tid, summary="not durable yet")
                raise RuntimeError("late sibling failure")

        assert kb.get_task(conn, tid).status == "ready"
        assert [(e.kind, e.payload) for e in kb.list_events(conn, tid)] == before_events
        assert workspace.exists()
        assert [e for e in captured_hooks if e[0] == "kanban_task_completed"] == []
    finally:
        conn.close()


def test_nested_completion_side_effects_run_once_after_outer_commit(
    kanban_home, captured_hooks
):
    """Successful outermost commit drains each irreversible callback once."""
    conn = kb.connect()
    try:
        tid = kb.create_task(conn, title="atomic success", assignee="worker")
        task = kb.get_task(conn, tid)
        workspace = kb.resolve_workspace(task)
        kb.set_workspace_path(conn, tid, workspace)

        with kb.write_txn(conn):
            assert kb.complete_task(conn, tid, summary="durable")
            assert workspace.exists(), "cleanup must not run before COMMIT"
            assert [e for e in captured_hooks if e[0] == "kanban_task_completed"] == []

        assert not workspace.exists()
        fired = [e for e in captured_hooks if e[0] == "kanban_task_completed"]
        assert len(fired) == 1
        assert fired[0][1]["task_id"] == tid
    finally:
        conn.close()


def test_after_commit_queues_are_connection_scoped(kanban_home, tmp_path):
    """A second connection cannot drain or discard the first connection's queue."""
    first = kb.connect()
    second = kb.connect(db_path=tmp_path / "second-kanban.db")
    fired = []
    try:
        with pytest.raises(RuntimeError, match="rollback first"):
            with kb.write_txn(first):
                kb.run_after_commit(first, fired.append, "first")
                with kb.write_txn(second):
                    kb.run_after_commit(second, fired.append, "second")
                assert fired == ["second"]
                raise RuntimeError("rollback first")
        assert fired == ["second"]

        with kb.write_txn(first):
            kb.run_after_commit(first, fired.append, "first-committed")
        assert fired == ["second", "first-committed"]
    finally:
        first.close()
        second.close()
