import importlib.util
import json
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "systemd" / "gateway_health.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("daos_gateway_health", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _runtime(tmp_path: Path, *, state="running", pid=42, cmd=b"python\0-m\0hermes_cli.main\0gateway\0run\0"):
    state_path = tmp_path / "gateway_state.json"
    state_path.write_text(json.dumps({
        "gateway_state": state,
        "pid": pid,
        "active_agents": 2,
        "platforms": {"slack": {"state": "connected", "token": "must-not-leak"}},
        "updated_at": "2026-08-11T16:51:01+00:00",
    }))
    proc = tmp_path / "proc" / str(pid)
    proc.mkdir(parents=True)
    (proc / "cmdline").write_bytes(cmd)
    return state_path, tmp_path / "proc"


def test_detailed_health_accepts_live_gateway_and_bounds_payload(tmp_path):
    mod = _load_module()
    state_path, proc_root = _runtime(tmp_path)

    status, body = mod.gateway_health(state_path=state_path, proc_root=proc_root)

    assert status == 200
    assert body == {
        "status": "ok",
        "gateway_state": "running",
        "pid": 42,
        "active_agents": 2,
        "platforms": {"slack": {"state": "connected"}},
        "updated_at": "2026-08-11T16:51:01+00:00",
    }
    assert "token" not in json.dumps(body)


def test_health_fails_closed_for_pid_reuse(tmp_path):
    mod = _load_module()
    state_path, proc_root = _runtime(tmp_path, cmd=b"python\0unrelated.py\0")

    status, body = mod.gateway_health(state_path=state_path, proc_root=proc_root)

    assert status == 503
    assert body == {"status": "unavailable", "gateway_state": "stopped"}


def test_health_fails_closed_for_nonrunning_state(tmp_path):
    mod = _load_module()
    state_path, proc_root = _runtime(tmp_path, state="stopped")

    status, body = mod.gateway_health(state_path=state_path, proc_root=proc_root)

    assert status == 503
    assert body == {"status": "unavailable", "gateway_state": "stopped"}


def test_systemd_unit_is_private_hardened_and_bridge_scoped():
    unit = (MODULE_PATH.parent / "daos-gateway-health.service").read_text()
    assert "User=ubuntu" in unit
    assert "172.18.0.1" in unit
    assert "--port 8792" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "--dport 8792" in unit
    assert "br-a0bd2b780836" in unit
