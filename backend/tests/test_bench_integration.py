import asyncio
import json
import os
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import uvicorn
from sqlalchemy import create_engine

from app import config
from app.bench import runner, traffic
from app.db import base, lab_base
from app.db.base import Base
from app.db.lab_base import LabBase
from app.db.models import User
from app.security.passwords import hash_password
from app.services.baseline_store import store
from app.ws.manager import manager
from app.ws.session_coordinator import coordinator


pytestmark = pytest.mark.skipif(os.getenv("CC_SKIP_INTEGRATION") == "1", reason="CC_SKIP_INTEGRATION=1")


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_started(server, thread):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and thread.is_alive():
        if server.started: return
        time.sleep(.05)
    raise RuntimeError("uvicorn failed to start")


@pytest.mark.integration
def test_real_uvicorn_benchmark_and_traffic(tmp_path, monkeypatch):
    old_app_engine, old_lab_engine = base.engine, lab_base.engine
    app_file, lab_file = tmp_path / "integration-app.db", tmp_path / "integration-lab.db"
    app_engine = create_engine(f"sqlite:///{app_file}", connect_args={"check_same_thread": False})
    lab_engine = create_engine(f"sqlite:///{lab_file}", connect_args={"check_same_thread": False})
    base.set_engine_and_session(app_engine); lab_base.set_lab_engine_and_session(lab_engine)
    Base.metadata.create_all(bind=app_engine); LabBase.metadata.create_all(bind=lab_engine)
    monkeypatch.setattr(config, "ALLOW_PLAINTEXT_BASELINE", True)
    monkeypatch.setattr(config, "BASELINE_TTL_SECONDS", 60)
    monkeypatch.setenv("CC_BENCH_PASS_A", "BenchPass123")
    monkeypatch.setenv("CC_BENCH_PASS_B", "BenchPass123")
    store._items.clear(); store._audited_sessions.clear()
    manager._users.clear(); manager._ws_to_user.clear()
    coordinator.active_session_id = None; coordinator.initiator = None; coordinator.responder = None
    coordinator.status = "none"
    with base.SessionLocal() as db:
        db.add(User(username="analyst", username_norm="analyst", password_hash=hash_password("Analyst123"), role="analyst"))
        db.commit()

    from app.main import create_app
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="critical", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        _wait_started(server, thread)
        base_url = f"http://127.0.0.1:{port}"
        # Redirect all task artifacts into pytest's configured basetemp.
        bench_root = tmp_path / "client-output"; (bench_root / "app" / "bench").mkdir(parents=True)
        monkeypatch.setattr(runner, "__file__", str(bench_root / "app" / "bench" / "runner.py"))
        monkeypatch.setattr(traffic, "__file__", str(bench_root / "app" / "bench" / "traffic.py"))
        result = asyncio.run(runner.run_benchmark(base_url, "bench_a", "bench_b", "BenchPass123", "BenchPass123",
            repeats=2, warmup=1, handshakes=2, text_lengths=(16,256), image_sides=(16,64),
            label="integration", no_post=False, analyst="analyst", analyst_password="Analyst123"))
        assert Path(result["path"]).is_file()
        assert len(result["run"]["handshake_ms"]) == 2
        samples = result["run"]["samples"]
        assert len(samples) == 16
        assert {s["mode"] for s in samples} == {"secure", "plain"}
        for sample in samples:
            assert abs(sum(sample[k] for k in ("crypto_send_ms", "to_notify_ms", "fetch_ms", "crypto_recv_ms")) - sample["e2e_ms"]) <= .01
            assert (sample["verify_post_ms"] is not None) == (sample["mode"] == "secure")
        assert all(next(s["bytes_up"] for s in samples if s["kind"] == "text" and s["size_param"] == n and s["mode"] == "secure") >
                   next(s["bytes_up"] for s in samples if s["kind"] == "text" and s["size_param"] == n and s["mode"] == "plain") for n in (16,256))
        with lab_base.LabSessionLocal() as db:
            from app.db.lab_models import BenchRun, BenchSample
            stored = db.query(BenchRun).one()
            assert stored.id and len(stored.handshake_ms) == 2
            assert db.query(BenchSample).filter(BenchSample.run_id == stored.id).count() == 16

        for mode in ("secure", "plain"):
            args = SimpleNamespace(server=base_url, mode=mode, messages=3, marker="SECRETWORD123", pause_ms=1,
                with_images=True, user_a="bench_a", user_b="bench_b", label=f"{mode}case")
            asyncio.run(traffic.run(args))
            sidecars = list((bench_root / "data" / "bench").glob(f"traffic_{mode}_*.json"))
            assert sidecars
            metadata = json.loads(sidecars[-1].read_text(encoding="utf-8"))
            assert metadata["mode"] == mode and metadata["marker"] == "SECRETWORD123"
            assert metadata["messages"] == 3 and metadata["with_images"] is True
            assert metadata["started_at_utc"].endswith("Z") and metadata["ended_at_utc"].endswith("Z")
        time.sleep(.1)
        db_bytes = b""
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(app_file) + suffix)
            if candidate.exists(): db_bytes += candidate.read_bytes()
        assert b"SECRETWORD123" not in db_bytes
        assert b"BASELINE_PLAINTEXT_USED" in db_bytes
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        app_engine.dispose(); lab_engine.dispose()
        base.set_engine_and_session(old_app_engine); lab_base.set_lab_engine_and_session(old_lab_engine)
