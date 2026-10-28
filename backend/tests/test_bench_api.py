import json
from pathlib import Path

from app import config
from app.db import base, lab_base
from app.db.models import AuditLog
from app.db.lab_models import BenchRun, BenchSample
from tests.test_lab_text_metrics import _auth, scenario


def _sample(**changes):
    row = {"seq": 0, "mode": "secure", "kind": "text", "size_param": 16, "plaintext_bytes": 16,
        "crypto_send_ms": 1.0, "to_notify_ms": 2.0, "fetch_ms": 3.0, "crypto_recv_ms": 4.0,
        "e2e_ms": 10.0, "post_ms": 1.5, "verify_post_ms": 0.5,
        "bytes_up": 250, "bytes_down": 350, "ws_notify_bytes": 100}
    return {**row, **changes}


def _run(**changes):
    result = {"label": "pytest bench", "repeats": 1, "warmup": 0, "text_lengths": [16],
        "image_sides": [16], "handshake_ms": [12.5], "note": None, "samples": [_sample()]}
    return {**result, **changes}


def _walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value: yield from _walk_keys(child)


def test_bench_api_auth_storage_strictness_limits_and_audits(scenario):
    client = scenario["client"]
    url = "/api/dashboard/bench/runs"
    assert client.get(url).status_code == 401
    assert client.get(url, headers=_auth(scenario["alice"])).status_code == 403
    assert client.post(url, json=_run()).status_code == 401
    assert client.post(url, json=_run(), headers=_auth(scenario["alice"])).status_code == 403

    created = client.post(url, json=_run(), headers=_auth(scenario["analyst"]))
    assert created.status_code == 201, created.text
    run_id = created.json()["id"]
    listing = client.get(url, headers=_auth(scenario["analyst"]))
    assert listing.status_code == 200 and listing.json()["items"][0]["id"] == run_id
    detail = client.get(f"{url}/{run_id}", headers=_auth(scenario["analyst"]))
    assert detail.status_code == 200 and len(detail.json()["samples"]) == 1
    assert not {"ct", "iv", "hmac", "key"}.intersection(_walk_keys(detail.json()))
    assert client.get(f"{url}/999999", headers=_auth(scenario["analyst"])).status_code == 404
    assert client.get(f"{url}?limit=201", headers=_auth(scenario["analyst"])).status_code == 422
    assert client.get(f"{url}?limit=2", headers=_auth(scenario["analyst"])).status_code == 200

    bad_requests = [
        {**_run(), "extra": 1},
        _run(repeats="1"),
        _run(handshake_ms=[float("nan")]),
        _run(label="illegal/$"),
        _run(samples=[_sample(mode="invalid")]),
        _run(samples=[_sample(size_param=2001)]),
        _run(samples=[_sample(e2e_ms=600001.0)]),
        _run(samples=[_sample(bytes_up=5_000_001)]),
        _run(samples=[_sample(mode="plain")]),
        _run(samples=[_sample(verify_post_ms=None)]),
        _run(samples=[_sample(kind="image", size_param=513)]),
        _run(samples=[{"seq":0,"mode":"secure","kind":"text","size_param":1,"plaintext_bytes":0,
            "crypto_send_ms":0.0,"to_notify_ms":0.0,"fetch_ms":0.0,"crypto_recv_ms":0.0,"e2e_ms":0.0,
            "post_ms":0.0,"verify_post_ms":0.0,"bytes_up":0,"bytes_down":0,"ws_notify_bytes":0}] * 2001),
    ]
    for body in bad_requests:
        headers = _auth(scenario["analyst"])
        if any(isinstance(value, float) and value != value for value in body.get("handshake_ms", [])):
            response = client.post(url, content=json.dumps(body, allow_nan=True), headers={**headers, "Content-Type":"application/json"})
        else:
            response = client.post(url, json=body, headers=headers)
        assert response.status_code == 400, (body, response.status_code, response.text)
    too_big = client.post(url, content=b" " * 512_001, headers={**_auth(scenario["analyst"]), "Content-Type":"application/json"})
    assert too_big.status_code == 413

    with lab_base.LabSessionLocal() as db:
        assert db.query(BenchRun).count() == 1
        assert db.query(BenchSample).count() == 1
    with base.SessionLocal() as db:
        assert db.query(AuditLog).filter(AuditLog.event_type == "BENCH_RUN_RECORDED").count() == 1
        rejected = db.query(AuditLog).filter(AuditLog.event_type == "METRICS_REJECTED").all()
        assert rejected and all(set((row.details or {})) == {"reason"} for row in rejected)

    cleared = client.delete(url, headers=_auth(scenario["analyst"]))
    assert cleared.status_code == 200 and "deleted" in cleared.json()
    with lab_base.LabSessionLocal() as db:
        assert db.query(BenchRun).count() == db.query(BenchSample).count() == 0
    with base.SessionLocal() as db:
        assert db.query(AuditLog).filter(AuditLog.event_type == "LAB_DATA_CLEARED", AuditLog.details["table"].as_string() == "bench").count() == 1


def test_handshake_endpoint_and_import_boundaries(scenario):
    client = scenario["client"]
    response = client.get("/api/dashboard/perf/handshakes", headers=_auth(scenario["analyst"]))
    assert response.status_code == 200 and response.json()["items"]
    assert client.get("/api/dashboard/perf/handshakes").status_code == 401
    before = len(scenario["client"].get("/api/dashboard/logs?limit=500", headers=_auth(scenario["analyst"])).json()["items"])
    client.get("/api/dashboard/perf/handshakes?limit=1000", headers=_auth(scenario["analyst"]))
    after = len(scenario["client"].get("/api/dashboard/logs?limit=500", headers=_auth(scenario["analyst"])).json()["items"])
    assert before == after
    item = response.json()["items"][0]
    assert set(item) == {"id", "ts", "session_id", "handshake_ms", "initiator", "responder", "initiator_keygen_ms", "initiator_derive_ms", "responder_keygen_ms", "responder_derive_ms"}
    app_dir = Path(__file__).resolve().parents[1] / "app"
    for folder in ("routers", "ws", "services", "db"):
        for file in (app_dir / folder).rglob("*.py"):
            assert "app.bench" not in file.read_text(encoding="utf-8"), file
    bench_dir = app_dir / "bench"
    for file in bench_dir.rglob("*.py"):
        source = file.read_text(encoding="utf-8").lower()
        assert "sqlite3" not in source and "sqlalchemy" not in source, file
