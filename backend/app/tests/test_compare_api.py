import base64
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

pytest_plugins = ["app.tests.compare_fixtures"]

from app.db import lab_base
from app.db import base
from app.db.lab_models import CompareExchange, CompareRun, CompareTrial
from app.db.models import AuditLog
from app.routers import compare as compare_router
from app.services.audit import verify_chain
from app.tests.compare_fixtures import (run_payload, secured_payload, trial_payload,
                                       unsecured_payload)

BASE = "/api/dashboard/compare"


def start(client, headers, **overrides):
    response = client.post(f"{BASE}/runs", headers=headers, json=run_payload(**overrides))
    return response


def create_complete_run(client, headers):
    run_id = start(client, headers).json()["id"]
    secured = client.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=secured_payload()).json()["id"]
    unsecured = client.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=unsecured_payload()).json()["id"]
    finalized = client.post(f"{BASE}/runs/{run_id}/finalize", headers=headers,
        json={"status": "complete", "trials": [trial_payload(secured, "secured"), trial_payload(unsecured, "unsecured")]})
    assert finalized.status_code == 200, finalized.text
    return run_id, secured, unsecured


def test_auth_lifecycle_history_restart_and_deletion(compare_client):
    c, analyst, user = compare_client["client"], compare_client["analyst"], compare_client["user"]
    paths = [("get", f"{BASE}/runs"), ("get", f"{BASE}/history"),
        ("post", f"{BASE}/runs"), ("delete", f"{BASE}/runs"),
        ("get", f"{BASE}/runs/1"), ("get", f"{BASE}/runs/1/exchanges"),
        ("get", f"{BASE}/runs/1/exchanges/1"), ("post", f"{BASE}/runs/1/exchanges"),
        ("post", f"{BASE}/runs/1/finalize"), ("post", f"{BASE}/runs/1/abort"),
        ("delete", f"{BASE}/runs/1")]
    for method, path in paths:
        assert c.request(method.upper(), path).status_code == 401
        kwargs = {"headers": user}
        if method == "post" and path == f"{BASE}/runs":
            kwargs["json"] = run_payload()
        elif method == "post" and path.endswith("/exchanges"):
            kwargs["json"] = unsecured_payload()
        elif method == "post" and path.endswith("/finalize"):
            kwargs["json"] = {"status": "complete", "trials": [trial_payload(1, "unsecured")]}
        assert c.request(method.upper(), path, **kwargs).status_code == 403
    run_id, secure_id, plain_id = create_complete_run(c, analyst)
    listed = c.get(f"{BASE}/runs", headers=analyst).json()["items"]
    assert listed[0]["id"] == run_id and listed[0]["trial_rows"] == 2
    detail = c.get(f"{BASE}/runs/{run_id}", headers=analyst).json()
    assert detail["run"]["input_text"] == "hello" and len(detail["trials"]) == 2
    history = c.get(f"{BASE}/history", headers=analyst).json()["items"]
    assert history[0]["secured_totals"] == [4.0] and history[0]["unsecured_totals"] == [4.0]
    page = c.get(f"{BASE}/runs/{run_id}/exchanges?limit=1", headers=analyst).json()
    assert len(page["items"]) == 1 and "ct" not in page["items"][0]
    secure = c.get(f"{BASE}/runs/{run_id}/exchanges/{secure_id}", headers=analyst).json()
    assert base64.b64decode(secure["ct"]) == b"c" * 16
    assert c.get(f"{BASE}/runs/{run_id}/exchanges/{plain_id}", headers=analyst).json()["text"] == "hello"
    assert c.get(f"{BASE}/runs/{run_id}/exchanges/999", headers=analyst).status_code == 404
    # A second lifespan against the same lab DB preserves completed results.
    from fastapi.testclient import TestClient
    from app.main import create_app
    with TestClient(create_app()) as restarted:
        assert restarted.get(f"{BASE}/runs/{run_id}", headers=analyst).status_code == 200
    assert c.get("/api/dashboard/summary", headers=analyst).json()["compare"]["runs"] == 1
    assert c.delete(f"{BASE}/runs/{run_id}", headers=analyst).status_code == 204
    assert c.delete(f"{BASE}/runs", headers=analyst).status_code == 204
    with lab_base.LabSessionLocal() as db:
        assert db.query(CompareRun).count() == db.query(CompareExchange).count() == db.query(CompareTrial).count() == 0


def test_stale_run_recovery_abort_and_single_running_guard(compare_client, monkeypatch):
    c, headers = compare_client["client"], compare_client["analyst"]
    fixed_now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(compare_router, "clock_now", lambda: fixed_now)
    first = start(c, headers).json()["id"]
    assert start(c, headers).status_code == 409
    with lab_base.LabSessionLocal() as db:
        db.query(CompareRun).filter(CompareRun.id == first).update({CompareRun.created_at: fixed_now - timedelta(minutes=16)})
        db.commit()
    second = start(c, headers)
    assert second.status_code == 201
    with lab_base.LabSessionLocal() as db:
        assert db.query(CompareRun).filter(CompareRun.id == first).one().status == "aborted"
    assert c.delete(f"{BASE}/runs/{second.json()['id']}", headers=headers).status_code == 409
    assert c.delete(f"{BASE}/runs", headers=headers).status_code == 409
    assert c.post(f"{BASE}/runs/{second.json()['id']}/abort", headers=headers).json()["status"] == "aborted"
    assert c.post(f"{BASE}/runs/{second.json()['id']}/abort", headers=headers).status_code == 409


def test_startup_marks_interrupted_running_run_aborted(compare_client):
    c, headers = compare_client["client"], compare_client["analyst"]
    run_id = start(c, headers).json()["id"]
    from fastapi.testclient import TestClient
    from app.main import create_app
    with TestClient(create_app()) as restarted:
        detail = restarted.get(f"{BASE}/runs/{run_id}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["run"]["status"] == "aborted"


@pytest.mark.parametrize("override", [
    {"label": "bad/label"}, {"input_text": ""}, {"trials": 0}, {"trials": 101},
    {"warmup": 11}, {"setup_keygen_ms": 0.0}, {"setup_dh_ms": 600001.0},
    {"unexpected": 1},
])
def test_run_validation(compare_client, override):
    c, headers = compare_client["client"], compare_client["analyst"]
    assert start(c, headers, **override).status_code in (400, 422)


def test_exchange_validation_caps_and_finalize_consistency(compare_client):
    c, headers = compare_client["client"], compare_client["analyst"]
    assert start(c, headers, sig_public_key_b64=base64.b64encode(b"x" * 65).decode()).status_code == 400
    run_id = start(c, headers).json()["id"]
    for payload in ({"mode": "unsecured", "text": "hello", "iv": "bad"},
                    {**secured_payload(), "text": "forbidden"},
                    {**secured_payload(), "counter": 0},
                    {**secured_payload(), "meta_json": "[]"},
                    {**secured_payload(), "iv": "***"},
                    {**secured_payload(), "ct": base64.b64encode(b"x" * 17).decode()}):
        response = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=payload)
        assert response.status_code == 400
    secured_id = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=secured_payload()).json()["id"]
    unsecured_id = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=unsecured_payload()).json()["id"]
    bad = trial_payload(secured_id, "secured"); bad["total_ms"] = 8.0
    rejected = c.post(f"{BASE}/runs/{run_id}/finalize", headers=headers,
        json={"status": "complete", "trials": [bad, trial_payload(unsecured_id, "unsecured")]})
    assert rejected.status_code == 400 and rejected.json()["detail"] == "segments_inconsistent"
    with base.SessionLocal() as db:
        assert db.query(AuditLog).filter(AuditLog.event_type == "METRICS_REJECTED").count() == 1
    assert c.get(f"{BASE}/runs/{run_id}", headers=headers).json()["run"]["status"] == "running"
    good_trials = [trial_payload(secured_id, "secured"), trial_payload(unsecured_id, "unsecured")]
    assert c.post(f"{BASE}/runs/{run_id}/finalize", headers=headers,
        json={"status": "complete", "trials": good_trials + [good_trials[0]]}).status_code == 400
    assert c.post(f"{BASE}/runs/{run_id}/finalize", headers=headers,
        json={"status": "complete", "trials": [good_trials[0]]}).status_code == 400
    assert c.post(f"{BASE}/runs/{run_id}/finalize", headers=headers,
        json={"status": "complete", "trials": good_trials}).status_code == 200
    # Non-running run and limits are handled without touching legacy tables.
    assert c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=unsecured_payload()).status_code == 409
    assert verify_chain()[0]


def test_oversized_requests_return_413(compare_client):
    c, headers = compare_client["client"], compare_client["analyst"]
    json_headers = {**headers, "Content-Type": "application/json"}
    response = c.post(f"{BASE}/runs", headers=json_headers,
                      content=b"{" + b" " * 17000 + b"}")
    assert response.status_code == 413
    run_id = start(c, headers).json()["id"]
    response = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=json_headers,
                      content=b"{" + b" " * 66000 + b"}")
    assert response.status_code == 413
    response = c.post(f"{BASE}/runs/{run_id}/finalize", headers=json_headers,
                      content=b"{" + b" " * 263000 + b"}")
    assert response.status_code == 413
