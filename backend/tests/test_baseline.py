import base64
from uuid import uuid4

from app import config
from app.db import base, lab_base
from app.db.models import AuditLog, ChatSession, utc_now
from app.services.baseline_store import store
from tests.test_lab_text_metrics import _auth, scenario


def test_disabled_routes_are_404(scenario, monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PLAINTEXT_BASELINE", False)
    client = scenario["client"]
    assert client.post("/api/baseline/messages", json={}).status_code == 404
    assert client.post("/api/baseline/messages", json={}, headers=_auth(scenario["alice"])).status_code == 404
    assert client.get("/api/baseline/messages/123456").status_code == 404


def test_text_image_recipients_consume_audit_and_privacy(scenario, monkeypatch, caplog):
    monkeypatch.setattr(config, "ALLOW_PLAINTEXT_BASELINE", True)
    store._items.clear(); store._audited_sessions.clear()
    client = scenario["client"]
    distinctive = "PLAINTEXT_SENTINEL_9c781"
    sent = client.post("/api/baseline/messages", headers=_auth(scenario["alice"]), json={
        "session_id": scenario["sid"], "kind": "text", "text": distinctive})
    assert sent.status_code == 201
    assert scenario["ws_b"].receive_json()["type"] == "baseline_available"
    message_id = sent.json()["id"]
    assert client.get(f"/api/baseline/messages/{message_id}", headers=_auth(scenario["alice"])).status_code == 403
    fetched = client.get(f"/api/baseline/messages/{message_id}", headers=_auth(scenario["bob"]))
    assert fetched.status_code == 200 and fetched.json()["text"] == distinctive
    assert client.get(f"/api/baseline/messages/{message_id}", headers=_auth(scenario["bob"])).status_code == 404

    raw = bytes((i * 17 + 3) % 256 for i in range(4 * 3 * 3))
    image_data = base64.b64encode(raw).decode("ascii")
    image = client.post("/api/baseline/messages", headers=_auth(scenario["alice"]), json={
        "session_id": scenario["sid"], "kind": "image", "w": 4, "h": 3, "data_b64": image_data})
    assert image.status_code == 201
    assert scenario["ws_b"].receive_json()["type"] == "baseline_available"
    received = client.get(f"/api/baseline/messages/{image.json()['id']}", headers=_auth(scenario["bob"]))
    assert received.status_code == 200 and base64.b64decode(received.json()["data_b64"]) == raw
    with base.SessionLocal() as db:
        assert db.query(AuditLog).filter(AuditLog.event_type == "BASELINE_PLAINTEXT_USED", AuditLog.session_id == scenario["sid"]).count() == 1
    for path in (scenario["app_engine"].url.database, scenario["lab_engine"].url.database):
        contents = open(path, "rb").read()
        assert distinctive.encode() not in contents and raw not in contents and image_data.encode() not in contents
    assert distinctive not in caplog.text and image_data not in caplog.text


def test_participant_session_validation_and_payload_limits(scenario, monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PLAINTEXT_BASELINE", True)
    client = scenario["client"]
    stranger = scenario["analyst"]
    body = {"session_id": scenario["sid"], "kind": "text", "text": "hello"}
    assert client.post("/api/baseline/messages", headers=_auth(stranger), json=body).status_code == 403
    non_established_id = str(uuid4())
    with base.SessionLocal() as db:
        old = db.query(ChatSession).filter(ChatSession.id == scenario["sid"]).first()
        pending = ChatSession(id=non_established_id, user_a_id=old.user_a_id, user_b_id=old.user_b_id,
            status="negotiating", started_at=utc_now())
        db.add(pending); db.commit()
    assert client.post("/api/baseline/messages", headers=_auth(scenario["alice"]), json={**body,"session_id":non_established_id}).status_code == 409
    invalid = [
        {**body, "text": "x" * 2001},
        {**body, "unexpected": True},
        {"session_id": scenario["sid"], "kind": "image", "w": 2, "h": 2, "data_b64": base64.b64encode(b"bad").decode()},
        {"session_id": scenario["sid"], "kind": "image", "w": 513, "h": 1, "data_b64": "AA=="},
    ]
    for payload in invalid:
        assert client.post("/api/baseline/messages", headers=_auth(scenario["alice"]), json=payload).status_code in (400, 422)
    oversized = client.post("/api/baseline/messages", content=b" " * 1_200_001,
        headers={**_auth(scenario["alice"]), "Content-Type":"application/json"})
    assert oversized.status_code == 413


def test_route_store_ttl_and_eviction(scenario, monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PLAINTEXT_BASELINE", True)
    monkeypatch.setattr(config, "BASELINE_TTL_SECONDS", 1)
    now = [50.0]; monkeypatch.setattr(store, "_clock", lambda: now[0])
    store._items.clear(); store._audited_sessions.clear()
    client = scenario["client"]
    body = {"session_id": scenario["sid"], "kind": "text", "text": "queued"}
    first = client.post("/api/baseline/messages", headers=_auth(scenario["alice"]), json=body).json()["id"]
    now[0] += 2
    assert client.get(f"/api/baseline/messages/{first}", headers=_auth(scenario["bob"])).status_code == 404
    monkeypatch.setattr(config, "BASELINE_TTL_SECONDS", 60)
    monkeypatch.setattr(config, "BASELINE_MAX_ITEMS", 1)
    second = client.post("/api/baseline/messages", headers=_auth(scenario["alice"]), json=body).json()["id"]
    third = client.post("/api/baseline/messages", headers=_auth(scenario["alice"]), json=body).json()["id"]
    assert client.get(f"/api/baseline/messages/{second}", headers=_auth(scenario["bob"])).status_code == 404
    assert client.get(f"/api/baseline/messages/{third}", headers=_auth(scenario["bob"])).status_code == 200
