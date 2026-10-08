import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func

from app.crypto.envelope import Envelope, encrypt_message, image_meta_json, verify_and_decrypt, EnvelopeError
from app.db import base
from app.db.base import Base, set_engine_and_session
from app.db.models import AuditLog, ChatSession, Message, User
from app.main import create_app
from app.services.tamper import tamper_service
from app.ws.manager import manager
from app.ws.session_coordinator import coordinator
from app.tests.test_messages_api import _establish_session, _get_token


@pytest.fixture
def client(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'dashboard.db'}", connect_args={"check_same_thread": False})
    set_engine_and_session(engine)
    Base.metadata.create_all(bind=engine)
    manager._users.clear(); manager._ws_to_user.clear()
    coordinator.active_session_id = None; coordinator.initiator = None; coordinator.responder = None; coordinator.status = "none"
    tamper_service.disarm()
    with TestClient(create_app()) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def _auth(token: str | None):
    return {"Authorization": f"Bearer {token}"} if token else {}


def test_dashboard_metadata_scenario(client: TestClient):
    alice = _get_token(client, "alice")
    bob = _get_token(client, "bob")
    client.post("/api/auth/register", json={"username": "carol", "password": "Password123"})
    analyst = _get_token(client, "analyst", role="analyst")
    client.post("/api/auth/login", json={"username": "no_such_user", "password": "Wrong123"})
    for _ in range(2):
        client.post("/api/auth/login", json={"username": "alice", "password": "Wrong123"})

    paths = ["/api/dashboard/logs", "/api/dashboard/logs/types", "/api/dashboard/messages", "/api/dashboard/sessions", "/api/dashboard/summary", "/api/dashboard/audit-integrity"]
    for path in paths:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_auth(bob)).status_code == 403

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        sid, keys_a, keys_b = _establish_session(client, ws_a, ws_b, alice, bob)
        text1 = encrypt_message(keys_a.k_enc, keys_a.k_mac, sid, "I", 1, b"first")
        text2 = encrypt_message(keys_a.k_enc, keys_a.k_mac, sid, "I", 2, b"second")
        image = encrypt_message(keys_a.k_enc, keys_a.k_mac, sid, "I", 3, bytes(range(36)), "image", image_meta_json(4, 3))
        sent = []
        for env in (text1, text2, image):
            response = client.post("/api/messages", headers=_auth(alice), json={"session_id": sid, "counter": env.counter, "msg_type": env.msg_type, "meta_json": env.meta_json, "iv": env.iv_b64, "ct": env.ct_b64, "hmac": env.hmac_b64})
            assert response.status_code == 201
            sent.append(response.json()["id"])
            ws_b.receive_json()
        verified = client.post(f"/api/messages/{sent[0]}/verification", headers=_auth(bob), json={"status": "verified"})
        assert verified.status_code == 204
        tamper_service.arm()
        tampered = client.get(f"/api/messages/{sent[2]}", headers=_auth(bob)).json()
        env_bad = Envelope(sid, "I", 3, "image", tampered["meta_json"], base64.b64decode(tampered["iv"]), base64.b64decode(tampered["ct"]), base64.b64decode(tampered["hmac"]))
        with pytest.raises(EnvelopeError, match="hmac_mismatch"):
            verify_and_decrypt(keys_b.k_enc, keys_b.k_mac, sid, "I", env_bad, 2)
        client.post(f"/api/messages/{sent[2]}/verification", headers=_auth(bob), json={"status": "failed", "reason": "hmac_mismatch"})

        summary = client.get("/api/dashboard/summary", headers=_auth(analyst)).json()
        assert summary["users"]["online"] == ["alice", "bob"]
        assert summary["messages"] == {"total": 3, "text": 2, "image": 1, "verified": 1, "failed": 1, "pending": 1}
        assert summary["security"]["failed_logins_total"] == 3
        assert summary["security"]["tamper_detected_total"] == 1
        assert summary["active_session"]["id"] == sid

        msg_page = client.get("/api/dashboard/messages?limit=9999", headers=_auth(analyst)).json()
        by_type = {row["msg_type"]: row for row in msg_page["items"]}
        assert by_type["image"]["w"] == 4 and by_type["image"]["h"] == 3
        assert by_type["text"]["w"] is None and by_type["text"]["sender"] == "alice"
        assert client.get("/api/dashboard/messages?msg_type=bad", headers=_auth(analyst)).status_code == 400

        sessions = client.get("/api/dashboard/sessions", headers=_auth(analyst)).json()["items"]
        assert sessions[0]["handshake_ms"] is not None and sessions[0]["message_count"] == 3
        assert sessions[0]["failed_verification_count"] == 1
        assert sessions[0]["fingerprint"] and len(sessions[0]["fingerprint"].replace(" ", "")) == 16

        with base.SessionLocal() as db:
            before_count = db.query(func.count(AuditLog.id)).scalar()
        logs = client.get("/api/dashboard/logs?limit=9999", headers=_auth(analyst)).json()
        assert len(logs["items"]) <= 500
        assert all(logs["items"][i]["id"] > logs["items"][i + 1]["id"] for i in range(len(logs["items"]) - 1))
        assert client.get("/api/dashboard/logs?before_id=4&after_id=2", headers=_auth(analyst)).status_code == 400
        types = client.get("/api/dashboard/logs/types", headers=_auth(analyst)).json()
        auth_logs = client.get("/api/dashboard/logs?category=auth", headers=_auth(analyst)).json()["items"]
        assert all(row["event_type"] in types["categories"]["auth"] for row in auth_logs)
        assert any(row["username"] == "no_such_user" for row in auth_logs)
        assert any(row["username"] == "alice" for row in auth_logs)
        assert all(row["severity"] == "alert" for row in client.get("/api/dashboard/logs?severity_min=alert", headers=_auth(analyst)).json()["items"])
        assert all(row["success"] is False for row in client.get("/api/dashboard/logs?success=false", headers=_auth(analyst)).json()["items"])
        assert client.get("/api/dashboard/logs?username=SUCH_US", headers=_auth(analyst)).json()["items"]
        first_page = client.get("/api/dashboard/logs?limit=3", headers=_auth(analyst)).json()["items"]
        older_page = client.get(f"/api/dashboard/logs?limit=3&before_id={first_page[-1]['id']}", headers=_auth(analyst)).json()["items"]
        assert first_page and older_page and not ({r["id"] for r in first_page} & {r["id"] for r in older_page})
        newest = client.get(f"/api/dashboard/logs?after_id={older_page[-1]['id']}", headers=_auth(analyst)).json()["items"]
        assert all(row["id"] > older_page[-1]["id"] for row in newest)
        assert all(newest[i]["id"] > newest[i + 1]["id"] for i in range(len(newest) - 1))
        assert client.get(f"/api/dashboard/logs?session_id={sid}", headers=_auth(analyst)).status_code == 200

        dashboard_responses = []
        for path in paths:
            response = client.get(path, headers=_auth(analyst))
            assert response.status_code == 200
            serialized = response.text
            dashboard_responses.append(serialized)
            for forbidden in ('"password_hash"', "$2b$", '"access_token"', '"jti"', '"ct"', '"iv"', '"hmac"', '"pub_a"', '"pub_b"', '"k_enc"', '"k_mac"'):
                assert forbidden not in serialized
        with base.SessionLocal() as db:
            ciphertexts = [base64.b64encode(raw).decode("ascii") for (raw,) in db.query(Message.ct).all()]
            after_count = db.query(func.count(AuditLog.id)).scalar()
        assert all(ciphertext not in response for ciphertext in ciphertexts for response in dashboard_responses)
        assert after_count == before_count

        integrity = client.get("/api/dashboard/audit-integrity", headers=_auth(analyst)).json()
        assert integrity["ok"] is True and integrity["rows_checked"] == after_count
        with base.SessionLocal() as db:
            first_id = db.query(func.min(AuditLog.id)).scalar()
            row = db.query(AuditLog).filter(AuditLog.id == first_id).first()
            row.details = {"edited": True}; db.commit()
        corrupt = client.get("/api/dashboard/audit-integrity", headers=_auth(analyst)).json()
        assert corrupt["ok"] is False and corrupt["first_bad_id"] == first_id

        logout = client.post("/api/auth/logout", headers=_auth(alice))
        assert logout.status_code == 204
        ended = client.get("/api/dashboard/sessions", headers=_auth(analyst)).json()["items"][0]
        assert ended["status"] == "terminated" and ended["end_reason"] == "logout"
