import base64
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app import config
from app.crypto.dh import (
    decode_public,
    encode_public,
    generate_private,
    public_from_private,
    shared_secret,
)
from app.crypto.envelope import (
    Envelope,
    EnvelopeError,
    encrypt_message,
    verify_and_decrypt,
)
from app.crypto.kdf import (
    confirm_tag,
    derive_session_keys,
    fingerprint_str,
    verify_confirm_tag,
)
from app.db import base
from app.db.base import Base, set_engine_and_session
from app.db.models import AuditLog, ChatSession, Message, User
from app.main import create_app
from app.services.tamper import tamper_service
from app.ws.session_coordinator import coordinator


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path):
    test_db_path = tmp_path / "test_messages.db"
    test_engine = create_engine(
        f"sqlite:///{test_db_path}",
        connect_args={"check_same_thread": False},
    )
    set_engine_and_session(test_engine)
    Base.metadata.create_all(bind=test_engine)

    # Reset coordinator state
    coordinator.active_session_id = None
    coordinator.initiator = None
    coordinator.responder = None
    coordinator.status = "none"
    tamper_service.disarm()
    config.TAMPER_DEMO_ENABLED = True

    yield test_db_path
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


def _get_token(client: TestClient, username: str, role: str = "user") -> str:
    if role == "analyst":
        # Create analyst directly in DB
        with base.SessionLocal() as db:
            from app.security.passwords import hash_password
            u = User(
                username=username,
                username_norm=username.lower(),
                password_hash=hash_password("Analyst123"),
                role="analyst",
            )
            db.add(u)
            db.commit()
    else:
        client.post(
            "/api/auth/register",
            json={"username": username, "password": "Password123"},
        )

    res = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Password123" if role == "user" else "Analyst123"},
    )
    return res.json()["token"]


def _establish_session(client: TestClient, ws_a, ws_b, alice_token, bob_token):
    """Establishes Phase 3 session between ws_a (Alice) and ws_b (Bob)."""
    ws_a.send_json({"v": 1, "type": "auth", "token": alice_token})
    ws_a.receive_json()  # joined
    ws_a.receive_json()  # status waiting

    ws_b.send_json({"v": 1, "type": "auth", "token": bob_token})
    ws_b.receive_json()  # joined
    ws_a.receive_json()  # status paired
    ws_b.receive_json()  # status paired

    start_a = ws_a.receive_json()
    start_b = ws_b.receive_json()
    session_id = start_a["session_id"]

    priv_a = generate_private()
    pub_a_hex = encode_public(public_from_private(priv_a))
    priv_b = generate_private()
    pub_b_hex = encode_public(public_from_private(priv_b))

    ws_a.send_json({"v": 1, "type": "dh_public", "session_id": session_id, "public": pub_a_hex})
    ws_b.send_json({"v": 1, "type": "dh_public", "session_id": session_id, "public": pub_b_hex})
    ws_b.receive_json()  # dh_public from A
    ws_a.receive_json()  # dh_public from B

    z_a = shared_secret(decode_public(pub_b_hex), priv_a)
    z_b = shared_secret(decode_public(pub_a_hex), priv_b)
    keys_a = derive_session_keys(z_a, session_id, bytes.fromhex(pub_a_hex), bytes.fromhex(pub_b_hex))
    keys_b = derive_session_keys(z_b, session_id, bytes.fromhex(pub_a_hex), bytes.fromhex(pub_b_hex))
    fp_a = fingerprint_str(keys_a.fingerprint_bytes)
    fp_b = fingerprint_str(keys_b.fingerprint_bytes)

    tag_a = confirm_tag(keys_a.k_mac, session_id, "initiator")
    tag_b = confirm_tag(keys_b.k_mac, session_id, "responder")
    ws_a.send_json({"v": 1, "type": "key_confirm", "session_id": session_id, "tag": tag_a})
    ws_b.send_json({"v": 1, "type": "key_confirm", "session_id": session_id, "tag": tag_b})
    ws_b.receive_json()
    ws_a.receive_json()

    ws_a.send_json({"v": 1, "type": "key_verified", "session_id": session_id, "fingerprint": fp_a})
    ws_b.send_json({"v": 1, "type": "key_verified", "session_id": session_id, "fingerprint": fp_b})
    ws_a.receive_json()  # session_established
    ws_b.receive_json()  # session_established

    return session_id, keys_a, keys_b


def test_blind_relay_source_grep():
    """
    GREP TEST: verify that nothing in routers/, ws/, or services/
    imports app.crypto.envelope or app.crypto.kdf.
    """
    repo_backend = Path(__file__).resolve().parent.parent
    forbidden = ["app.crypto.envelope", "app.crypto.kdf", "shared_secret", "derive_session_keys"]

    for d in [repo_backend / "routers", repo_backend / "ws", repo_backend / "services"]:
        for py_file in d.glob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            for term in forbidden:
                assert term not in text, f"Blind relay violation! '{term}' found in {py_file.name}"


def test_full_messages_happy_path(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        session_id, keys_a, keys_b = _establish_session(
            client, ws_a, ws_b, alice_token, bob_token
        )

        # 1. Alice encrypts and sends message to Bob
        pt = "Hello Bob! Top secret Phase 4 message.".encode("utf-8")
        env_a = encrypt_message(
            k_enc=keys_a.k_enc,
            k_mac=keys_a.k_mac,
            session_id=session_id,
            sender_role="I",
            counter=1,
            plaintext_bytes=pt,
        )

        res_send = client.post(
            "/api/messages",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={
                "session_id": session_id,
                "counter": env_a.counter,
                "msg_type": env_a.msg_type,
                "meta_json": env_a.meta_json,
                "iv": env_a.iv_b64,
                "ct": env_a.ct_b64,
                "hmac": env_a.hmac_b64,
            },
        )
        assert res_send.status_code == 201
        msg_id = res_send.json()["id"]

        # Bob receives message_available on WebSocket
        ws_notif = ws_b.receive_json()
        assert ws_notif["type"] == "message_available"
        assert ws_notif["message_id"] == msg_id
        assert ws_notif["counter"] == 1
        assert ws_notif["from_role"] == "I"
        # Ciphertext must NOT be in WS notification
        assert "ct" not in ws_notif

        # 2. Bob fetches the envelope via GET /api/messages/{id}
        res_get = client.get(
            f"/api/messages/{msg_id}",
            headers={"Authorization": f"Bearer {bob_token}"},
        )
        assert res_get.status_code == 200
        data = res_get.json()
        assert data["id"] == msg_id
        assert data["counter"] == 1
        assert data["from_role"] == "I"

        fetched_env = Envelope(
            session_id=data["session_id"],
            sender_role=data["from_role"],
            counter=data["counter"],
            msg_type=data["msg_type"],
            meta_json=data["meta_json"],
            iv=base64.b64decode(data["iv"]),
            ct=base64.b64decode(data["ct"]),
            hmac=base64.b64decode(data["hmac"]),
        )

        # 3. Bob runs strict verify_and_decrypt
        decrypted = verify_and_decrypt(
            k_enc=keys_b.k_enc,
            k_mac=keys_b.k_mac,
            session_id=session_id,
            sender_role="I",
            envelope=fetched_env,
            last_counter=0,
        )
        assert decrypted == pt

        # 4. Bob reports verification result
        res_v = client.post(
            f"/api/messages/{msg_id}/verification",
            headers={"Authorization": f"Bearer {bob_token}"},
            json={"status": "verified"},
        )
        assert res_v.status_code == 204

        # 5. Alice receives message_status over WebSocket
        ws_status = ws_a.receive_json()
        assert ws_status["type"] == "message_status"
        assert ws_status["message_id"] == msg_id
        assert ws_status["status"] == "verified"


def test_fetch_authorization(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")
    eve_token = _get_token(client, "eve")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        session_id, keys_a, _ = _establish_session(
            client, ws_a, ws_b, alice_token, bob_token
        )

        env_a = encrypt_message(
            keys_a.k_enc, keys_a.k_mac, session_id, "I", 1, b"Secret"
        )
        res_send = client.post(
            "/api/messages",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={
                "session_id": session_id,
                "counter": 1,
                "msg_type": "text",
                "meta_json": "{}",
                "iv": env_a.iv_b64,
                "ct": env_a.ct_b64,
                "hmac": env_a.hmac_b64,
            },
        )
        msg_id = res_send.json()["id"]

        # Sender (Alice) fetching returns 403
        res_alice = client.get(
            f"/api/messages/{msg_id}",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert res_alice.status_code == 403

        # Non-participant (Eve) fetching returns 403
        res_eve = client.get(
            f"/api/messages/{msg_id}",
            headers={"Authorization": f"Bearer {eve_token}"},
        )
        assert res_eve.status_code == 403

        # Non-participant (Eve) posting returns 403
        res_eve_post = client.post(
            "/api/messages",
            headers={"Authorization": f"Bearer {eve_token}"},
            json={
                "session_id": session_id,
                "counter": 1,
                "msg_type": "text",
                "meta_json": "{}",
                "iv": env_a.iv_b64,
                "ct": env_a.ct_b64,
                "hmac": env_a.hmac_b64,
            },
        )
        assert res_eve_post.status_code == 403


def test_session_not_established_rejected(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    # Manually create a session in negotiating status
    with base.SessionLocal() as db:
        u_a = db.query(User).filter(User.username == "alice").first()
        u_b = db.query(User).filter(User.username == "bob").first()
        s = ChatSession(
            id="negotiating-session-id",
            user_a_id=u_a.id,
            user_b_id=u_b.id,
            status="negotiating",
        )
        db.add(s)
        db.commit()

    res = client.post(
        "/api/messages",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "session_id": "negotiating-session-id",
            "counter": 1,
            "msg_type": "text",
            "meta_json": "{}",
            "iv": base64.b64encode(b"0" * 16).decode(),
            "ct": base64.b64encode(b"0" * 16).decode(),
            "hmac": base64.b64encode(b"0" * 32).decode(),
        },
    )
    assert res.status_code == 409
    assert res.json()["detail"] == "session_not_established"


def test_counter_validation_and_replay_rejection(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        session_id, keys_a, _ = _establish_session(
            client, ws_a, ws_b, alice_token, bob_token
        )

        env1 = encrypt_message(keys_a.k_enc, keys_a.k_mac, session_id, "I", 1, b"Msg 1")
        res1 = client.post(
            "/api/messages",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={
                "session_id": session_id,
                "counter": 1,
                "msg_type": "text",
                "meta_json": "{}",
                "iv": env1.iv_b64,
                "ct": env1.ct_b64,
                "hmac": env1.hmac_b64,
            },
        )
        assert res1.status_code == 201

        # Re-posting same counter 1 returns 409 counter_not_increasing
        res_dup = client.post(
            "/api/messages",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={
                "session_id": session_id,
                "counter": 1,
                "msg_type": "text",
                "meta_json": "{}",
                "iv": env1.iv_b64,
                "ct": env1.ct_b64,
                "hmac": env1.hmac_b64,
            },
        )
        assert res_dup.status_code == 409
        assert res_dup.json()["detail"] == "counter_not_increasing"


def test_bad_format_rejection(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        session_id, _, _ = _establish_session(
            client, ws_a, ws_b, alice_token, bob_token
        )

        # Invalid base64
        res_b64 = client.post(
            "/api/messages",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={
                "session_id": session_id,
                "counter": 1,
                "msg_type": "text",
                "meta_json": "{}",
                "iv": "not-valid-base64!!!",
                "ct": base64.b64encode(b"0" * 16).decode(),
                "hmac": base64.b64encode(b"0" * 32).decode(),
            },
        )
        assert res_b64.status_code == 400

        # Wrong IV length (not 16)
        res_iv = client.post(
            "/api/messages",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={
                "session_id": session_id,
                "counter": 1,
                "msg_type": "text",
                "meta_json": "{}",
                "iv": base64.b64encode(b"0" * 10).decode(),
                "ct": base64.b64encode(b"0" * 16).decode(),
                "hmac": base64.b64encode(b"0" * 32).decode(),
            },
        )
        assert res_iv.status_code == 400

        # Check MESSAGE_REJECTED was logged
        with base.SessionLocal() as db:
            logs = db.query(AuditLog).filter(AuditLog.event_type == "MESSAGE_REJECTED").all()
            assert len(logs) >= 2


def test_tamper_simulation_flow(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")
    analyst_token = _get_token(client, "analyst1", role="analyst")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        session_id, keys_a, keys_b = _establish_session(
            client, ws_a, ws_b, alice_token, bob_token
        )

        # 1. Alice sends message
        pt = b"Critical instruction"
        env = encrypt_message(keys_a.k_enc, keys_a.k_mac, session_id, "I", 1, pt)
        res_send = client.post(
            "/api/messages",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={
                "session_id": session_id,
                "counter": 1,
                "msg_type": "text",
                "meta_json": "{}",
                "iv": env.iv_b64,
                "ct": env.ct_b64,
                "hmac": env.hmac_b64,
            },
        )
        msg_id = res_send.json()["id"]

        # 2. Analyst arms tamper simulation
        res_arm = client.post(
            "/api/admin/tamper",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json={"armed": True},
        )
        assert res_arm.status_code == 200
        assert res_arm.json()["armed"] is True

        # 3. Bob fetches message -> gets corrupted ciphertext copy
        res_fetch = client.get(
            f"/api/messages/{msg_id}",
            headers={"Authorization": f"Bearer {bob_token}"},
        )
        assert res_fetch.status_code == 200
        data = res_fetch.json()
        assert data["ct"] != env.ct_b64  # Altered!

        # Check DB row is untouched!
        with base.SessionLocal() as db:
            row = db.query(Message).filter(Message.id == msg_id).first()
            assert row.ct == env.ct

        # Verify armed state reset to False
        res_state = client.get(
            "/api/admin/tamper",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert res_state.json()["armed"] is False

        # 4. Bob runs verify_and_decrypt on tampered envelope -> fails with hmac_mismatch!
        corrupted_env = Envelope(
            session_id=session_id,
            sender_role="I",
            counter=1,
            msg_type="text",
            meta_json="{}",
            iv=base64.b64decode(data["iv"]),
            ct=base64.b64decode(data["ct"]),
            hmac=base64.b64decode(data["hmac"]),
        )
        with pytest.raises(EnvelopeError) as exc_info:
            verify_and_decrypt(keys_b.k_enc, keys_b.k_mac, session_id, "I", corrupted_env, 0)
        assert exc_info.value.reason == "hmac_mismatch"

        # 5. Bob reports verification failure
        res_report = client.post(
            f"/api/messages/{msg_id}/verification",
            headers={"Authorization": f"Bearer {bob_token}"},
            json={"status": "failed", "reason": "hmac_mismatch"},
        )
        assert res_report.status_code == 204

        # Second report returns 409 already_reported
        res_report_dup = client.post(
            f"/api/messages/{msg_id}/verification",
            headers={"Authorization": f"Bearer {bob_token}"},
            json={"status": "failed", "reason": "hmac_mismatch"},
        )
        assert res_report_dup.status_code == 409

        # 6. Audit check for TAMPER_DETECTED (alert)
        with base.SessionLocal() as db:
            alert = db.query(AuditLog).filter(AuditLog.event_type == "TAMPER_DETECTED").first()
            assert alert is not None
            assert alert.severity == "alert"
            assert alert.details["reason"] == "hmac_mismatch"


def test_admin_endpoints_authorization_and_disabled(client: TestClient):
    alice_token = _get_token(client, "alice")
    analyst_token = _get_token(client, "analyst1", role="analyst")

    # Non-analyst gets 403
    res_user = client.get(
        "/api/admin/tamper",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res_user.status_code == 403

    # TAMPER_DEMO_ENABLED = False returns 404
    config.TAMPER_DEMO_ENABLED = False
    res_disabled = client.get(
        "/api/admin/tamper",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res_disabled.status_code == 404


def test_plaintext_leak_check(client: TestClient, setup_test_db, caplog):
    """
    PLAINTEXT LEAK TEST: after sending several distinctive plaintexts,
    scan the whole app.db file bytes and captured log output for those
    plaintext strings (must not appear).
    """
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")
    test_db_path = setup_test_db

    distinctive_strings = [
        "DISTINCTIVE_SECRET_ALPHA_9981",
        "DISTINCTIVE_SECRET_BETA_7712",
        "DISTINCTIVE_SECRET_GAMMA_3344",
    ]

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        session_id, keys_a, _ = _establish_session(
            client, ws_a, ws_b, alice_token, bob_token
        )

        for i, text in enumerate(distinctive_strings, start=1):
            env = encrypt_message(
                keys_a.k_enc, keys_a.k_mac, session_id, "I", i, text.encode("utf-8")
            )
            res = client.post(
                "/api/messages",
                headers={"Authorization": f"Bearer {alice_token}"},
                json={
                    "session_id": session_id,
                    "counter": i,
                    "msg_type": "text",
                    "meta_json": "{}",
                    "iv": env.iv_b64,
                    "ct": env.ct_b64,
                    "hmac": env.hmac_b64,
                },
            )
            assert res.status_code == 201

    # Inspect SQLite database bytes directly
    db_bytes = test_db_path.read_bytes()
    for text in distinctive_strings:
        assert text.encode("utf-8") not in db_bytes, f"Plaintext leak in database file! Found: {text}"

    # Inspect captured logs
    captured_logs = caplog.text
    for text in distinctive_strings:
        assert text not in captured_logs, f"Plaintext leak in logs! Found: {text}"

