import asyncio
import json
from pathlib import Path
import time
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
from app.crypto.kdf import (
    confirm_tag,
    derive_session_keys,
    fingerprint_str,
    verify_confirm_tag,
)
from app.db import base
from app.db.base import Base, set_engine_and_session
from app.db.models import AuditLog, ChatSession
from app.main import create_app
import app.ws.session_coordinator as sc_module
from app.ws.session_coordinator import coordinator


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path):
    test_db_path = tmp_path / "test_session.db"
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
    coordinator.started_at = None
    coordinator.established_at = None
    coordinator.pub_a = None
    coordinator.pub_b = None
    coordinator.fingerprint_a = None
    coordinator.fingerprint_b = None
    if coordinator._timeout_task and not coordinator._timeout_task.done():
        coordinator._timeout_task.cancel()
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


def _get_token(client: TestClient, username: str) -> str:
    client.post(
        "/api/auth/register",
        json={"username": username, "password": "Password123"},
    )
    res = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Password123"},
    )
    return res.json()["token"]


def test_blind_relay_source_grep():
    """
    CRITICAL: Verify the server NEVER imports or references shared_secret
    or derive_session_keys in routers or ws modules.
    """
    repo_backend = Path(__file__).resolve().parent.parent
    forbidden_symbols = ["shared_secret", "derive_session_keys"]

    scan_dirs = [repo_backend / "routers", repo_backend / "ws"]
    for d in scan_dirs:
        for py_file in d.glob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for sym in forbidden_symbols:
                assert (
                    sym not in content
                ), f"Blind relay violation! '{sym}' found in {py_file.name}"


def test_chat_blocked_without_session(client: TestClient):
    alice_token = _get_token(client, "alice")

    with client.websocket_connect("/ws") as ws:
        # Auth frame
        ws.send_json({"v": 1, "type": "auth", "token": alice_token})
        joined = ws.receive_json()
        assert joined["type"] == "joined"
        status = ws.receive_json()
        assert status["type"] == "status"
        assert status["state"] == "waiting"

        # Attempt chat (plaintext chat frame is disabled in Phase 4)
        ws.send_json({"v": 1, "type": "chat", "text": "Hello world"})
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["code"] == "BAD_FRAME"


def test_happy_path_handshake_and_chat(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        # Auth Alice
        ws_a.send_json({"v": 1, "type": "auth", "token": alice_token})
        assert ws_a.receive_json()["type"] == "joined"
        status_a1 = ws_a.receive_json()
        assert status_a1["type"] == "status"
        assert status_a1["state"] == "waiting"

        # Auth Bob
        ws_b.send_json({"v": 1, "type": "auth", "token": bob_token})
        assert ws_b.receive_json()["type"] == "joined"

        # Room status update frames
        assert ws_a.receive_json()["type"] == "status"
        assert ws_b.receive_json()["type"] == "status"

        # Session start
        start_a = ws_a.receive_json()
        start_b = ws_b.receive_json()
        assert start_a["type"] == "session_start"
        assert start_b["type"] == "session_start"
        assert start_a["role"] == "initiator"
        assert start_b["role"] == "responder"
        assert start_a["session_id"] == start_b["session_id"]
        session_id = start_a["session_id"]

        # Alice computes keypair
        priv_a = generate_private()
        pub_a_int = public_from_private(priv_a)
        pub_a_hex = encode_public(pub_a_int)

        # Bob computes keypair
        priv_b = generate_private()
        pub_b_int = public_from_private(priv_b)
        pub_b_hex = encode_public(pub_b_int)

        # Send public keys
        ws_a.send_json(
            {"v": 1, "type": "dh_public", "session_id": session_id, "public": pub_a_hex}
        )
        ws_b.send_json(
            {"v": 1, "type": "dh_public", "session_id": session_id, "public": pub_b_hex}
        )

        # Relayed public keys
        relayed_b = ws_b.receive_json()
        assert relayed_b["type"] == "dh_public"
        assert relayed_b["from_role"] == "initiator"
        assert relayed_b["public"] == pub_a_hex

        relayed_a = ws_a.receive_json()
        assert relayed_a["type"] == "dh_public"
        assert relayed_a["from_role"] == "responder"
        assert relayed_a["public"] == pub_b_hex

        # Both compute shared secret and keys
        z_a = shared_secret(pub_b_int, priv_a)
        z_b = shared_secret(pub_a_int, priv_b)
        assert z_a == z_b

        keys_a = derive_session_keys(
            z_a, session_id, bytes.fromhex(pub_a_hex), bytes.fromhex(pub_b_hex)
        )
        keys_b = derive_session_keys(
            z_b, session_id, bytes.fromhex(pub_a_hex), bytes.fromhex(pub_b_hex)
        )
        fp_a = fingerprint_str(keys_a.fingerprint_bytes)
        fp_b = fingerprint_str(keys_b.fingerprint_bytes)
        assert fp_a == fp_b

        # Key confirmation
        tag_a = confirm_tag(keys_a.k_mac, session_id, "initiator")
        tag_b = confirm_tag(keys_b.k_mac, session_id, "responder")

        ws_a.send_json({"v": 1, "type": "key_confirm", "session_id": session_id, "tag": tag_a})
        ws_b.send_json({"v": 1, "type": "key_confirm", "session_id": session_id, "tag": tag_b})

        relayed_tag_b = ws_b.receive_json()
        assert relayed_tag_b["type"] == "key_confirm"
        assert relayed_tag_b["tag"] == tag_a
        assert verify_confirm_tag(keys_b.k_mac, session_id, "initiator", relayed_tag_b["tag"])

        relayed_tag_a = ws_a.receive_json()
        assert relayed_tag_a["type"] == "key_confirm"
        assert relayed_tag_a["tag"] == tag_b
        assert verify_confirm_tag(keys_a.k_mac, session_id, "responder", relayed_tag_a["tag"])

        # Send key_verified
        ws_a.send_json(
            {
                "v": 1,
                "type": "key_verified",
                "session_id": session_id,
                "fingerprint": fp_a,
                "timings": {"keygen_ms": 1.2, "derive_ms": 2.1},
            }
        )
        ws_b.send_json(
            {
                "v": 1,
                "type": "key_verified",
                "session_id": session_id,
                "fingerprint": fp_b,
                "timings": {"keygen_ms": 1.5, "derive_ms": 2.0},
            }
        )

        est_a = ws_a.receive_json()
        est_b = ws_b.receive_json()
        assert est_a["type"] == "session_established"
        assert est_b["type"] == "session_established"
        assert est_a["fingerprint"] == fp_a

        # Plaintext chat is rejected with BAD_FRAME in Phase 4
        ws_a.send_json({"v": 1, "type": "chat", "text": "Secret hello from Alice"})
        chat_err = ws_a.receive_json()
        assert chat_err["type"] == "error"
        assert chat_err["code"] == "BAD_FRAME"

        # Check DB and audit log
        with base.SessionLocal() as db:
            cs = db.query(ChatSession).filter(ChatSession.id == session_id).first()
            assert cs is not None
            assert cs.status == "established"
            assert cs.fingerprint_a == fp_a
            assert cs.fingerprint_b == fp_b

            logs = (
                db.query(AuditLog)
                .filter(AuditLog.event_type.in_(["SESSION_STARTED", "KEY_EXCHANGE_OK"]))
                .all()
            )
            event_types = [l.event_type for l in logs]
            assert "SESSION_STARTED" in event_types
            assert "KEY_EXCHANGE_OK" in event_types


def test_bad_public_key_rejected(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        ws_a.send_json({"v": 1, "type": "auth", "token": alice_token})
        ws_a.receive_json()
        ws_a.receive_json()

        ws_b.send_json({"v": 1, "type": "auth", "token": bob_token})
        ws_b.receive_json()
        ws_a.receive_json()
        ws_b.receive_json()

        start_a = ws_a.receive_json()
        ws_b.receive_json()
        session_id = start_a["session_id"]

        # Alice sends bad public key: all zeros (0 < 2)
        bad_pub = "00" * 256
        ws_a.send_json(
            {"v": 1, "type": "dh_public", "session_id": session_id, "public": bad_pub}
        )

        term_a = ws_a.receive_json()
        term_b = ws_b.receive_json()
        assert term_a["type"] == "session_terminated"
        assert term_a["reason"] == "bad_public"
        assert term_b["type"] == "session_terminated"
        assert term_b["reason"] == "bad_public"

        with base.SessionLocal() as db:
            logs = (
                db.query(AuditLog)
                .filter(AuditLog.event_type == "KEY_EXCHANGE_FAILED")
                .all()
            )
            assert len(logs) >= 1
            assert logs[0].details["reason"] == "bad_public"


def test_fingerprint_mismatch(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        ws_a.send_json({"v": 1, "type": "auth", "token": alice_token})
        ws_a.receive_json()
        ws_a.receive_json()

        ws_b.send_json({"v": 1, "type": "auth", "token": bob_token})
        ws_b.receive_json()
        ws_a.receive_json()
        ws_b.receive_json()

        start_a = ws_a.receive_json()
        ws_b.receive_json()
        session_id = start_a["session_id"]

        priv_a = generate_private()
        pub_a = encode_public(public_from_private(priv_a))
        priv_b = generate_private()
        pub_b = encode_public(public_from_private(priv_b))

        ws_a.send_json({"v": 1, "type": "dh_public", "session_id": session_id, "public": pub_a})
        ws_b.send_json({"v": 1, "type": "dh_public", "session_id": session_id, "public": pub_b})
        ws_b.receive_json()
        ws_a.receive_json()

        ws_a.send_json({"v": 1, "type": "key_confirm", "session_id": session_id, "tag": "aa" * 32})
        ws_b.send_json({"v": 1, "type": "key_confirm", "session_id": session_id, "tag": "bb" * 32})
        ws_b.receive_json()
        ws_a.receive_json()

        # Alice and Bob report DIFFERENT fingerprints
        ws_a.send_json(
            {
                "v": 1,
                "type": "key_verified",
                "session_id": session_id,
                "fingerprint": "1111 2222 3333 4444",
            }
        )
        ws_b.send_json(
            {
                "v": 1,
                "type": "key_verified",
                "session_id": session_id,
                "fingerprint": "5555 6666 7777 8888",
            }
        )

        term_a = ws_a.receive_json()
        term_b = ws_b.receive_json()
        assert term_a["type"] == "session_terminated"
        assert term_a["reason"] == "fingerprint_mismatch"
        assert term_b["type"] == "session_terminated"
        assert term_b["reason"] == "fingerprint_mismatch"


def test_handshake_timeout(client: TestClient, monkeypatch):
    monkeypatch.setattr(sc_module, "HANDSHAKE_TIMEOUT_SECONDS", 0.1)

    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        ws_a.send_json({"v": 1, "type": "auth", "token": alice_token})
        ws_a.receive_json()
        ws_a.receive_json()

        ws_b.send_json({"v": 1, "type": "auth", "token": bob_token})
        ws_b.receive_json()
        ws_a.receive_json()
        ws_b.receive_json()

        ws_a.receive_json()  # session_start
        ws_b.receive_json()

        # Wait for timeout
        time.sleep(0.25)

        term_a = ws_a.receive_json()
        term_b = ws_b.receive_json()
        assert term_a["type"] == "session_terminated"
        assert term_a["reason"] == "handshake_timeout"
        assert term_b["type"] == "session_terminated"
        assert term_b["reason"] == "handshake_timeout"


def test_disconnect_frame_ordering(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a:
        ws_a.send_json({"v": 1, "type": "auth", "token": alice_token})
        ws_a.receive_json()
        ws_a.receive_json()

        with client.websocket_connect("/ws") as ws_b:
            ws_b.send_json({"v": 1, "type": "auth", "token": bob_token})
            ws_b.receive_json()
            ws_a.receive_json()  # status paired
            ws_b.receive_json()  # status paired

            ws_a.receive_json()  # session_start
            ws_b.receive_json()  # session_start

            # Bob disconnects
            ws_b.close()

            # Alice must receive EXACTLY in order:
            # 1. session_terminated
            # 2. peer_left
            # 3. status (state: waiting)
            f1 = ws_a.receive_json()
            assert f1["type"] == "session_terminated"
            assert f1["reason"] == "disconnect"

            f2 = ws_a.receive_json()
            assert f2["type"] == "peer_left"
            assert f2["username"] == "bob"

            f3 = ws_a.receive_json()
            assert f3["type"] == "status"
            assert f3["state"] == "waiting"
            assert f3["peer"] is None


def test_request_session_after_termination(client: TestClient):
    alice_token = _get_token(client, "alice")
    bob_token = _get_token(client, "bob")

    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        ws_a.send_json({"v": 1, "type": "auth", "token": alice_token})
        ws_a.receive_json()
        ws_a.receive_json()

        ws_b.send_json({"v": 1, "type": "auth", "token": bob_token})
        ws_b.receive_json()
        ws_a.receive_json()
        ws_b.receive_json()

        start1_a = ws_a.receive_json()
        start1_b = ws_b.receive_json()
        s1_id = start1_a["session_id"]

        # Alice sends key_failed to terminate
        ws_a.send_json({"v": 1, "type": "key_failed", "session_id": s1_id, "reason": "bad_public"})
        term_a = ws_a.receive_json()
        term_b = ws_b.receive_json()
        assert term_a["type"] == "session_terminated"
        assert term_b["type"] == "session_terminated"

        # Now Bob requests new session
        ws_b.send_json({"v": 1, "type": "request_session"})
        start2_b = ws_b.receive_json()
        start2_a = ws_a.receive_json()
        assert start2_b["type"] == "session_start"
        assert start2_a["type"] == "session_start"
        assert start2_b["session_id"] != s1_id
        assert start2_a["session_id"] == start2_b["session_id"]
