from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from app.db.base import Base, set_engine_and_session, init_db
from app.db import base
from app.db.models import ChatSession, Message, SigningKey, User, utc_now
from app.main import create_app
from app.security.passwords import hash_password


def test_old_messages_upgrade_is_idempotent_and_legacy_rows_stay_excluded(tmp_path):
    engine=create_engine(f"sqlite:///{tmp_path/'old-app.db'}",connect_args={"check_same_thread":False})
    set_engine_and_session(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("""CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id VARCHAR(36) NOT NULL,
            sender_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL, sender_role VARCHAR(1) NOT NULL,
            msg_type VARCHAR(20) NOT NULL, counter INTEGER NOT NULL, meta_json VARCHAR(255) NOT NULL,
            iv BLOB NOT NULL, ct BLOB NOT NULL, hmac BLOB NOT NULL, size_bytes INTEGER NOT NULL,
            created_at DATETIME NOT NULL, delivered_at DATETIME, verification_status VARCHAR(20) NOT NULL,
            verification_reason VARCHAR(50), verified_at DATETIME,
            UNIQUE(session_id,sender_role,counter))""")
        connection.execute(text("INSERT INTO messages(session_id,sender_id,recipient_id,sender_role,msg_type,counter,meta_json,iv,ct,hmac,size_bytes,created_at,verification_status) VALUES(:sid,1,2,'I','text',1,'{}',:iv,:ct,:tag,16,:created,'pending')"),
            {"sid":"00000000-0000-4000-8000-000000000001","iv":bytes(16),"ct":bytes(16),"tag":bytes(32),"created":datetime.now(timezone.utc).isoformat()})
    init_db(engine); init_db(engine)
    columns={column["name"] for column in inspect(engine).get_columns("messages")}
    expected={"pt_len_bytes","hmac_gen_us","signer_key_id","signature","sig_gen_ms","signature_status","sig_verify_ms"}
    assert expected <= columns
    with engine.connect() as connection:
        row=connection.execute(text("SELECT id, pt_len_bytes, hmac_gen_us, signer_key_id, signature, sig_gen_ms, signature_status, sig_verify_ms FROM messages")).one()
        assert row.id==1 and all(value is None for value in row[1:])
    Base.metadata.create_all(engine)
    created = utc_now()
    with base.SessionLocal() as db:
        alice = User(id=1, username="alice", username_norm="alice", password_hash=hash_password("Alice1234"), role="user")
        bob = User(id=2, username="bob", username_norm="bob", password_hash=hash_password("Bob12345"), role="user")
        analyst = User(id=3, username="analyst", username_norm="analyst", password_hash=hash_password("Analyst123"), role="analyst")
        db.add_all([alice, bob, analyst]); db.flush()
        db.add(ChatSession(id="00000000-0000-4000-8000-000000000001", user_a_id=1, user_b_id=2,
            status="terminated", started_at=created))
        legacy_key = SigningKey(user_id=1, auth_jti="legacy-session", public_key_der=bytes(256),
            fingerprint="a" * 64, created_at=created)
        db.add(legacy_key); db.flush()
        message = db.query(Message).filter(Message.id == 1).one()
        message.signer_key_id = legacy_key.id
        message.signature = bytes(256)
        message.sig_gen_ms = 5.0
        message.signature_status = "valid"
        db.commit()
    init_db(engine)
    with base.SessionLocal() as db:
        legacy = db.query(SigningKey).one()
        assert legacy.retired_at is not None and legacy.retire_reason == "legacy_algorithm"
    with TestClient(create_app()) as client:
        token=client.post("/api/auth/login",json={"username":"analyst","password":"Analyst123"}).json()["token"]
        headers={"Authorization":f"Bearer {token}"}
        assert client.get("/api/dashboard/hmac/records",headers=headers).json()["total"]==0
        assert client.get("/api/dashboard/signatures/records",headers=headers).json()["total"]==0
        keys = client.get("/api/dashboard/signatures/keys", headers=headers).json()
        assert keys["total"] == 1 and keys["items"][0]["signed_count"] == 0
        summary=client.get("/api/dashboard/summary",headers=headers).json()
        assert summary["signatures"]=={"signed":0,"valid":0,"invalid":0,"keys_total":1,"keys_active":0}
    engine.dispose()
