import base64

from sqlalchemy.orm import Session

from app.crypto.envelope import encrypt_message, image_meta_json
from app.db import base
from app.db.models import AuditLog, Message
from app.tests.signing_helpers import register_signer, signed_message_payload
from app.tests.test_messages_api import _establish_session, _get_token

pytest_plugins = ["app.tests.test_messages_api"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_signed_text_and_image_round_trip_metadata_and_status_frames(client):
    alice, bob = _get_token(client,"alice"), _get_token(client,"bob")
    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        sid, keys_a, _keys_b = _establish_session(client,ws_a,ws_b,alice,bob)
        text=b"signed text"
        env=encrypt_message(keys_a.k_enc,keys_a.k_mac,sid,"I",1,text)
        sent=client.post("/api/messages",headers=_auth(alice),json=signed_message_payload(client,alice,env,len(text)))
        assert sent.status_code==201
        ws_b.receive_json()
        image=bytes(range(36)); env_image=encrypt_message(keys_a.k_enc,keys_a.k_mac,sid,"I",2,image,"image",image_meta_json(4,3))
        sent_image=client.post("/api/messages",headers=_auth(alice),json=signed_message_payload(client,alice,env_image,len(image)))
        assert sent_image.status_code==201
        ws_b.receive_json()
        with base.SessionLocal() as db:
            rows=db.query(Message).order_by(Message.id).all()
            assert len(rows)==2
            assert all(row.signature and len(row.signature)==64 and row.signature_status=="pending" for row in rows)
            assert rows[0].pt_len_bytes==len(text) and rows[1].pt_len_bytes==36
            assert rows[0].hmac_gen_us and rows[0].sig_gen_ms and rows[0].signer_key_id
        fetched=client.get(f"/api/messages/{sent.json()['id']}",headers=_auth(bob))
        assert fetched.status_code==200
        data=fetched.json()
        assert len(base64.b64decode(data["signature"]))==64 and data["signer_key_id"]
        assert data["sig_gen_ms"] and data["hmac_gen_us"]
        assert client.get(f"/api/messages/{sent.json()['id']}",headers=_auth(alice)).status_code==403
        report=client.post(f"/api/messages/{sent.json()['id']}/verification",headers=_auth(bob),json={"status":"verified"})
        assert report.status_code==204
        status=ws_a.receive_json()
        assert status["type"]=="message_status" and status["sig_status"]=="valid" and status["sig_verify_ms"]
        with base.SessionLocal() as db:
            row=db.query(Message).filter(Message.id==sent.json()["id"]).one()
            assert row.signature_status=="valid" and row.sig_verify_ms
        analyst = _get_token(client, "analyst", "analyst")
        records = client.get("/api/dashboard/signatures/records", headers=_auth(analyst)).json()
        assert records["total"] == 2
        assert all(row["signature_len"] == 64 and len(row["signature_preview_hex"]) == 64 for row in records["items"])
        key_records = client.get("/api/dashboard/signatures/keys", headers=_auth(analyst)).json()
        assert key_records["total"] == 1 and key_records["items"][0]["signed_count"] == 2
        assert "public_key_b64" not in str(key_records) and "private_key" not in str(key_records).lower()


def test_missing_wrong_key_and_invalid_signature_are_rejected_without_storage(client):
    alice,bob=_get_token(client,"alice"),_get_token(client,"bob")
    with client.websocket_connect("/ws") as ws_a,client.websocket_connect("/ws") as ws_b:
        sid,keys_a,_=_establish_session(client,ws_a,ws_b,alice,bob)
        plaintext=b"authentic"
        env=encrypt_message(keys_a.k_enc,keys_a.k_mac,sid,"I",1,plaintext)
        valid=signed_message_payload(client,alice,env,len(plaintext))
        missing=dict(valid); [missing.pop(k) for k in ("signer_key_id","signature","sig_gen_ms","hmac_gen_us","pt_len_bytes")]
        response=client._cipherchat_raw_post("/api/messages",headers=_auth(alice),json=missing)
        assert response.status_code==400 and response.json()["detail"]=="signature_required"
        bob_key_id,_=register_signer(client,bob)
        wrong_key={**valid,"signer_key_id":bob_key_id}
        wrong=client._cipherchat_raw_post("/api/messages",headers=_auth(alice),json=wrong_key)
        assert wrong.status_code==403 and wrong.json()["detail"]=="wrong_signing_key"
        for malformed_length in (63, 65):
            malformed = {**valid, "signature": base64.b64encode(bytes(malformed_length)).decode()}
            response = client._cipherchat_raw_post("/api/messages", headers=_auth(alice), json=malformed)
            assert response.status_code == 400 and response.json()["detail"] == "bad_signature_format"
        invalid_sig=bytearray(base64.b64decode(valid["signature"]));invalid_sig[0]^=1
        invalid={**valid,"signature":base64.b64encode(invalid_sig).decode()}
        rejected=client._cipherchat_raw_post("/api/messages",headers=_auth(alice),json=invalid)
        assert rejected.status_code==400 and rejected.json()["detail"]=="invalid_signature"
        with base.SessionLocal() as db:
            assert db.query(Message).count()==0
            event=db.query(AuditLog).filter(AuditLog.event_type=="SIGNATURE_REJECTED").one()
            assert event.details=={"reason":"invalid_signature","signer_key_id":valid["signer_key_id"]}


def test_ecdsa_rejects_out_of_range_scalars_and_accepts_high_s(client):
    from app.crypto.sigverify import P256_ORDER
    alice, bob = _get_token(client, "alice"), _get_token(client, "bob")
    with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
        sid, keys_a, _ = _establish_session(client, ws_a, ws_b, alice, bob)
        env = encrypt_message(keys_a.k_enc, keys_a.k_mac, sid, "I", 1, b"high-s")
        payload = signed_message_payload(client, alice, env, 6)
        signature = base64.b64decode(payload["signature"])
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        high_s_value = s if s > P256_ORDER // 2 else P256_ORDER - s
        assert high_s_value > P256_ORDER // 2
        high_s = r.to_bytes(32, "big") + high_s_value.to_bytes(32, "big")
        accepted = client._cipherchat_raw_post("/api/messages", headers=_auth(alice),
            json={**payload, "signature": base64.b64encode(high_s).decode()})
        assert accepted.status_code == 201
        ws_b.receive_json()

        env2 = encrypt_message(keys_a.k_enc, keys_a.k_mac, sid, "I", 2, b"bad scalar")
        payload2 = signed_message_payload(client, alice, env2, 10)
        signature2 = base64.b64decode(payload2["signature"])
        for raw in (bytes(32) + signature2[32:],
                    P256_ORDER.to_bytes(32, "big") + signature2[32:],
                    signature2[:32] + bytes(32),
                    signature2[:32] + P256_ORDER.to_bytes(32, "big")):
            rejected = client._cipherchat_raw_post("/api/messages", headers=_auth(alice),
                json={**payload2, "signature": base64.b64encode(raw).decode()})
            assert rejected.status_code == 400 and rejected.json()["detail"] == "invalid_signature"


def test_length_consistency_and_verification_rules(client):
    alice,bob=_get_token(client,"alice"),_get_token(client,"bob")
    with client.websocket_connect("/ws") as ws_a,client.websocket_connect("/ws") as ws_b:
        sid,keys_a,_=_establish_session(client,ws_a,ws_b,alice,bob)
        env=encrypt_message(keys_a.k_enc,keys_a.k_mac,sid,"I",1,b"abc")
        body=signed_message_payload(client,alice,env,3)
        inconsistent=client._cipherchat_raw_post("/api/messages",headers=_auth(alice),json={**body,"pt_len_bytes":30})
        assert inconsistent.status_code==400 and inconsistent.json()["detail"]=="length_inconsistent"
        sent=client.post("/api/messages",headers=_auth(alice),json=body)
        assert sent.status_code==201
        ws_b.receive_json()
        mid=sent.json()["id"]
        bad=client._cipherchat_raw_post(f"/api/messages/{mid}/verification",headers=_auth(bob),json={"status":"verified","sig_status":"invalid","sig_verify_ms":1.0})
        assert bad.status_code==400 and bad.json()["detail"]=="sig_inconsistent"
        good=client._cipherchat_raw_post(f"/api/messages/{mid}/verification",headers=_auth(bob),json={"status":"verified","sig_status":"valid","sig_verify_ms":1.0})
        assert good.status_code==204
        assert ws_a.receive_json()["sig_status"]=="valid"
