import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.db import base
from app.db.models import AuditLog, SigningKey
from app.crypto.sigsign import export_public_key, generate_keypair
from app.tests.test_messages_api import _get_token

pytest_plugins = ["app.tests.test_messages_api"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _key_body(key, **extra):
    return {"public_key_b64": base64.b64encode(export_public_key(key)).decode("ascii"), "keygen_ms": 12.5, **extra}


def test_key_registration_access_fingerprint_get_and_retirement(client):
    alice = _get_token(client, "alice")
    analyst = _get_token(client, "analyst", "analyst")
    key1 = generate_keypair()
    result = client.post("/api/keys", headers=_auth(alice), json=_key_body(key1))
    assert result.status_code == 201
    data = result.json()
    raw = export_public_key(key1)
    assert data["fingerprint"] == hashlib.sha256(raw).hexdigest()
    assert client.post("/api/keys", json=_key_body(generate_keypair())).status_code == 401
    assert client.post("/api/keys", headers=_auth(analyst), json=_key_body(generate_keypair())).status_code == 403
    fetched = client.get(f"/api/keys/{data['id']}", headers=_auth(analyst))
    assert fetched.status_code == 200 and base64.b64decode(fetched.json()["public_key_b64"]) == raw
    assert fetched.json()["user_id"] and fetched.json()["retired_at"] is None
    assert client.get("/api/keys/999999", headers=_auth(alice)).status_code == 404
    assert client.post("/api/keys", headers=_auth(alice), json=_key_body(key1)).status_code == 409

    key2 = generate_keypair()
    second = client.post("/api/keys", headers=_auth(alice), json=_key_body(key2))
    assert second.status_code == 201
    with base.SessionLocal() as db:
        rows = db.query(SigningKey).order_by(SigningKey.id).all()
        assert len(rows) == 2 and rows[0].retire_reason == "replaced" and rows[1].retired_at is None
        assert db.query(AuditLog).filter(AuditLog.event_type == "SIGNING_KEY_REGISTERED").count() == 2
        assert db.query(AuditLog).filter(AuditLog.event_type == "SIGNING_KEY_RETIRED").count() == 1
    assert client.post("/api/auth/logout", headers=_auth(alice)).status_code == 204
    with base.SessionLocal() as db:
        assert db.query(SigningKey).filter(SigningKey.retired_at.is_(None)).count() == 0
        assert db.query(SigningKey).filter(SigningKey.id == second.json()["id"]).one().retire_reason == "logout"


def test_key_rejects_invalid_point_encodings_and_private_material(client, setup_test_db):
    token = _get_token(client, "alice")
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_curve = ec.generate_private_key(ec.SECP384R1()).public_key()
    compressed = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    rsa_spki = rsa_key.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    private_scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value.to_bytes(32, "big")
    bad_values = [
        b"garbage", b"\x04" + bytes(64), compressed, rsa_spki,
        other_curve.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint),
        private_scalar,
    ]
    for raw in bad_values:
        response = client.post("/api/keys", headers=_auth(token), json={"public_key_b64": base64.b64encode(raw).decode()})
        assert response.status_code == 400 and response.json()["detail"] == "bad_public_key"
    assert client.post("/api/keys", headers=_auth(token), json={"public_key_b64": "!!!!"}).status_code == 400
    assert client.post("/api/keys", headers=_auth(token), json={**_key_body(generate_keypair()), "unexpected": 1}).status_code == 422
    with base.SessionLocal() as db:
        assert db.query(SigningKey).count() == 0
    database = Path(setup_test_db)
    if database.exists():
        stored = database.read_bytes()
        assert private_scalar not in stored


def test_key_registration_rate_limit(client):
    token = _get_token(client, "alice")
    responses = [client.post("/api/keys", headers=_auth(token), json=_key_body(generate_keypair())) for _ in range(11)]
    assert all(response.status_code == 201 for response in responses[:10])
    assert responses[-1].status_code == 429 and responses[-1].headers.get("retry-after")
