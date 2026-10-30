from collections import Counter
import base64
from pathlib import Path

import pytest
from sqlalchemy import event

pytest_plugins = ["app.tests.compare_fixtures"]

from app.db import base
from app.db import lab_base
from app.db.models import AuditLog
from app.db.models import ChatSession, Message, SigningKey
from app.db.lab_models import CompareExchange, CompareRun, CompareTrial, ImageMetric, TextMetric
from app.services.audit import verify_chain
from app.tests.compare_fixtures import run_payload, secured_payload, trial_payload, unsecured_payload
from app.tests.test_compare_api import BASE


def test_modes_have_matching_sql_shapes_and_no_exchange_audit(compare_client):
    c, headers = compare_client["client"], compare_client["analyst"]
    run_id = c.post(f"{BASE}/runs", headers=headers, json=run_payload()).json()["id"]
    statements = []
    def capture(conn, _cursor, statement, _params, _context, _many):
        first = statement.lstrip().split(None, 1)[0].upper()
        if first in {"SELECT", "INSERT", "UPDATE", "DELETE"}:
            statements.append(("lab" if conn.engine is compare_client["lab_engine"] else "app", first))
    event.listen(compare_client["lab_engine"], "before_cursor_execute", capture)
    event.listen(compare_client["app_engine"], "before_cursor_execute", capture)
    try:
        with base.SessionLocal() as db:
            audit_before = db.query(AuditLog.event_type).all()
        statements.clear()
        secure_id = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=secured_payload()).json()["id"]
        secured_shape = Counter(statements)
        statements.clear()
        plain_id = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=unsecured_payload()).json()["id"]
        plain_shape = Counter(statements)
        assert secured_shape == plain_shape
        assert secured_shape[("lab", "INSERT")] == 1
        statements.clear()
        c.get(f"{BASE}/runs/{run_id}/exchanges/{secure_id}", headers=headers)
        secure_get_shape = Counter(statements)
        statements.clear()
        c.get(f"{BASE}/runs/{run_id}/exchanges/{plain_id}", headers=headers)
        plain_get_shape = Counter(statements)
        assert secure_get_shape == plain_get_shape
        assert secure_get_shape[("lab", "SELECT")] == 1
        with base.SessionLocal() as db:
            assert db.query(AuditLog.event_type).all() == audit_before
    finally:
        event.remove(compare_client["lab_engine"], "before_cursor_execute", capture)
        event.remove(compare_client["app_engine"], "before_cursor_execute", capture)


def test_compare_router_and_queries_have_no_crypto_dependencies():
    root = Path(__file__).resolve().parents[1]
    for relative in ("routers/compare.py", "services/compare_queries.py"):
        source = (root / relative).read_text(encoding="utf-8").lower()
        assert "from app.crypto" not in source and "import app.crypto" not in source
        assert "import cryptography" not in source and "from cryptography" not in source
        assert "verify_ecdsa(" not in source and "sign_ecdsa(" not in source
        assert "hmac.new(" not in source and "verify_signature(" not in source


def test_real_reference_envelope_roundtrips_and_secrets_are_not_persisted(compare_client):
    from cryptography.hazmat.primitives.asymmetric import ec
    from app.crypto.envelope import encrypt_message, verify_and_decrypt
    from app.crypto.kdf import derive_session_keys
    from app.crypto.sigsign import export_public_key, sign_ecdsa
    from app.crypto.sigverify import build_signature_input, verify_ecdsa

    c, headers = compare_client["client"], compare_client["analyst"]
    private = ec.generate_private_key(ec.SECP256R1())
    public = export_public_key(private)
    # Public benchmark key registration takes no private-key or symmetric-key data.
    run_id = c.post(f"{BASE}/runs", headers=headers,
        json=run_payload(sig_public_key_b64=base64.b64encode(public).decode())).json()["id"]
    keys = derive_session_keys(b"z" * 256, "12345678-1234-4234-9234-123456789abc", b"i" * 256, b"r" * 256)
    env = encrypt_message(keys.k_enc, keys.k_mac, "12345678-1234-4234-9234-123456789abc", "I", 1, b"hello")
    from app.crypto.sigverify import build_mac_input_bytes
    mac_input = build_mac_input_bytes(env.session_id, env.sender_role, env.counter, env.msg_type,
        env.meta_json, env.iv, env.ct)
    signature = sign_ecdsa(private, build_signature_input(mac_input, env.hmac))
    payload = {"mode": "secured", "warmup": False, "session_id": env.session_id,
        "sender_role": env.sender_role, "counter": env.counter, "msg_type": env.msg_type,
        "meta_json": env.meta_json, "iv": env.iv_b64, "ct": env.ct_b64,
        "hmac": env.hmac_b64, "signature": base64.b64encode(signature).decode()}
    exchange_id = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=payload).json()["id"]
    received = c.get(f"{BASE}/runs/{run_id}/exchanges/{exchange_id}", headers=headers).json()
    from app.crypto.envelope import Envelope
    saved = Envelope(received["session_id"], received["sender_role"], received["counter"],
        received["msg_type"], received["meta_json"], base64.b64decode(received["iv"]),
        base64.b64decode(received["ct"]), base64.b64decode(received["hmac"]))
    assert verify_and_decrypt(keys.k_enc, keys.k_mac, saved.session_id, "I", saved, 0) == b"hello"
    signature_input = build_signature_input(build_mac_input_bytes(saved.session_id, "I", 1,
        "text", "{}", saved.iv, saved.ct), saved.hmac)
    assert verify_ecdsa(public, signature, signature_input)
    db_bytes = compare_client["lab_path"].read_bytes()
    wal = compare_client["lab_path"].with_name("lab.db-wal")
    if wal.exists():
        db_bytes += wal.read_bytes()
    for secret in (keys.k_enc, keys.k_mac, private.private_numbers().private_value.to_bytes(32, "big")):
        assert secret not in db_bytes
    assert not any(name.lower() in {"key", "private", "k_enc", "k_mac"}
                   for name in received)
    assert verify_chain()[0]


def test_lifecycle_isolated_to_cmp_tables_and_compare_audits(compare_client):
    c, headers = compare_client["client"], compare_client["analyst"]
    with base.SessionLocal() as app_db:
        app_before = {model.__tablename__: app_db.query(model).count()
                      for model in (Message, ChatSession, SigningKey)}
        events_before = [row.event_type for row in app_db.query(AuditLog).all()]
    with lab_base.LabSessionLocal() as lab_db:
        metrics_before = {model.__tablename__: lab_db.query(model).count()
                          for model in (TextMetric, ImageMetric)}
    run_id = c.post(f"{BASE}/runs", headers=headers, json=run_payload()).json()["id"]
    secure_id = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=secured_payload()).json()["id"]
    plain_id = c.post(f"{BASE}/runs/{run_id}/exchanges", headers=headers, json=unsecured_payload()).json()["id"]
    result = c.post(f"{BASE}/runs/{run_id}/finalize", headers=headers,
        json={"status": "complete", "trials": [
            trial_payload(secure_id, "secured"), trial_payload(plain_id, "unsecured")]})
    assert result.status_code == 200
    with base.SessionLocal() as app_db:
        assert {model.__tablename__: app_db.query(model).count()
                for model in (Message, ChatSession, SigningKey)} == app_before
        events_after = [row.event_type for row in app_db.query(AuditLog).all()]
        added = events_after[len(events_before):]
        assert added and all(name.startswith("COMPARE_") for name in added)
    with lab_base.LabSessionLocal() as lab_db:
        assert {model.__tablename__: lab_db.query(model).count()
                for model in (TextMetric, ImageMetric)} == metrics_before
        assert lab_db.query(CompareRun).count() == 1
        assert lab_db.query(CompareExchange).count() == 2
        assert lab_db.query(CompareTrial).count() == 2
    assert verify_chain()[0]
