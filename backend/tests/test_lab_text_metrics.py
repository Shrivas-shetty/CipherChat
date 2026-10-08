import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, inspect

from app import config
from app.crypto.envelope import encrypt_message, image_meta_json
from app.db import base, lab_base
from app.db.base import Base, set_engine_and_session
from app.db.lab_base import LabBase, set_lab_engine_and_session
from app.db.lab_models import TextMetric
from app.db.models import AuditLog, Message, User
from app.main import create_app
from app.services.dashboard_queries import EVENT_CATEGORIES
from app.tests.test_messages_api import _establish_session, _get_token
from tests.tools.make_text_metric_vectors import make_vectors
from app.routers import lab as lab_router
from app.ws.manager import manager
from app.ws.session_coordinator import coordinator


@pytest.fixture
def scenario(tmp_path: Path):
    previous_app_engine, previous_lab_engine = base.engine, lab_base.engine
    app_engine = create_engine(f"sqlite:///{tmp_path / 'app.db'}", connect_args={"check_same_thread": False})
    lab_engine = create_engine(f"sqlite:///{tmp_path / 'lab.db'}", connect_args={"check_same_thread": False})
    set_engine_and_session(app_engine); set_lab_engine_and_session(lab_engine)
    Base.metadata.create_all(bind=app_engine); LabBase.metadata.create_all(bind=lab_engine)
    manager._users.clear(); manager._ws_to_user.clear()
    lab_router._post_times.clear()
    coordinator.active_session_id = None; coordinator.initiator = None; coordinator.responder = None; coordinator.status = "none"
    with TestClient(create_app()) as client:
        alice = _get_token(client, "alice")
        bob = _get_token(client, "bob")
        analyst = _get_token(client, "analyst", role="analyst")
        with client.websocket_connect("/ws") as ws_a, client.websocket_connect("/ws") as ws_b:
            sid, keys_a, keys_b = _establish_session(client, ws_a, ws_b, alice, bob)
            text_env = encrypt_message(keys_a.k_enc, keys_a.k_mac, sid, "I", 1, b"private-lab-plaintext")
            text_response = client.post("/api/messages", headers=_auth(alice), json={"session_id": sid, "counter": 1, "msg_type": "text", "meta_json": "{}", "iv": text_env.iv_b64, "ct": text_env.ct_b64, "hmac": text_env.hmac_b64})
            assert text_response.status_code == 201
            ws_b.receive_json()
            image_env = encrypt_message(keys_a.k_enc, keys_a.k_mac, sid, "I", 2, bytes(range(12)), "image", image_meta_json(2, 2))
            image_response = client.post("/api/messages", headers=_auth(alice), json={"session_id": sid, "counter": 2, "msg_type": "image", "meta_json": image_env.meta_json, "iv": image_env.iv_b64, "ct": image_env.ct_b64, "hmac": image_env.hmac_b64})
            assert image_response.status_code == 201
            ws_b.receive_json()
            text2_env = encrypt_message(keys_a.k_enc, keys_a.k_mac, sid, "I", 3, b"private-lab-plaintext")
            text2_response = client.post("/api/messages", headers=_auth(alice), json={"session_id": sid, "counter": 3, "msg_type": "text", "meta_json": "{}", "iv": text2_env.iv_b64, "ct": text2_env.ct_b64, "hmac": text2_env.hmac_b64})
            assert text2_response.status_code == 201
            ws_b.receive_json()
            yield {"client": client, "alice": alice, "bob": bob, "analyst": analyst, "sid": sid, "text_id": text_response.json()["id"], "text2_id": text2_response.json()["id"], "image_id": image_response.json()["id"], "text_ct": base64.b64decode(text_env.ct_b64), "image_ct": base64.b64decode(image_env.ct_b64), "image_iv": base64.b64decode(image_env.iv_b64), "image_pixels": bytes(range(12)), "keys_a": keys_a, "ws_b": ws_b, "key": keys_a.k_enc, "iv": base64.b64decode(text_env.iv_b64), "pt": b"private-lab-plaintext", "app_engine": app_engine, "lab_engine": lab_engine, "path": tmp_path / "lab.db"}
    Base.metadata.drop_all(bind=app_engine); LabBase.metadata.drop_all(bind=lab_engine)
    app_engine.dispose(); lab_engine.dispose()
    set_engine_and_session(previous_app_engine); set_lab_engine_and_session(previous_lab_engine)


def _auth(token: str | None):
    return {"Authorization": f"Bearer {token}"} if token else {}


def _payload(scenario, message_id=None):
    pt = scenario["pt"]
    ct_len = len(scenario["text_ct"])
    return {"message_id": message_id or scenario["text_id"], "session_id": scenario["sid"], "pt_len_bytes": len(pt), "ct_len_bytes": ct_len, "total_ct_bits": ct_len * 8, "key_trials": 2, "confusion_pct": 49.5, "key_flip_pcts": [48.0, 51.0], "pt_trials": 2, "diffusion_bits": 60.0, "avalanche_pct": 50.0, "block_avalanche_pct": 50.0, "pt_flip_bit_idx": [0, 7], "pt_flip_changed_bits": [63, 57], "pt_flip_block_changed_bits": [63, 57], "enc_us": 4.5, "dec_us": 5.5, "timing_iters": 8}


def test_pydantic_schema_and_oracle_regeneration():
    from app.routers.lab import TextMetricRequest
    fields = TextMetricRequest.model_fields
    assert set(fields) == {"message_id", "session_id", "pt_len_bytes", "ct_len_bytes", "total_ct_bits", "key_trials", "confusion_pct", "key_flip_pcts", "pt_trials", "diffusion_bits", "avalanche_pct", "block_avalanche_pct", "pt_flip_bit_idx", "pt_flip_changed_bits", "pt_flip_block_changed_bits", "enc_us", "dec_us", "timing_iters"}
    assert fields["session_id"].annotation is str
    for name, field in fields.items():
        if name == "session_id": continue
        schema = TextMetricRequest.model_json_schema()["properties"][name]
        assert schema.get("type") in {"integer", "number", "array"}
        if schema.get("type") == "array": assert schema["items"].get("type") in {"integer", "number"}
    assert json.loads((Path(__file__).resolve().parents[2] / "shared/test_vectors/text_metrics.json").read_text()) == make_vectors()
    seen = [name for category in EVENT_CATEGORIES.values() for name in category]
    assert len(seen) == len(set(seen))
    app_root = Path(__file__).resolve().parents[1] / "app"
    for relative in ("routers/lab.py", "services/lab_queries.py", "db/lab_models.py"):
        source = (app_root / relative).read_text(encoding="utf-8")
        for forbidden in ("app.crypto.envelope", "app.crypto.kdf", "cryptography"):
            assert forbidden not in source


def test_post_authorization_validation_storage_and_secret_separation(scenario):
    client, payload = scenario["client"], _payload(scenario)
    url = "/api/lab/text-metrics"
    assert client.post(url, json=payload).status_code == 401
    assert client.post(url, json=payload, headers=_auth(scenario["analyst"])).status_code == 403
    assert client.post(url, json=payload, headers=_auth(scenario["bob"])).status_code == 403

    with base.SessionLocal() as db:
        bob_user = db.query(User).filter(User.username == "bob").one()
        # Receiver cannot attribute its own report to the sender's message.
        assert bob_user.id != db.query(Message).filter(Message.id == scenario["text_id"]).one().sender_id

    response = client.post(url, json=payload, headers=_auth(scenario["alice"]))
    assert response.status_code == 201
    metric_id = response.json()["id"]
    assert client.post(url, json=payload, headers=_auth(scenario["alice"])).status_code == 409
    with lab_base.LabSessionLocal() as db:
        row = db.query(TextMetric).one()
        assert row.id == metric_id and row.message_id == payload["message_id"] and row.sender_id == 1
        assert row.key_flip_pcts == payload["key_flip_pcts"] and row.pt_flip_bit_idx == payload["pt_flip_bit_idx"]
        db.execute(__import__("sqlalchemy").text("PRAGMA wal_checkpoint(FULL)"))
    raw_db = scenario["path"].read_bytes()
    for secret in (scenario["pt"], scenario["key"], scenario["key"].hex().encode(), scenario["iv"], scenario["iv"].hex().encode(), scenario["text_ct"], scenario["text_ct"].hex().encode()):
        assert secret not in raw_db
    columns = inspect(scenario["lab_engine"]).get_columns("text_metrics")
    for column in columns:
        if column["name"] == "session_id": continue
        assert column["type"].__class__.__name__.lower() in {"integer", "float", "json", "datetime"}


@pytest.mark.parametrize(("mutate", "code"), [
    (lambda p: p.update(message_id=999999), "unknown_message"),
    (lambda p: p.update(session_id="00000000-0000-0000-0000-000000000000"), "session_mismatch"),
    (lambda p: p.update(pt_len_bytes=p["pt_len_bytes"] + 20), "length_inconsistent"),
    (lambda p: p.update(key_trials=3), "trial_count"),
    (lambda p: p.update(pt_flip_block_changed_bits=[129, 1]), "out_of_range"),
    (lambda p: p.update(enc_us=0), "out_of_range"),
    (lambda p: p.update(confusion_pct=101.0), "out_of_range"),
    (lambda p: p.update(pt_flip_bit_idx=[0, p["pt_len_bytes"] * 8]), "out_of_range"),
    (lambda p: p.update(pt_flip_changed_bits=[p["total_ct_bits"] + 1, 1]), "out_of_range"),
    (lambda p: p.update(diffusion_bits=p["total_ct_bits"] + 1), "out_of_range"),
    (lambda p: p.update(avalanche_pct=101.0), "out_of_range"),
    (lambda p: p.update(dec_us=5_000_001.0), "out_of_range"),
    (lambda p: p.update(timing_iters=5001), "out_of_range"),
    (lambda p: p.update(pt_trials=3), "trial_count"),
])
def test_rejection_codes_are_audited(scenario, mutate, code):
    payload = _payload(scenario); mutate(payload)
    response = scenario["client"].post("/api/lab/text-metrics", json=payload, headers=_auth(scenario["alice"]))
    assert response.status_code == 400 and response.json()["detail"]["code"] == code
    with base.SessionLocal() as db:
        event = db.query(AuditLog).filter(AuditLog.event_type == "METRICS_REJECTED").order_by(AuditLog.id.desc()).first()
        assert event and event.details == {"reason": code, "message_id": payload["message_id"]}
    with lab_base.LabSessionLocal() as db: assert db.query(TextMetric).count() == 0


def test_wrong_type_session_and_strict_payload(scenario):
    client = scenario["client"]
    wrong_type = _payload(scenario, scenario["image_id"])
    assert client.post("/api/lab/text-metrics", json=wrong_type, headers=_auth(scenario["alice"])).json()["detail"]["code"] == "wrong_type"
    bob_report = client.post("/api/lab/text-metrics", json=_payload(scenario), headers=_auth(scenario["bob"]))
    assert bob_report.status_code == 403 and bob_report.json()["detail"]["code"] == "not_sender"
    for body in ({**_payload(scenario), "plaintext": "secret"}, {**_payload(scenario), "pt_len_bytes": "21"}, {**_payload(scenario), "key_trials": True}):
        assert client.post("/api/lab/text-metrics", json=body, headers=_auth(scenario["alice"])).status_code == 422
    nan_payload = json.dumps({**_payload(scenario), "confusion_pct": float("nan")}, allow_nan=True)
    assert client.post("/api/lab/text-metrics", content=nan_payload, headers={**_auth(scenario["alice"]), "Content-Type": "application/json"}).status_code == 422
    oversized = client.post("/api/lab/text-metrics", content=b" " * 4097, headers={**_auth(scenario["alice"]), "Content-Type": "application/json"})
    assert oversized.status_code == 413
    with lab_base.LabSessionLocal() as db: assert db.query(TextMetric).count() == 0


def test_rate_limit_and_analyst_dashboard_clear(scenario, monkeypatch):
    client = scenario["client"]
    assert client.get("/api/dashboard/lab/text/records").status_code == 401
    assert client.delete("/api/dashboard/lab/text").status_code == 401
    assert client.get("/api/dashboard/lab/text/records", headers=_auth(scenario["alice"])).status_code == 403
    assert client.delete("/api/dashboard/lab/text", headers=_auth(scenario["alice"])).status_code == 403
    monkeypatch.setattr(config, "LAB_POSTS_PER_MINUTE", 1)
    # One successful post consumes the rate slot; subsequent valid posts are throttled.
    assert client.post("/api/lab/text-metrics", json=_payload(scenario), headers=_auth(scenario["alice"])).status_code == 201
    response = client.post("/api/lab/text-metrics", json={**_payload(scenario), "message_id": 999998}, headers=_auth(scenario["alice"]))
    assert response.status_code == 429 and response.headers.get("retry-after")
    monkeypatch.setattr(config, "LAB_POSTS_PER_MINUTE", 30)
    analyst = _auth(scenario["analyst"])
    before_audit = _audit_count()
    page = client.get("/api/dashboard/lab/text/records?limit=9999", headers=analyst)
    assert page.status_code == 200
    data = page.json()
    assert data["total"] == 1 and data["items"][0]["sender"] == "alice"
    assert "ct_preview_hex" not in data["items"][0]
    payload_json = json.dumps(data)
    for forbidden in ('"ct"', '"iv"', '"hmac"', '"plaintext"'): assert forbidden not in payload_json
    summary = client.get("/api/dashboard/summary", headers=analyst).json()
    assert summary["lab"]["text_records"] == 1
    assert _audit_count() == before_audit
    assert client.post("/api/lab/text-metrics", json=_payload(scenario, scenario["text2_id"]), headers=_auth(scenario["alice"])).status_code == 201
    first_page = client.get("/api/dashboard/lab/text/records?limit=1", headers=analyst).json()
    older_page = client.get(f"/api/dashboard/lab/text/records?limit=1&before_id={first_page['items'][0]['id']}", headers=analyst).json()
    assert first_page["total"] == 2 and first_page["has_more_older"] is True
    assert first_page["items"][0]["id"] > older_page["items"][0]["id"] and older_page["has_more_older"] is False
    cleared = client.delete("/api/dashboard/lab/text", headers=analyst)
    assert cleared.status_code == 200 and cleared.json() == {"deleted": 2}
    assert client.get("/api/dashboard/lab/text/records", headers=analyst).json()["total"] == 0
    with base.SessionLocal() as db: assert db.query(AuditLog).filter(AuditLog.event_type == "LAB_DATA_CLEARED").count() == 1


def _audit_count():
    with base.SessionLocal() as db: return db.query(func.count(AuditLog.id)).scalar()
