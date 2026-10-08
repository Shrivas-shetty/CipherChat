import base64
import json
from pathlib import Path

import pytest
from sqlalchemy import inspect

pytest_plugins = ["tests.test_lab_text_metrics"]

from app.crypto.envelope import encrypt_message, image_meta_json
from app.db import base, lab_base
from app.db.lab_models import ImageMetric
from app.db.models import AuditLog
from app.routers import lab as lab_router
from app.routers.lab import ImageMetricRequest
from app.services.audit import verify_chain_detailed
from tests.test_lab_text_metrics import _auth
from tests.tools.make_image_metric_vectors import make_vectors


def payload(scenario):
    return {
        "message_id": scenario["image_id"], "session_id": scenario["sid"], "width": 2, "height": 2,
        "n_pixels": 4, "pt_len_bytes": 12, "ct_len_bytes": 16, "npcr_trials": 2,
        "npcr_pct": 58.0, "npcr_trial_pcts": [60.0, 56.0], "npcr_changed_counts": [7, 6],
        "uaci_pct": 18.0, "uaci_trial_pcts": [19.0, 17.0], "flip_byte_idx": [0, 11],
        "entropy_r": 2.0, "entropy_g": 2.0, "entropy_b": 2.0, "entropy_avg": 2.0,
        "corr_pt_r": None, "corr_pt_g": None, "corr_pt_b": None, "corr_pt_avg": None,
        "corr_ct_r": None, "corr_ct_g": None, "corr_ct_b": None, "corr_ct_avg": None,
        "mse_dec": 0.0, "psnr_dec": None, "mse_enc": 9000.0, "psnr_enc": 8.59,
        "enc_us": 12.3, "dec_us": 15.2, "timing_iters": 1,
    }


def test_image_schema_and_oracle_is_deterministic():
    assert ImageMetricRequest.model_fields.keys() == payload_schema_names()
    assert ImageMetricRequest.model_fields["session_id"].annotation is str
    properties = ImageMetricRequest.model_json_schema()["properties"]
    nullable = {"corr_pt_r", "corr_pt_g", "corr_pt_b", "corr_pt_avg", "corr_ct_r", "corr_ct_g", "corr_ct_b", "corr_ct_avg", "psnr_dec", "psnr_enc"}
    for name, schema in properties.items():
        if name == "session_id":
            assert schema["type"] == "string"
            continue
        variants = schema.get("anyOf", [schema])
        types = {variant.get("type") for variant in variants}
        assert types <= ({"number", "null"} if name in nullable else {"integer", "number", "array"})
        if name not in nullable: assert "null" not in types
        if schema.get("type") == "array": assert schema["items"]["type"] in {"integer", "number"}
    root = Path(__file__).resolve().parents[2]
    vectors = json.loads((root / "shared/test_vectors/image_metrics.json").read_text(encoding="utf-8"))
    assert vectors == make_vectors()
    for relative in ("backend/app/routers/lab.py", "backend/app/services/lab_queries.py", "backend/app/db/lab_models.py"):
        source = (root / relative).read_text(encoding="utf-8")
        assert "app.crypto." not in source and "cryptography" not in source


def payload_schema_names():
    return set(payload({"image_id": 1, "sid": "x"})) - set()


def test_image_post_and_analyst_cipher_noise_endpoints(scenario):
    client, body = scenario["client"], payload(scenario)
    url = "/api/lab/image-metrics"
    assert client.post(url, json=body).status_code == 401
    assert client.post(url, json=body, headers=_auth(scenario["analyst"])).status_code == 403
    rejected = client.post(url, json=body, headers=_auth(scenario["bob"]))
    assert rejected.status_code == 403 and rejected.json()["detail"]["code"] == "not_sender"
    audit_before = _audit_count()
    response = client.post(url, json=body, headers=_auth(scenario["alice"]))
    assert response.status_code == 201
    assert _audit_count() == audit_before
    duplicate = client.post(url, json=body, headers=_auth(scenario["alice"]))
    assert duplicate.status_code == 409 and duplicate.json()["detail"]["code"] == "already_recorded"
    with lab_base.LabSessionLocal() as db:
        row = db.query(ImageMetric).one()
        assert row.message_id == body["message_id"] and row.npcr_trial_pcts == body["npcr_trial_pcts"]
        assert row.corr_ct_avg is None and row.psnr_dec is None
        db.execute(__import__("sqlalchemy").text("PRAGMA wal_checkpoint(FULL)"))
    raw = (scenario["path"]).read_bytes()
    for secret in (scenario["key"], scenario["image_pixels"], scenario["image_iv"], scenario["image_ct"]):
        assert secret not in raw
    for col in inspect(scenario["lab_engine"]).get_columns("image_metrics"):
        assert col["type"].__class__.__name__.lower() != "blob"

    analyst = _auth(scenario["analyst"])
    before = _audit_count()
    page = client.get("/api/dashboard/lab/image/records?limit=9999", headers=analyst)
    assert page.status_code == 200
    data = page.json()
    assert data["total"] == 1 and data["items"][0]["sender"] == "alice"
    assert data["items"][0]["message_created_at"] is not None
    serialized = json.dumps(data)
    for secret_key in ('"ct"', '"iv"', '"hmac"', '"key"', '"noise_rgb_b64"'):
        assert secret_key not in serialized
    assert _audit_count() == before
    noise = client.get(f"/api/dashboard/lab/image/{scenario['image_id']}/cipher-noise", headers=analyst)
    assert noise.status_code == 200 and noise.headers["cache-control"] == "private, max-age=300"
    assert noise.json()["noise_rgb_b64"] and len(base64.b64decode(noise.json()["noise_rgb_b64"])) == 12
    assert base64.b64decode(noise.json()["noise_rgb_b64"]) == scenario["image_ct"][:12]
    # A 4x4 image has 48 image bytes (a multiple of the AES block size) and 64 stored ciphertext bytes.
    env = encrypt_message(scenario["keys_a"].k_enc, scenario["keys_a"].k_mac, scenario["sid"], "I", 4,
                         bytes(range(48)), "image", image_meta_json(4, 4))
    sent = client.post("/api/messages", headers=_auth(scenario["alice"]), json={
        "session_id": scenario["sid"], "counter": 4, "msg_type": "image", "meta_json": env.meta_json,
        "iv": env.iv_b64, "ct": env.ct_b64, "hmac": env.hmac_b64,
    })
    assert sent.status_code == 201
    scenario["ws_b"].receive_json()
    aligned = client.get(f"/api/dashboard/lab/image/{sent.json()['id']}/cipher-noise", headers=analyst)
    assert len(base64.b64decode(aligned.json()["noise_rgb_b64"])) == 48
    assert base64.b64decode(aligned.json()["noise_rgb_b64"]) == base64.b64decode(env.ct_b64)[:48]
    assert client.get(f"/api/dashboard/lab/image/{scenario['text_id']}/cipher-noise", headers=analyst).status_code == 404
    assert client.get("/api/dashboard/lab/image/999999/cipher-noise", headers=analyst).status_code == 404
    assert client.get("/api/dashboard/lab/image/records").status_code == 401
    assert client.get("/api/dashboard/lab/image/records", headers=_auth(scenario["alice"])).status_code == 403
    summary = client.get("/api/dashboard/summary", headers=analyst).json()
    assert summary["lab"]["image_records"] == 1

    clear = client.delete("/api/dashboard/lab/image", headers=analyst)
    assert clear.status_code == 200 and clear.json() == {"deleted": 1}
    assert client.get("/api/dashboard/lab/image/records", headers=analyst).json()["total"] == 0
    with base.SessionLocal() as db:
        event = db.query(AuditLog).filter(AuditLog.event_type == "LAB_DATA_CLEARED").order_by(AuditLog.id.desc()).first()
        assert event and event.details == {"table": "image_metrics", "rows_deleted": 1}
    assert verify_chain_detailed(base.SessionLocal()).get("ok")


@pytest.mark.parametrize(("changes", "code"), [
    ({"message_id": 999999}, "unknown_message"),
    ({"message_id": 1}, "wrong_type"),
    ({"session_id": "00000000-0000-0000-0000-000000000000"}, "session_mismatch"),
    ({"width": 3}, "dimension_mismatch"),
    ({"pt_len_bytes": 13}, "length_inconsistent"),
    ({"npcr_trial_pcts": [1.0]}, "trial_count"),
    ({"npcr_pct": 101.0}, "out_of_range"),
    ({"flip_byte_idx": [0, 12]}, "out_of_range"),
    ({"entropy_avg": 8.1}, "out_of_range"),
    ({"corr_ct_r": 1.1}, "out_of_range"),
    ({"mse_dec": 5.0}, "psnr_inconsistent"),
])
def test_rejects_invalid_image_metrics_and_audits_reason(scenario, changes, code):
    body = payload(scenario); body.update(changes)
    response = scenario["client"].post("/api/lab/image-metrics", json=body, headers=_auth(scenario["alice"]))
    assert response.status_code == 400 and response.json()["detail"]["code"] == code
    with base.SessionLocal() as db:
        event = db.query(AuditLog).filter(AuditLog.event_type == "METRICS_REJECTED").order_by(AuditLog.id.desc()).first()
        assert event and event.details == {"reason": code, "message_id": body["message_id"]}
    with lab_base.LabSessionLocal() as db: assert db.query(ImageMetric).count() == 0


def test_image_payload_strictness_and_shared_rate_limit(scenario, monkeypatch):
    client, body = scenario["client"], payload(scenario)
    for bad in ({**body, "pixels": [1]}, {**body, "width": "2"}, {**body, "npcr_trials": True}):
        assert client.post("/api/lab/image-metrics", json=bad, headers=_auth(scenario["alice"])).status_code == 422
    oversized = client.post("/api/lab/image-metrics", content=b" " * 4097,
                            headers={**_auth(scenario["alice"]), "Content-Type": "application/json"})
    assert oversized.status_code == 413
    monkeypatch.setattr(__import__("app.config", fromlist=["LAB_POSTS_PER_MINUTE"]), "LAB_POSTS_PER_MINUTE", 1)
    assert client.post("/api/lab/text-metrics", json=__import__("tests.test_lab_text_metrics", fromlist=["_payload"])._payload(scenario), headers=_auth(scenario["alice"])).status_code == 201
    limited = client.post("/api/lab/image-metrics", json=body, headers=_auth(scenario["alice"]))
    assert limited.status_code == 429 and limited.headers.get("retry-after")


def _audit_count():
    with base.SessionLocal() as db: return db.query(AuditLog).count()
