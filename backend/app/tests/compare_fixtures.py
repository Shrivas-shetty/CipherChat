from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app.db import base, lab_base, network_base
from app.db.base import Base, set_engine_and_session
from app.db.lab_base import LabBase, set_lab_engine_and_session
from app.db.network_base import set_network_engine_and_session
from app.db.network_models import NetworkBase
from app.main import create_app
from app.tests.test_messages_api import _get_token


@pytest.fixture
def compare_client(tmp_path: Path, monkeypatch):
    old_app, old_lab, old_network = base.engine, lab_base.engine, network_base.engine
    app_engine = create_engine(f"sqlite:///{tmp_path / 'app.db'}", connect_args={"check_same_thread": False})
    lab_engine = create_engine(f"sqlite:///{tmp_path / 'lab.db'}", connect_args={"check_same_thread": False})
    net_engine = create_engine(f"sqlite:///{tmp_path / 'network.db'}", connect_args={"check_same_thread": False})
    set_engine_and_session(app_engine)
    set_lab_engine_and_session(lab_engine)
    set_network_engine_and_session(net_engine)
    from app import config
    monkeypatch.setattr(config, "get_pcap_dir", lambda: tmp_path / "pcaps")
    Base.metadata.create_all(app_engine)
    LabBase.metadata.create_all(lab_engine)
    NetworkBase.metadata.create_all(net_engine)
    with TestClient(create_app()) as client:
        analyst = _get_token(client, "cmp_analyst", "analyst")
        user = _get_token(client, "cmp_user")
        yield {"client": client, "analyst": {"Authorization": f"Bearer {analyst}"},
               "user": {"Authorization": f"Bearer {user}"}, "app_engine": app_engine,
               "lab_engine": lab_engine, "lab_path": tmp_path / "lab.db"}
    app_engine.dispose(); lab_engine.dispose(); net_engine.dispose()
    set_engine_and_session(old_app)
    set_lab_engine_and_session(old_lab)
    set_network_engine_and_session(old_network)


def run_payload(**overrides):
    import base64
    body = {"label": "api run", "input_text": "hello", "trials": 1, "warmup": 0,
        "setup_keygen_ms": 1.0, "setup_dh_ms": 2.0, "setup_hkdf_ms": 1.0,
        "sig_public_key_b64": base64.b64encode(b"\x04" + b"x" * 64).decode("ascii")}
    return {**body, **overrides}


def unsecured_payload():
    return {"mode": "unsecured", "warmup": False, "text": "hello"}


def secured_payload(warmup=False):
    import base64
    return {"mode": "secured", "warmup": warmup, "session_id": "12345678-1234-4234-9234-123456789abc",
        "sender_role": "I", "counter": 1, "msg_type": "text", "meta_json": "{}",
        "iv": base64.b64encode(b"i" * 16).decode("ascii"),
        "ct": base64.b64encode(b"c" * 16).decode("ascii"),
        "hmac": base64.b64encode(b"h" * 32).decode("ascii"),
        "signature": base64.b64encode(b"s" * 64).decode("ascii")}


def trial_payload(exchange_id, mode, *, warmup=False):
    common = {"trial_no": 0 if warmup else 1, "mode": mode, "warmup": warmup,
        "exchange_id": exchange_id, "total_ms": 4.0, "prep_ms": 1.0,
        "post_ms": 1.0, "get_ms": 1.0, "finish_ms": 1.0,
        "post_req_bytes": 150, "post_resp_bytes": 10, "get_resp_bytes": 100,
        "plaintext_bytes": 5, "roundtrip_ok": True}
    if mode == "secured":
        common.update({"seal_ms": .1, "sign_ms": .1, "verify_hmac_ms": .1,
            "verify_sig_ms": .1, "decrypt_ms": .1, "ciphertext_bytes": 16,
            "integrity_ok": True, "signature_ok": True})
    else:
        common.update({"seal_ms": None, "sign_ms": None, "verify_hmac_ms": None,
            "verify_sig_ms": None, "decrypt_ms": None, "ciphertext_bytes": None,
            "integrity_ok": None, "signature_ok": None})
    return common
