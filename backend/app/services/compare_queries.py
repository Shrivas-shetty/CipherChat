"""Persistence queries for the Secure vs Unsecured comparison lab."""
import base64
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.lab_models import CompareExchange, CompareRun, CompareTrial
from app.db.models import to_iso_z


def run_dict(row: CompareRun) -> dict[str, Any]:
    return {
        "id": row.id, "created_at": to_iso_z(row.created_at),
        "finished_at": to_iso_z(row.finished_at), "status": row.status,
        "analyst_id": row.analyst_id, "label": row.label,
        "input_text": row.input_text, "input_bytes": row.input_bytes,
        "trials": row.trials, "warmup": row.warmup,
        "setup_keygen_ms": row.setup_keygen_ms, "setup_dh_ms": row.setup_dh_ms,
        "setup_hkdf_ms": row.setup_hkdf_ms,
        "sig_public_key_b64": row.sig_public_key_b64,
        "sig_fingerprint": row.sig_fingerprint,
    }


def trial_dict(row: CompareTrial) -> dict[str, Any]:
    return {column.name: getattr(row, column.name) for column in CompareTrial.__table__.columns}


def list_runs(db: Session, limit: int = 50) -> list[dict[str, Any]]:
    rows = db.query(CompareRun).order_by(CompareRun.id.desc()).limit(max(1, min(limit, 200))).all()
    return [{"id": row.id, "created_at": to_iso_z(row.created_at),
             "finished_at": to_iso_z(row.finished_at), "status": row.status,
             "label": row.label, "input_preview": row.input_text[:80],
             "input_bytes": row.input_bytes, "trials": row.trials,
             "warmup": row.warmup,
             "trial_rows": db.query(func.count(CompareTrial.id)).filter(CompareTrial.run_id == row.id).scalar() or 0}
            for row in rows]


def get_run(db: Session, run_id: int) -> dict[str, Any] | None:
    row = db.query(CompareRun).filter(CompareRun.id == run_id).first()
    if row is None:
        return None
    trials = db.query(CompareTrial).filter(CompareTrial.run_id == run_id).order_by(
        CompareTrial.trial_no.asc(), CompareTrial.mode.asc(), CompareTrial.id.asc()).all()
    return {"run": run_dict(row), "trials": [trial_dict(item) for item in trials]}


def list_exchanges(db: Session, run_id: int, limit: int = 50,
                   after_id: int | None = None) -> list[dict[str, Any]]:
    query = db.query(CompareExchange).filter(CompareExchange.run_id == run_id)
    if after_id is not None:
        query = query.filter(CompareExchange.id > after_id)
    rows = query.order_by(CompareExchange.id.asc()).limit(max(1, min(limit, 200))).all()
    result = []
    for row in rows:
        result.append({
            "id": row.id, "created_at": to_iso_z(row.created_at), "mode": row.mode,
            "warmup": row.warmup, "text": row.text, "session_id": row.session_id,
            "sender_role": row.sender_role, "counter": row.counter,
            "msg_type": row.msg_type, "meta_json": row.meta_json,
            "iv_hex": row.iv.hex() if row.iv is not None else None,
            "ct_len": len(row.ct) if row.ct is not None else None,
            "ct_preview_hex": row.ct[:32].hex() if row.ct is not None else None,
            "hmac_hex": row.hmac.hex() if row.hmac is not None else None,
            "signature_preview_hex": row.signature[:32].hex() if row.signature is not None else None,
        })
    return result


def get_exchange(db: Session, run_id: int, exchange_id: int) -> dict[str, Any] | None:
    row = db.query(CompareExchange).filter(
        CompareExchange.id == exchange_id, CompareExchange.run_id == run_id).first()
    if row is None:
        return None
    result = {"id": row.id, "mode": row.mode}
    if row.mode == "unsecured":
        result["text"] = row.text
    else:
        result.update({"session_id": row.session_id, "sender_role": row.sender_role,
                       "counter": row.counter, "msg_type": row.msg_type,
                       "meta_json": row.meta_json,
                       "iv": base64.b64encode(row.iv).decode("ascii"),
                       "ct": base64.b64encode(row.ct).decode("ascii"),
                       "hmac": base64.b64encode(row.hmac).decode("ascii"),
                       "signature": base64.b64encode(row.signature).decode("ascii")})
    return result


def history(db: Session, limit: int = 50) -> list[dict[str, Any]]:
    runs = db.query(CompareRun).filter(CompareRun.status.in_(("complete", "stopped"))).order_by(
        CompareRun.id.desc()).limit(max(1, min(limit, 200))).all()
    result = []
    for run in runs:
        rows = db.query(CompareTrial).filter(CompareTrial.run_id == run.id,
            CompareTrial.warmup.is_(False)).order_by(CompareTrial.id.asc()).all()
        result.append({"id": run.id, "created_at": to_iso_z(run.created_at),
            "label": run.label, "input_bytes": run.input_bytes, "trials": run.trials,
            "status": run.status,
            "secured_totals": [row.total_ms for row in rows if row.mode == "secured"],
            "unsecured_totals": [row.total_ms for row in rows if row.mode == "unsecured"]})
    return result


def delete_run(db: Session, run: CompareRun) -> tuple[int, int]:
    trials = db.query(CompareTrial).filter(CompareTrial.run_id == run.id).delete(synchronize_session=False)
    exchanges = db.query(CompareExchange).filter(CompareExchange.run_id == run.id).delete(synchronize_session=False)
    db.delete(run)
    db.commit()
    return 1, exchanges + trials


def delete_all(db: Session) -> tuple[int, int]:
    runs = db.query(func.count(CompareRun.id)).scalar() or 0
    exchanges = db.query(func.count(CompareExchange.id)).scalar() or 0
    trials = db.query(func.count(CompareTrial.id)).scalar() or 0
    db.query(CompareTrial).delete(synchronize_session=False)
    db.query(CompareExchange).delete(synchronize_session=False)
    db.query(CompareRun).delete(synchronize_session=False)
    db.commit()
    return runs, exchanges + trials
