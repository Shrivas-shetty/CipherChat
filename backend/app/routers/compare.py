"""Analyst-only persistence endpoints for Secure vs Unsecured measurements.

The timed exchange paths intentionally perform no benchmark cryptography.
"""
import base64
import binascii
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, StrictBool, StrictFloat, StrictInt, StrictStr, Field, ValidationError
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.lab_base import get_lab_db
from app.db.lab_models import CompareExchange, CompareRun, CompareTrial
from app.db.models import User, utc_now, to_iso_z
from app.deps import require_role
from app.services.audit import log_event
from app.services import compare_queries as queries

router = APIRouter(prefix="/api/dashboard/compare", tags=["comparison benchmark"])
analyst = Depends(require_role("analyst"))
SAFE_LABEL = re.compile(r"^[A-Za-z0-9 _.\-]+$")
MAX_EXCHANGES = 500


def clock_now() -> datetime:
    return datetime.now(timezone.utc)


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    label: StrictStr = Field(min_length=1, max_length=64)
    input_text: StrictStr = Field(min_length=1, max_length=2000)
    trials: StrictInt = Field(ge=1, le=100)
    warmup: StrictInt = Field(ge=0, le=10)
    setup_keygen_ms: StrictFloat = Field(gt=0, le=600000)
    setup_dh_ms: StrictFloat = Field(gt=0, le=600000)
    setup_hkdf_ms: StrictFloat = Field(gt=0, le=600000)
    sig_public_key_b64: StrictStr = Field(min_length=1, max_length=100)


class ExchangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    mode: Literal["secured", "unsecured"]
    warmup: StrictBool = False
    text: StrictStr | None = None
    session_id: StrictStr | None = None
    sender_role: StrictStr | None = None
    counter: StrictInt | None = None
    msg_type: StrictStr | None = None
    meta_json: StrictStr | None = None
    iv: StrictStr | None = None
    ct: StrictStr | None = None
    hmac: StrictStr | None = None
    signature: StrictStr | None = None


class TrialIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    trial_no: StrictInt = Field(ge=0)
    mode: Literal["secured", "unsecured"]
    warmup: StrictBool
    exchange_id: StrictInt = Field(ge=1)
    total_ms: StrictFloat = Field(gt=0, le=600000)
    prep_ms: StrictFloat = Field(gt=0, le=600000)
    post_ms: StrictFloat = Field(gt=0, le=600000)
    get_ms: StrictFloat = Field(gt=0, le=600000)
    finish_ms: StrictFloat = Field(gt=0, le=600000)
    seal_ms: StrictFloat | None
    sign_ms: StrictFloat | None
    verify_hmac_ms: StrictFloat | None
    verify_sig_ms: StrictFloat | None
    decrypt_ms: StrictFloat | None
    post_req_bytes: StrictInt = Field(ge=0, le=1_000_000)
    post_resp_bytes: StrictInt = Field(ge=0, le=1_000_000)
    get_resp_bytes: StrictInt = Field(ge=0, le=1_000_000)
    plaintext_bytes: StrictInt = Field(ge=0, le=1_000_000)
    ciphertext_bytes: StrictInt | None
    integrity_ok: StrictBool | None
    signature_ok: StrictBool | None
    roundtrip_ok: StrictBool


class FinalizeIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    status: Literal["complete", "stopped"]
    trials: list[TrialIn] = Field(min_length=1, max_length=220)


def fail(status_code: int, code: str):
    raise HTTPException(status_code=status_code, detail=code)


def audit_rejection(reason: str, user: User) -> None:
    log_event("METRICS_REJECTED", severity="warning", success=False,
              user_id=user.id, details={"reason": reason})


def _decode_b64(value: str | None, expected: int | None = None, max_len: int | None = None) -> bytes:
    if value is None or (max_len is not None and len(value) > max_len):
        raise ValueError
    raw = base64.b64decode(value, validate=True)
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError
    if expected is not None and len(raw) != expected:
        raise ValueError
    return raw


def _get_running_run(db: Session, run_id: int) -> CompareRun:
    run = db.query(CompareRun).filter(CompareRun.id == run_id).first()
    if run is None:
        fail(404, "run_not_found")
    if run.status != "running":
        fail(409, "run_not_running")
    return run


@router.post("/runs", status_code=201)
def create_run(req: RunIn, user: User = analyst, db: Session = Depends(get_lab_db)):
    if not SAFE_LABEL.fullmatch(req.label) or len(req.input_text.encode("utf-8")) > 8000:
        fail(400, "invalid_run")
    try:
        public_key = _decode_b64(req.sig_public_key_b64, expected=65, max_len=100)
    except (ValueError, binascii.Error):
        fail(400, "bad_public_key")
    if public_key[0] != 0x04:
        fail(400, "bad_public_key")
    now = clock_now()
    stale_before = now - timedelta(minutes=15)
    stale = db.query(CompareRun).filter(CompareRun.status == "running").all()
    for row in stale:
        created = row.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created < stale_before:
            row.status = "aborted"
            row.finished_at = now
    db.commit()
    if db.query(CompareRun.id).filter(CompareRun.status == "running").first():
        fail(409, "run_in_progress")
    row = CompareRun(status="running", analyst_id=user.id, label=req.label,
        input_text=req.input_text, input_bytes=len(req.input_text.encode("utf-8")),
        trials=req.trials, warmup=req.warmup,
        setup_keygen_ms=req.setup_keygen_ms, setup_dh_ms=req.setup_dh_ms,
        setup_hkdf_ms=req.setup_hkdf_ms, sig_public_key_b64=req.sig_public_key_b64,
        sig_fingerprint=hashlib.sha256(public_key).hexdigest(), created_at=now)
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        fail(409, "run_in_progress")
    db.refresh(row)
    log_event("COMPARE_RUN_STARTED", user_id=user.id,
              details={"run_id": row.id, "trials": row.trials})
    return {"id": row.id}


@router.post("/runs/{run_id}/exchanges", status_code=201)
def create_exchange(run_id: int, req: ExchangeIn, user: User = analyst,
                    db: Session = Depends(get_lab_db)):
    # Both modes deliberately execute the same SELECT/COUNT/INSERT/COMMIT shape.
    run = _get_running_run(db, run_id)
    exchange_count = db.query(func.count(CompareExchange.id)).filter(
        CompareExchange.run_id == run_id).scalar() or 0
    if exchange_count >= MAX_EXCHANGES:
        fail(409, "too_many_exchanges")
    try:
        if req.mode == "unsecured":
            forbidden = {"session_id", "sender_role", "counter", "msg_type", "meta_json",
                         "iv", "ct", "hmac", "signature"}
            if (req.text is None or not 1 <= len(req.text) <= 2000 or
                forbidden.intersection(req.model_fields_set)):
                fail(400, "mode_fields_mismatch")
            fields = {"text": req.text}
        else:
            if "text" in req.model_fields_set:
                fail(400, "mode_fields_mismatch")
            if (req.session_id is None or req.sender_role != "I" or req.counter is None or req.counter < 1
                or req.msg_type != "text" or req.meta_json != "{}"):
                fail(400, "mode_fields_mismatch")
            try:
                UUID(req.session_id)
                iv = _decode_b64(req.iv, expected=16, max_len=24)
                ct = _decode_b64(req.ct, max_len=10924)
                tag = _decode_b64(req.hmac, expected=32, max_len=44)
                signature = _decode_b64(req.signature, expected=64, max_len=88)
            except (ValueError, binascii.Error):
                fail(400, "bad_envelope_format")
            if len(ct) < 16 or len(ct) > 8192 or len(ct) % 16:
                fail(400, "bad_envelope_format")
            fields = {"session_id": str(UUID(req.session_id)), "sender_role": req.sender_role,
                      "counter": req.counter, "msg_type": req.msg_type, "meta_json": req.meta_json,
                      "iv": iv, "ct": ct, "hmac": tag, "signature": signature}
    except HTTPException:
        raise
    row = CompareExchange(run_id=run.id, mode=req.mode, warmup=req.warmup, **fields)
    db.add(row)
    db.commit()
    return {"id": row.id}


@router.get("/runs/{run_id}/exchanges/{exchange_id}")
def exchange_detail(run_id: int, exchange_id: int, _: User = analyst,
                    db: Session = Depends(get_lab_db)):
    item = queries.get_exchange(db, run_id, exchange_id)
    if item is None:
        fail(404, "exchange_not_found")
    return item


@router.post("/runs/{run_id}/finalize")
async def finalize_run(run_id: int, request: Request, user: User = analyst,
                       db: Session = Depends(get_lab_db)):
    run = _get_running_run(db, run_id)
    try:
        req = FinalizeIn.model_validate_json(await request.body())
    except ValidationError as exc:
        audit_rejection("invalid_trial_payload", user)
        raise HTTPException(status_code=422, detail="invalid_trial_payload") from exc
    exchanges = {row.id: row for row in db.query(CompareExchange).filter(
        CompareExchange.run_id == run_id).all()}
    seen: set[int] = set()
    counts = {"secured": 0, "unsecured": 0}
    measured = {"secured": 0, "unsecured": 0}
    reasons: list[str] = []
    rows = []
    expected_pt = len(run.input_text.encode("utf-8"))
    for trial in req.trials:
        data = trial.model_dump()
        exchange = exchanges.get(trial.exchange_id)
        if exchange is None or exchange.mode != trial.mode or exchange.warmup != trial.warmup:
            reasons.append("exchange_mismatch"); continue
        if trial.exchange_id in seen:
            reasons.append("exchange_mismatch"); continue
        seen.add(trial.exchange_id)
        if trial.plaintext_bytes != expected_pt or (trial.mode == "secured" and
                (trial.ciphertext_bytes != len(exchange.ct or b"") or
                 trial.ciphertext_bytes != (expected_pt // 16 + 1) * 16)):
            reasons.append("length_inconsistent"); continue
        if abs(trial.total_ms - (trial.prep_ms + trial.post_ms + trial.get_ms + trial.finish_ms)) > .5:
            reasons.append("segments_inconsistent"); continue
        if trial.mode == "secured":
            if any(value is None or value <= 0 for value in
                   (trial.seal_ms, trial.sign_ms, trial.verify_hmac_ms)):
                reasons.append("mode_fields_mismatch"); continue
            if trial.integrity_ok is None or trial.signature_ok is None or trial.ciphertext_bytes is None:
                reasons.append("mode_fields_mismatch"); continue
            # Later stages are null only when the prerequisite check failed and
            # the client correctly skipped signature verification/decryption.
            if trial.integrity_ok:
                if trial.verify_sig_ms is None or trial.verify_sig_ms <= 0:
                    reasons.append("mode_fields_mismatch"); continue
                if trial.signature_ok:
                    if trial.decrypt_ms is None or trial.decrypt_ms <= 0:
                        reasons.append("mode_fields_mismatch"); continue
                elif trial.decrypt_ms is not None:
                    reasons.append("mode_fields_mismatch"); continue
            elif trial.signature_ok or trial.verify_sig_ms is not None or trial.decrypt_ms is not None:
                reasons.append("mode_fields_mismatch"); continue
            if (trial.seal_ms + trial.sign_ms > trial.prep_ms + .5 or
                trial.verify_hmac_ms + (trial.verify_sig_ms or 0) + (trial.decrypt_ms or 0) > trial.finish_ms + .5):
                reasons.append("subtimings_inconsistent"); continue
        elif any(value is not None for value in (trial.seal_ms, trial.sign_ms,
                trial.verify_hmac_ms, trial.verify_sig_ms, trial.decrypt_ms,
                trial.ciphertext_bytes, trial.integrity_ok, trial.signature_ok)):
            reasons.append("mode_fields_mismatch"); continue
        counts[trial.mode] += 1
        if not trial.warmup:
            measured[trial.mode] += 1
        rows.append(CompareTrial(run_id=run_id, **data))
    if reasons:
        reason = reasons[0]
        audit_rejection(reason, user)
        fail(400, reason)
    if measured["secured"] != measured["unsecured"] or measured["secured"] > run.trials or (
        req.status == "complete" and measured["secured"] != run.trials):
        audit_rejection("pair_count_mismatch", user)
        fail(400, "pair_count_mismatch")
    db.add_all(rows)
    run.status = req.status
    run.finished_at = utc_now()
    db.commit()
    log_event("COMPARE_RUN_COMPLETED", user_id=user.id,
              details={"run_id": run.id, "status": run.status,
                       "pairs": measured["secured"]})
    return {"id": run.id, "status": run.status}


@router.post("/runs/{run_id}/abort")
def abort_run(run_id: int, db: Session = Depends(get_lab_db), _: User = analyst):
    run = _get_running_run(db, run_id)
    run.status = "aborted"
    run.finished_at = utc_now()
    db.commit()
    return {"id": run.id, "status": run.status}


@router.get("/runs")
def runs(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_lab_db), _: User = analyst):
    return {"items": queries.list_runs(db, limit)}


@router.get("/runs/{run_id}/exchanges")
def exchanges(run_id: int, limit: int = Query(50, ge=1, le=200),
              after_id: int | None = Query(None, ge=1), db: Session = Depends(get_lab_db),
              _: User = analyst):
    if db.query(CompareRun.id).filter(CompareRun.id == run_id).first() is None:
        fail(404, "run_not_found")
    items = queries.list_exchanges(db, run_id, limit, after_id)
    return {"items": items, "next_after_id": items[-1]["id"] if len(items) == limit else None}


@router.get("/history")
def run_history(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_lab_db), _: User = analyst):
    return {"items": queries.history(db, limit)}


@router.get("/runs/{run_id}")
def run_detail(run_id: int, db: Session = Depends(get_lab_db), _: User = analyst):
    result = queries.get_run(db, run_id)
    if result is None:
        fail(404, "run_not_found")
    return result


@router.delete("/runs/{run_id}", status_code=204)
def delete_one(run_id: int, user: User = analyst, db: Session = Depends(get_lab_db)):
    run = db.query(CompareRun).filter(CompareRun.id == run_id).first()
    if run is None:
        fail(404, "run_not_found")
    if run.status == "running":
        fail(409, "run_in_progress")
    counts = queries.delete_run(db, run)
    log_event("COMPARE_DATA_CLEARED", severity="warning", user_id=user.id,
              details={"runs_deleted": counts[0], "rows_deleted": counts[1]})
    return Response(status_code=204)


@router.delete("/runs", status_code=204)
def delete_all(user: User = analyst, db: Session = Depends(get_lab_db)):
    if db.query(CompareRun.id).filter(CompareRun.status == "running").first():
        fail(409, "run_in_progress")
    counts = queries.delete_all(db)
    log_event("COMPARE_DATA_CLEARED", severity="warning", user_id=user.id,
              details={"runs_deleted": counts[0], "rows_deleted": counts[1]})
    return Response(status_code=204)
