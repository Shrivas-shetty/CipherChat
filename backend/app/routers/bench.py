import math
import re
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, StrictFloat, StrictInt, StrictStr, Field, conlist
from sqlalchemy.orm import Session

from app.db.lab_base import get_lab_db
from app.db.lab_models import BenchRun, BenchSample
from app.db.models import User, to_iso_z
from app.deps import require_role
from app.services.audit import log_event

router = APIRouter(prefix="/api/dashboard/bench", tags=["benchmark"])
analyst = Depends(require_role("analyst"))
SAFE = re.compile(r"^[A-Za-z0-9 _.\-]+$")


class SampleIn(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, strict=True)
    seq: StrictInt = Field(ge=0)
    mode: Literal["secure", "plain"]
    kind: Literal["text", "image"]
    size_param: StrictInt = Field(ge=1, le=2000)
    plaintext_bytes: StrictInt = Field(ge=0, le=5_000_000)
    crypto_send_ms: StrictFloat = Field(ge=0, le=600000)
    to_notify_ms: StrictFloat = Field(ge=0, le=600000)
    fetch_ms: StrictFloat = Field(ge=0, le=600000)
    crypto_recv_ms: StrictFloat = Field(ge=0, le=600000)
    e2e_ms: StrictFloat = Field(ge=0, le=600000)
    post_ms: StrictFloat = Field(ge=0, le=600000)
    verify_post_ms: StrictFloat | None = None
    bytes_up: StrictInt = Field(ge=0, le=5_000_000)
    bytes_down: StrictInt = Field(ge=0, le=5_000_000)
    ws_notify_bytes: StrictInt = Field(ge=0, le=5_000_000)


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, strict=True)
    label: StrictStr = Field(min_length=1, max_length=64)
    repeats: StrictInt = Field(ge=1)
    warmup: StrictInt = Field(ge=0)
    text_lengths: list[StrictInt]
    image_sides: list[StrictInt]
    handshake_ms: list[StrictFloat]
    note: StrictStr | None = Field(default=None, max_length=200)
    samples: list[SampleIn] = Field(min_length=1, max_length=2000)

    def valid_charset(self):
        if not SAFE.fullmatch(self.label) or (self.note is not None and not SAFE.fullmatch(self.note)):
            raise ValueError("invalid_label_or_note")
        if any(not 1 <= x <= 2000 for x in self.text_lengths) or any(not 1 <= x <= 512 for x in self.image_sides):
            raise ValueError("invalid_size")
        if any(not math.isfinite(x) or not 0 <= x <= 600000 for x in self.handshake_ms):
            raise ValueError("invalid_handshake")
        for sample in self.samples:
            max_size = 2000 if sample.kind == "text" else 512
            if sample.size_param > max_size or (sample.verify_post_ms is not None and (not math.isfinite(sample.verify_post_ms) or not 0 <= sample.verify_post_ms <= 600000)):
                raise ValueError("invalid_sample")
            if sample.mode == "plain" and sample.verify_post_ms is not None:
                raise ValueError("invalid_sample")
        return self


@router.post("/runs", status_code=201)
def create_run(req: RunIn, lab: Session = Depends(get_lab_db), user: User = analyst):
    try:
        req.valid_charset()
    except ValueError as exc:
        log_event("METRICS_REJECTED", severity="warning", user_id=user.id, details={"reason": str(exc)})
        raise HTTPException(400, {"code": "invalid_bench_run"}) from exc
    row = BenchRun(label=req.label, repeats=req.repeats, warmup=req.warmup,
        text_lengths=req.text_lengths, image_sides=req.image_sides,
        handshake_ms=req.handshake_ms, note=req.note)
    lab.add(row); lab.flush()
    for item in req.samples:
        values = item.model_dump()
        values["run_id"] = row.id
        lab.add(BenchSample(**values))
    lab.commit()
    log_event("BENCH_RUN_RECORDED", severity="info", user_id=user.id,
              details={"run_id": row.id, "label": row.label, "samples": len(req.samples)})
    return {"id": row.id}


def serialize_run(lab: Session, row: BenchRun):
    return {"id": row.id, "created_at": to_iso_z(row.created_at), "label": row.label,
        "repeats": row.repeats, "warmup": row.warmup, "text_lengths": row.text_lengths,
        "image_sides": row.image_sides, "handshake_ms": row.handshake_ms, "note": row.note,
        "sample_count": lab.query(BenchSample).filter(BenchSample.run_id == row.id).count()}


@router.get("/runs")
def runs(limit: int = Query(50, ge=1, le=200), lab: Session = Depends(get_lab_db), _: User = analyst):
    rows = lab.query(BenchRun).order_by(BenchRun.created_at.desc(), BenchRun.id.desc()).limit(limit).all()
    return {"items": [serialize_run(lab, row) for row in rows]}


@router.get("/runs/{run_id}")
def run_detail(run_id: int, lab: Session = Depends(get_lab_db), _: User = analyst):
    row = lab.query(BenchRun).filter(BenchRun.id == run_id).first()
    if row is None: raise HTTPException(404, "Run not found")
    result = serialize_run(lab, row)
    result["samples"] = [{c.name: getattr(s, c.name) for c in BenchSample.__table__.columns if c.name != "run_id"} for s in lab.query(BenchSample).filter(BenchSample.run_id == run_id).order_by(BenchSample.seq).all()]
    return result


@router.delete("/runs")
def clear_runs(lab: Session = Depends(get_lab_db), user: User = analyst):
    count = lab.query(BenchRun).count()
    lab.query(BenchSample).delete(synchronize_session=False)
    lab.query(BenchRun).delete(synchronize_session=False)
    lab.commit()
    log_event("LAB_DATA_CLEARED", severity="warning", user_id=user.id, details={"table": "bench", "rows_deleted": count})
    return {"deleted": count}
