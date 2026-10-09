import math
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, StrictFloat, StrictInt, StrictStr, Field
from sqlalchemy.orm import Session

from app.db.lab_base import get_lab_db
from app.db.models import User
from app.deps import require_role
from app.services.audit import log_event
from app.services.lab_queries import clear_bench_runs, create_bench_run, get_bench_run, list_bench_runs

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
            if (sample.mode == "plain" and sample.verify_post_ms is not None) or (sample.mode == "secure" and sample.verify_post_ms is None):
                raise ValueError("invalid_sample")
        return self


@router.post("/runs", status_code=201)
async def create_run(request: Request, lab: Session = Depends(get_lab_db), user: User = analyst):
    try:
        req = RunIn.model_validate_json(await request.body())
    except Exception:
        log_event("METRICS_REJECTED", severity="warning", user_id=user.id,
                  details={"reason": "invalid_bench_run"})
        raise HTTPException(400, {"code": "invalid_bench_run"})
    try:
        req.valid_charset()
    except ValueError as exc:
        log_event("METRICS_REJECTED", severity="warning", user_id=user.id, details={"reason": str(exc)})
        raise HTTPException(400, {"code": "invalid_bench_run"}) from exc
    data = req.model_dump()
    data["samples"] = [sample.model_dump() for sample in req.samples]
    row = create_bench_run(lab, data)
    log_event("BENCH_RUN_RECORDED", severity="info", user_id=user.id,
              details={"run_id": row.id, "label": row.label, "samples": len(req.samples)})
    return {"id": row.id}


@router.get("/runs")
def runs(limit: int = Query(50, ge=1, le=200), lab: Session = Depends(get_lab_db), _: User = analyst):
    return {"items": list_bench_runs(lab, limit)}


@router.get("/runs/{run_id}")
def run_detail(run_id: int, lab: Session = Depends(get_lab_db), _: User = analyst):
    result = get_bench_run(lab, run_id)
    if result is None: raise HTTPException(404, "Run not found")
    return result


@router.delete("/runs")
def clear_runs(lab: Session = Depends(get_lab_db), user: User = analyst):
    count, samples_count = clear_bench_runs(lab)
    log_event("LAB_DATA_CLEARED", severity="warning", user_id=user.id, details={"table": "bench", "rows_deleted": count + samples_count})
    return {"deleted": count}
