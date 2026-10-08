from collections import defaultdict, deque
from threading import Lock
from time import monotonic
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import config
from app.db.base import get_db
from app.db.lab_base import get_lab_db
from app.db.lab_models import TextMetric
from app.db.models import Message, User
from app.deps import require_role
from app.services.audit import log_event
from app.services.lab_queries import create_text_metric

router = APIRouter(prefix="/api/lab", tags=["lab"])
_post_times: dict[int, deque[float]] = defaultdict(deque)
_post_lock = Lock()


class TextMetricRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    message_id: StrictInt
    session_id: str
    pt_len_bytes: StrictInt
    ct_len_bytes: StrictInt
    total_ct_bits: StrictInt
    key_trials: StrictInt
    confusion_pct: StrictFloat
    key_flip_pcts: list[StrictFloat]
    pt_trials: StrictInt
    diffusion_bits: StrictFloat
    avalanche_pct: StrictFloat
    block_avalanche_pct: StrictFloat
    pt_flip_bit_idx: list[StrictInt]
    pt_flip_changed_bits: list[StrictInt]
    pt_flip_block_changed_bits: list[StrictInt]
    enc_us: StrictFloat
    dec_us: StrictFloat
    timing_iters: StrictInt

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (ValueError, AttributeError) as exc:
            raise ValueError("session_id must be a UUID") from exc


def _reject(reason: str, message_id: int, status_code: int = 400, user_id: int | None = None):
    log_event("METRICS_REJECTED", severity="warning", success=False, user_id=user_id,
              details={"reason": reason, "message_id": message_id})
    raise HTTPException(status_code=status_code, detail={"code": reason})


def _rate_limit(user_id: int) -> int | None:
    now = monotonic()
    cutoff = now - 60
    with _post_lock:
        queue = _post_times[user_id]
        while queue and queue[0] <= cutoff:
            queue.popleft()
        if len(queue) >= max(1, config.LAB_POSTS_PER_MINUTE):
            return max(1, int(60 - (now - queue[0])))
        queue.append(now)
    return None


def _check_ranges(req: TextMetricRequest, ciphertext_length: int) -> str | None:
    if (req.ct_len_bytes != ciphertext_length or req.total_ct_bits != req.ct_len_bytes * 8
            or not 1 <= req.pt_len_bytes <= 8000
            or req.ct_len_bytes != (req.pt_len_bytes // 16 + 1) * 16):
        return "length_inconsistent"
    arrays = (req.key_flip_pcts, req.pt_flip_bit_idx, req.pt_flip_changed_bits, req.pt_flip_block_changed_bits)
    if (not 1 <= req.key_trials <= 32 or req.key_trials != len(req.key_flip_pcts)
            or not 1 <= req.pt_trials <= 32 or any(len(a) != req.pt_trials for a in arrays[1:])):
        return "trial_count"
    if (not 0 <= req.confusion_pct <= 100
            or any(not 0 <= pct <= 100 for pct in req.key_flip_pcts)
            or any(not 0 <= bit < req.pt_len_bytes * 8 for bit in req.pt_flip_bit_idx)
            or any(not 0 <= bits <= req.total_ct_bits for bits in req.pt_flip_changed_bits)
            or any(not 0 <= bits <= 128 for bits in req.pt_flip_block_changed_bits)
            or not 0 <= req.diffusion_bits <= req.total_ct_bits
            or not 0 <= req.avalanche_pct <= 100
            or not 0 <= req.block_avalanche_pct <= 100
            or not 0 < req.enc_us <= 5_000_000 or not 0 < req.dec_us <= 5_000_000
            or not 1 <= req.timing_iters <= 5000):
        return "out_of_range"
    return None


@router.post("/text-metrics", status_code=201)
async def post_text_metrics(
    payload: TextMetricRequest,
    request: Request,
    user: User = Depends(require_role("user")),
    app_db: Session = Depends(get_db),
    lab_db: Session = Depends(get_lab_db),
):
    content_length = request.headers.get("content-length", "")
    if (content_length.isdigit() and int(content_length) > 4096) or len(await request.body()) > 4096:
        raise HTTPException(status_code=413, detail="Request body too large")
    retry_after = _rate_limit(user.id)
    if retry_after is not None:
        raise HTTPException(status_code=429, detail="Metrics rate limit exceeded", headers={"Retry-After": str(retry_after)})

    message = app_db.query(Message).filter(Message.id == payload.message_id).first()
    if message is None:
        _reject("unknown_message", payload.message_id, user_id=user.id)
    if message.sender_id != user.id:
        _reject("not_sender", payload.message_id, 403, user.id)
    if message.msg_type != "text":
        _reject("wrong_type", payload.message_id, user_id=user.id)
    if message.session_id.lower() != payload.session_id:
        _reject("session_mismatch", payload.message_id, user_id=user.id)
    reason = _check_ranges(payload, len(message.ct))
    if reason:
        _reject(reason, payload.message_id, user_id=user.id)
    if lab_db.query(TextMetric.id).filter(TextMetric.message_id == payload.message_id).first() is not None:
        _reject("already_recorded", payload.message_id, 409, user.id)

    values = payload.model_dump()
    values["sender_id"] = user.id
    try:
        row = create_text_metric(lab_db, values)
    except IntegrityError:
        lab_db.rollback()
        _reject("already_recorded", payload.message_id, 409, user.id)
    return {"id": row.id}
