from collections import defaultdict, deque
from threading import Lock
from time import monotonic
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, StrictFloat, StrictInt, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import config
from app.db.base import get_db
from app.db.lab_base import get_lab_db
from app.db.lab_models import ImageMetric, TextMetric
from app.db.models import Message, User
from app.deps import require_role
from app.services.audit import log_event
from app.image import ImageFormatError, expected_image_ct_len, parse_image_meta
from app.services.lab_queries import create_image_metric, create_text_metric

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


class ImageMetricRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    message_id: StrictInt
    session_id: str
    width: StrictInt
    height: StrictInt
    n_pixels: StrictInt
    pt_len_bytes: StrictInt
    ct_len_bytes: StrictInt
    npcr_trials: StrictInt
    npcr_pct: StrictFloat
    npcr_trial_pcts: list[StrictFloat]
    npcr_changed_counts: list[StrictInt]
    uaci_pct: StrictFloat
    uaci_trial_pcts: list[StrictFloat]
    flip_byte_idx: list[StrictInt]
    entropy_r: StrictFloat
    entropy_g: StrictFloat
    entropy_b: StrictFloat
    entropy_avg: StrictFloat
    corr_pt_r: StrictFloat | None
    corr_pt_g: StrictFloat | None
    corr_pt_b: StrictFloat | None
    corr_pt_avg: StrictFloat | None
    corr_ct_r: StrictFloat | None
    corr_ct_g: StrictFloat | None
    corr_ct_b: StrictFloat | None
    corr_ct_avg: StrictFloat | None
    mse_dec: StrictFloat
    psnr_dec: StrictFloat | None
    mse_enc: StrictFloat
    psnr_enc: StrictFloat | None
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


def _check_image_ranges(req: ImageMetricRequest) -> str | None:
    if (not 1 <= req.npcr_trials <= 16 or any(len(values) != req.npcr_trials for values in
            (req.npcr_trial_pcts, req.npcr_changed_counts, req.uaci_trial_pcts, req.flip_byte_idx))):
        return "trial_count"
    pcts = [req.npcr_pct, req.uaci_pct, *req.npcr_trial_pcts, *req.uaci_trial_pcts]
    correlations = [req.corr_pt_r, req.corr_pt_g, req.corr_pt_b, req.corr_pt_avg,
                    req.corr_ct_r, req.corr_ct_g, req.corr_ct_b, req.corr_ct_avg]
    psnrs = [req.psnr_dec, req.psnr_enc]
    if (any(not 0 <= value <= 100 for value in pcts)
            or any(not 0 <= value <= req.pt_len_bytes for value in req.npcr_changed_counts)
            or any(not 0 <= value < req.pt_len_bytes for value in req.flip_byte_idx)
            or any(not 0 <= value <= 8 for value in (req.entropy_r, req.entropy_g, req.entropy_b, req.entropy_avg))
            or any(value is not None and not -1 <= value <= 1 for value in correlations)
            or not 0 <= req.mse_dec <= 65025 or not 0 <= req.mse_enc <= 65025
            or any(value is not None and not 0 <= value <= 200 for value in psnrs)
            or not 0 < req.enc_us <= 120_000_000 or not 0 < req.dec_us <= 120_000_000
            or not 1 <= req.timing_iters <= 5000):
        return "out_of_range"
    if ((req.psnr_dec is None) != (req.mse_dec == 0) or (req.psnr_enc is None) != (req.mse_enc == 0)):
        return "psnr_inconsistent"
    return None


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


@router.post("/image-metrics", status_code=201)
async def post_image_metrics(
    payload: ImageMetricRequest,
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
    if message.msg_type != "image":
        _reject("wrong_type", payload.message_id, user_id=user.id)
    if message.session_id.lower() != payload.session_id:
        _reject("session_mismatch", payload.message_id, user_id=user.id)
    try:
        width, height = parse_image_meta(message.meta_json)
        expected_ct_len = expected_image_ct_len(width, height)
    except ImageFormatError:
        _reject("dimension_mismatch", payload.message_id, user_id=user.id)
    if payload.width != width or payload.height != height:
        _reject("dimension_mismatch", payload.message_id, user_id=user.id)
    if (payload.n_pixels != width * height or payload.pt_len_bytes != width * height * 3
            or payload.ct_len_bytes != len(message.ct) or len(message.ct) != expected_ct_len):
        _reject("length_inconsistent", payload.message_id, user_id=user.id)
    reason = _check_image_ranges(payload)
    if reason:
        _reject(reason, payload.message_id, user_id=user.id)
    if lab_db.query(ImageMetric.id).filter(ImageMetric.message_id == payload.message_id).first() is not None:
        _reject("already_recorded", payload.message_id, 409, user.id)
    values = payload.model_dump()
    values["sender_id"] = user.id
    try:
        row = create_image_metric(lab_db, values)
    except IntegrityError:
        lab_db.rollback()
        _reject("already_recorded", payload.message_id, 409, user.id)
    return {"id": row.id}
