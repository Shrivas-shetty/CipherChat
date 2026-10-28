import base64
import binascii
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.db.models import SigningKey, User, to_iso_z, utc_now
from app.deps import get_current_auth
from app.crypto.sigverify import fingerprint_hex, parse_public_key
from app.services.audit import log_event
from app.services.rate_limit import sliding_window_limit

router = APIRouter(prefix="/api/keys", tags=["signing keys"])


class RegisterKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_key_b64: str = Field(min_length=1)
    keygen_ms: float | None = Field(default=None, gt=0, le=600000)


@router.post("", status_code=201)
def register_key(req: RegisterKeyRequest, request: Request,
                 auth=Depends(get_current_auth), db: Session = Depends(get_db)):
    user, session = auth
    if user.role != "user":
        raise HTTPException(403, "Forbidden")
    retry = sliding_window_limit(user.id, limit=10)
    if retry:
        raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": str(retry)})
    try:
        if len(req.public_key_b64) > 100:
            raise ValueError
        public_key = base64.b64decode(req.public_key_b64, validate=True)
        if len(public_key) != 65:
            raise ValueError
        parse_public_key(public_key)
    except (ValueError, binascii.Error):
        raise HTTPException(400, "bad_public_key")
    fingerprint = fingerprint_hex(public_key)
    if db.query(SigningKey.id).filter(SigningKey.fingerprint == fingerprint).first():
        raise HTTPException(409, "key_reused")
    now = utc_now()
    active = db.query(SigningKey).filter(SigningKey.auth_jti == session.jti,
        SigningKey.retired_at.is_(None)).all()
    for row in active:
        row.retired_at = now
        row.retire_reason = "replaced"
    db.flush()
    key = SigningKey(user_id=user.id, auth_jti=session.jti, public_key_der=public_key,
        fingerprint=fingerprint, created_at=now, keygen_ms=req.keygen_ms)
    db.add(key)
    db.commit()
    db.refresh(key)
    for row in active:
        log_event("SIGNING_KEY_RETIRED", severity="info", user_id=user.id,
                  session_id=session.jti, details={"key_id": row.id, "reason": "replaced"})
    log_event("SIGNING_KEY_REGISTERED", severity="info", user_id=user.id,
              session_id=session.jti, details={"key_id": key.id, "fingerprint": fingerprint})
    return {"id": key.id, "fingerprint": fingerprint, "created_at": to_iso_z(key.created_at)}


@router.get("/{key_id}")
def get_key(key_id: int, auth=Depends(get_current_auth), db: Session = Depends(get_db)):
    key = db.query(SigningKey).filter(SigningKey.id == key_id).first()
    if not key:
        raise HTTPException(404, "Signing key not found")
    user = db.query(User).filter(User.id == key.user_id).first()
    return {"id": key.id, "user_id": key.user_id, "username": user.username,
        "fingerprint": key.fingerprint, "public_key_b64": base64.b64encode(key.public_key_der).decode("ascii"),
        "created_at": to_iso_z(key.created_at), "retired_at": to_iso_z(key.retired_at),
        "retire_reason": key.retire_reason}
