from typing import Optional

import base64
import json
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.db.lab_base import get_lab_db
from app.db.models import User
from app.deps import require_role
from app.services.audit import log_event, verify_chain_detailed
from app.services.dashboard_queries import event_types, query_logs, query_messages, query_sessions, query_summary
from app.services.lab_queries import clear_image_metrics, clear_text_metrics, get_cipher_noise_message, query_image_records, query_text_records

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
analyst = Depends(require_role("analyst"))


def _bad_query(exc: ValueError):
    raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/logs/types")
def logs_types(_: User = analyst):
    return event_types()


@router.get("/logs")
def logs(
    limit: int = Query(100, ge=1), before_id: Optional[int] = None,
    after_id: Optional[int] = None, category: Optional[str] = None,
    event_type: Optional[str] = None, severity_min: Optional[str] = None,
    success: Optional[bool] = None, username: Optional[str] = None,
    session_id: Optional[str] = None, db: Session = Depends(get_db),
    _: User = analyst,
):
    try:
        return query_logs(db, limit=limit, before_id=before_id, after_id=after_id,
            category=category, event_type=event_type, severity_min=severity_min,
            success=success, username=username, session_id=session_id)
    except ValueError as exc:
        _bad_query(exc)


@router.get("/messages")
def messages(
    limit: int = Query(100, ge=1), before_id: Optional[int] = None,
    after_id: Optional[int] = None, session_id: Optional[str] = None,
    msg_type: Optional[str] = None, verification_status: Optional[str] = None,
    db: Session = Depends(get_db), _: User = analyst,
):
    try:
        return query_messages(db, limit=limit, before_id=before_id, after_id=after_id,
            session_id=session_id, msg_type=msg_type, verification_status=verification_status)
    except ValueError as exc:
        _bad_query(exc)


@router.get("/sessions")
def sessions(limit: int = Query(50, ge=1), db: Session = Depends(get_db), _: User = analyst):
    return {"items": query_sessions(db, limit=limit)}


@router.get("/summary")
def summary(db: Session = Depends(get_db), lab_db: Session = Depends(get_lab_db), _: User = analyst):
    return query_summary(db, lab_db)


@router.get("/lab/text/records")
def text_lab_records(
    limit: int = Query(200, ge=1), before_id: Optional[int] = None,
    lab_db: Session = Depends(get_lab_db), app_db: Session = Depends(get_db),
    _: User = analyst,
):
    return query_text_records(lab_db, app_db, limit=limit, before_id=before_id)


@router.delete("/lab/text")
def clear_text_lab(
    lab_db: Session = Depends(get_lab_db), user: User = analyst,
):
    deleted = clear_text_metrics(lab_db)
    log_event("LAB_DATA_CLEARED", severity="warning", user_id=user.id,
              details={"table": "text_metrics", "rows_deleted": deleted})
    return {"deleted": deleted}


@router.get("/lab/image/records")
def image_lab_records(
    limit: int = Query(200, ge=1), before_id: Optional[int] = None,
    lab_db: Session = Depends(get_lab_db), app_db: Session = Depends(get_db),
    _: User = analyst,
):
    return query_image_records(lab_db, app_db, limit=limit, before_id=before_id)


@router.get("/lab/image/{message_id}/cipher-noise")
def image_cipher_noise(message_id: int, app_db: Session = Depends(get_db), _: User = analyst):
    result = get_cipher_noise_message(app_db, message_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Image message not found")
    width, height, noise = result
    return Response(
        content=json.dumps({"message_id": message_id, "w": width, "h": height,
            "noise_rgb_b64": base64.b64encode(noise).decode("ascii")}),
        media_type="application/json", headers={"Cache-Control": "private, max-age=300"},
    )


@router.delete("/lab/image")
def clear_image_lab(lab_db: Session = Depends(get_lab_db), user: User = analyst):
    deleted = clear_image_metrics(lab_db)
    log_event("LAB_DATA_CLEARED", severity="warning", user_id=user.id,
              details={"table": "image_metrics", "rows_deleted": deleted})
    return {"deleted": deleted}


@router.get("/audit-integrity")
def audit_integrity(db: Session = Depends(get_db), _: User = analyst):
    return verify_chain_detailed(db)
