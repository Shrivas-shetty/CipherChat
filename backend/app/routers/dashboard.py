from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.db.models import User
from app.deps import require_role
from app.services.audit import verify_chain_detailed
from app.services.dashboard_queries import event_types, query_logs, query_messages, query_sessions, query_summary

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
def summary(db: Session = Depends(get_db), _: User = analyst):
    return query_summary(db)


@router.get("/audit-integrity")
def audit_integrity(db: Session = Depends(get_db), _: User = analyst):
    return verify_chain_detailed(db)
