"""Read-only dashboard queries. This module deliberately contains no HTTP logic."""
from datetime import timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session, aliased

from app.db.models import AuditLog, ChatSession, Message, User, to_iso_z, utc_now
from app.db.lab_models import TextMetric
from app.image import ImageFormatError, parse_image_meta
from app.ws.manager import manager

EVENT_CATEGORIES: dict[str, list[str]] = {
    "auth": ["REGISTER", "REGISTER_FAILED", "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_LOCKED", "LOGOUT", "TOKEN_REJECTED"],
    "session": ["WS_CONNECTED", "WS_DISCONNECTED", "WS_SUPERSEDED", "ROOM_FULL", "SESSION_WAITING", "SESSION_STARTED", "KEY_EXCHANGE_OK", "KEY_EXCHANGE_FAILED", "SESSION_ENDED"],
    "message": ["MESSAGE_SENT", "MESSAGE_REJECTED", "MESSAGE_VERIFIED", "TAMPER_DETECTED"],
    "demo": ["TAMPER_ARMED", "TAMPER_DISARMED", "TAMPER_APPLIED"],
    "lab": ["METRICS_REJECTED", "LAB_DATA_CLEARED"],
}
SEVERITIES = ["info", "warning", "alert"]
_ALL_CATEGORIZED = {event for events in EVENT_CATEGORIES.values() for event in events}
_SEVERITY_RANK = {"info": 0, "warning": 1, "alert": 2}
_AUTH_SESSION_ID_EVENTS = {"LOGIN_SUCCESS", "LOGOUT", "TOKEN_REJECTED", "WS_CONNECTED", "WS_DISCONNECTED", "WS_SUPERSEDED", "ROOM_FULL"}


def event_types() -> dict[str, Any]:
    return {"categories": EVENT_CATEGORIES, "severities": SEVERITIES}


def _page_result(db: Session, query, model, limit: int, filters: list, before_id: Optional[int], after_id: Optional[int], serializer):
    limit = max(1, min(limit, 500))
    page_query = query
    if before_id is not None:
        page_query = page_query.filter(model.id < before_id)
    if after_id is not None:
        page_query = page_query.filter(model.id > after_id)
    rows = page_query.order_by(model.id.desc()).limit(limit + 1).all()
    has_more_older = False
    if len(rows) > limit:
        rows = rows[:limit]
    if rows:
        has_more_older = db.query(model.id).filter(*filters, model.id < min(row.id for row in rows)).first() is not None
    latest_id = db.query(func.max(model.id)).scalar()
    return {"items": [serializer(row) for row in rows], "has_more_older": has_more_older, "latest_id": latest_id}


def _aware(dt):
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def query_logs(
    db: Session, *, limit: int = 100, before_id: Optional[int] = None,
    after_id: Optional[int] = None, category: Optional[str] = None,
    event_type: Optional[str] = None, severity_min: Optional[str] = None,
    success: Optional[bool] = None, username: Optional[str] = None,
    session_id: Optional[str] = None,
) -> dict[str, Any]:
    if before_id is not None and after_id is not None:
        raise ValueError("before_id and after_id are mutually exclusive")
    if category is not None and category not in (*EVENT_CATEGORIES, "other"):
        raise ValueError("category must be auth, session, message, demo, or other")
    if severity_min is not None and severity_min not in SEVERITIES:
        raise ValueError("severity_min must be info, warning, or alert")
    user_alias = aliased(User)
    query = db.query(AuditLog, user_alias.username).outerjoin(user_alias, AuditLog.user_id == user_alias.id)
    filters = []
    if category in EVENT_CATEGORIES:
        filters.append(AuditLog.event_type.in_(EVENT_CATEGORIES[category]))
    elif category == "other":
        filters.append(AuditLog.event_type.notin_(_ALL_CATEGORIZED))
    if event_type:
        filters.append(AuditLog.event_type == event_type)
    if severity_min:
        filters.append(AuditLog.severity.in_(SEVERITIES[_SEVERITY_RANK[severity_min]:]))
    if success is not None:
        filters.append(AuditLog.success == success)
    if username:
        term = f"%{username.strip().lower()}%"
        filters.append(or_(func.lower(user_alias.username).like(term), func.lower(AuditLog.username_attempted).like(term)))
    if session_id:
        filters.append(AuditLog.session_id == session_id)
    query = query.filter(*filters)
    limit = max(1, min(limit, 500))
    if before_id is not None:
        query = query.filter(AuditLog.id < before_id)
    if after_id is not None:
        query = query.filter(AuditLog.id > after_id)
    pairs = query.order_by(AuditLog.id.desc()).limit(limit + 1).all()
    has_more = len(pairs) > limit
    pairs = pairs[:limit]
    if pairs:
        older_query = db.query(AuditLog.id).outerjoin(user_alias, AuditLog.user_id == user_alias.id)
        has_more = older_query.filter(*filters, AuditLog.id < pairs[-1][0].id).first() is not None
    latest_id = db.query(func.max(AuditLog.id)).scalar()
    items = []
    for row, resolved_username in pairs:
        items.append({
            "id": row.id, "ts": to_iso_z(row.ts), "event_type": row.event_type,
            "severity": row.severity, "user_id": row.user_id,
            "username": resolved_username or row.username_attempted,
            "success": row.success, "ip": row.ip,
            # Auth token jti values are stored in this audit column for token errors.
            "session_id": None if row.event_type in _AUTH_SESSION_ID_EVENTS else row.session_id,
            "details": row.details, "prev_hash": row.prev_hash, "row_hash": row.row_hash,
        })
    return {"items": items, "has_more_older": has_more, "latest_id": latest_id}


def query_messages(
    db: Session, *, limit: int = 100, before_id: Optional[int] = None,
    after_id: Optional[int] = None, session_id: Optional[str] = None,
    msg_type: Optional[str] = None, verification_status: Optional[str] = None,
) -> dict[str, Any]:
    if before_id is not None and after_id is not None:
        raise ValueError("before_id and after_id are mutually exclusive")
    if msg_type is not None and msg_type not in ("text", "image"):
        raise ValueError("msg_type must be text or image")
    if verification_status is not None and verification_status not in ("pending", "verified", "failed"):
        raise ValueError("verification_status must be pending, verified, or failed")
    sender = aliased(User)
    recipient = aliased(User)
    query = db.query(Message, sender.username, recipient.username).join(sender, Message.sender_id == sender.id).join(recipient, Message.recipient_id == recipient.id)
    filters = []
    if session_id:
        filters.append(Message.session_id == session_id)
    if msg_type:
        filters.append(Message.msg_type == msg_type)
    if verification_status:
        filters.append(Message.verification_status == verification_status)
    query = query.filter(*filters)
    limit = max(1, min(limit, 500))
    if before_id is not None:
        query = query.filter(Message.id < before_id)
    if after_id is not None:
        query = query.filter(Message.id > after_id)
    pairs = query.order_by(Message.id.desc()).limit(limit + 1).all()
    has_more = len(pairs) > limit
    pairs = pairs[:limit]
    if pairs:
        has_more = db.query(Message.id).filter(*filters, Message.id < pairs[-1][0].id).first() is not None
    items = []
    for row, sender_name, recipient_name in pairs:
        width = height = None
        if row.msg_type == "image":
            try:
                width, height = parse_image_meta(row.meta_json)
            except ImageFormatError:
                pass
        items.append({
            "id": row.id, "session_id": row.session_id, "sender": sender_name,
            "recipient": recipient_name, "sender_role": row.sender_role,
            "msg_type": row.msg_type, "counter": row.counter,
            "size_bytes": row.size_bytes, "w": width, "h": height,
            "created_at": to_iso_z(row.created_at), "delivered_at": to_iso_z(row.delivered_at),
            "verification_status": row.verification_status,
            "verification_reason": row.verification_reason, "verified_at": to_iso_z(row.verified_at),
        })
    return {"items": items, "has_more_older": has_more, "latest_id": db.query(func.max(Message.id)).scalar()}


def query_sessions(db: Session, *, limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 200))
    rows = db.query(ChatSession).order_by(ChatSession.started_at.desc()).limit(limit).all()
    if not rows:
        return []
    ids = [row.id for row in rows]
    message_counts = dict(db.query(Message.session_id, func.count(Message.id)).filter(Message.session_id.in_(ids)).group_by(Message.session_id).all())
    failed_counts = dict(db.query(Message.session_id, func.count(Message.id)).filter(Message.session_id.in_(ids), Message.verification_status == "failed").group_by(Message.session_id).all())
    now = utc_now()
    items = []
    for row in rows:
        start = _aware(row.started_at)
        end = _aware(row.ended_at) if row.ended_at else now
        established = _aware(row.established_at) if row.established_at else None
        fingerprint = row.fingerprint_a if row.fingerprint_a and row.fingerprint_a == row.fingerprint_b else None
        items.append({
            "id": row.id, "initiator": row.user_a.username, "responder": row.user_b.username,
            "status": row.status, "started_at": to_iso_z(start), "established_at": to_iso_z(established),
            "ended_at": to_iso_z(row.ended_at), "end_reason": row.end_reason,
            "duration_seconds": max(0.0, (end - start).total_seconds()),
            "handshake_ms": (established - start).total_seconds() * 1000 if established else None,
            "fingerprint": fingerprint, "message_count": message_counts.get(row.id, 0),
            "failed_verification_count": failed_counts.get(row.id, 0),
        })
    return items


def query_summary(db: Session, lab_db: Optional[Session] = None) -> dict[str, Any]:
    now = utc_now()
    total_users = db.query(func.count(User.id)).scalar() or 0
    analysts = db.query(func.count(User.id)).filter(User.role == "analyst").scalar() or 0
    sessions_total = db.query(func.count(ChatSession.id)).scalar() or 0
    established = db.query(func.count(ChatSession.id)).filter(ChatSession.established_at.isnot(None)).scalar() or 0
    terminated = db.query(func.count(ChatSession.id)).filter(ChatSession.status == "terminated").scalar() or 0
    active = db.query(func.count(ChatSession.id)).filter(ChatSession.status != "terminated").scalar() or 0
    message_total = db.query(func.count(Message.id)).scalar() or 0
    type_counts = dict(db.query(Message.msg_type, func.count(Message.id)).group_by(Message.msg_type).all())
    status_counts = dict(db.query(Message.verification_status, func.count(Message.id)).group_by(Message.verification_status).all())
    event_counts = dict(db.query(AuditLog.event_type, func.count(AuditLog.id)).filter(AuditLog.event_type.in_(["LOGIN_FAILED", "LOGIN_LOCKED", "TAMPER_DETECTED", "TOKEN_REJECTED", "ROOM_FULL"])).group_by(AuditLog.event_type).all())
    failed_24h = db.query(func.count(AuditLog.id)).filter(AuditLog.event_type == "LOGIN_FAILED", AuditLog.ts >= now - timedelta(hours=24)).scalar() or 0
    active_row = db.query(ChatSession).filter(ChatSession.status != "terminated").order_by(ChatSession.started_at.desc()).first()
    active_session = None
    if active_row:
        active_session = {
            "id": active_row.id, "initiator": active_row.user_a.username,
            "responder": active_row.user_b.username, "status": active_row.status,
            "started_at": to_iso_z(active_row.started_at), "established_at": to_iso_z(active_row.established_at),
            "fingerprint": active_row.fingerprint_a if active_row.fingerprint_a == active_row.fingerprint_b else None,
        }
    return {
        "server_time": to_iso_z(now),
        "users": {"total": total_users, "analysts": analysts, "online": manager.connected_usernames()},
        "active_session": active_session,
        "sessions": {"total": sessions_total, "established_ever": established, "terminated": terminated, "active": active},
        "messages": {"total": message_total, "text": type_counts.get("text", 0), "image": type_counts.get("image", 0), "verified": status_counts.get("verified", 0), "failed": status_counts.get("failed", 0), "pending": status_counts.get("pending", 0)},
        "security": {"failed_logins_total": event_counts.get("LOGIN_FAILED", 0), "failed_logins_24h": failed_24h, "lockouts_total": event_counts.get("LOGIN_LOCKED", 0), "tamper_detected_total": event_counts.get("TAMPER_DETECTED", 0), "token_rejections_total": event_counts.get("TOKEN_REJECTED", 0), "room_full_total": event_counts.get("ROOM_FULL", 0)},
        "audit": {"rows": db.query(func.count(AuditLog.id)).scalar() or 0, "last_id": db.query(func.max(AuditLog.id)).scalar()},
        "lab": {"text_records": (lab_db.query(func.count(TextMetric.id)).scalar() or 0) if lab_db is not None else 0},
    }
