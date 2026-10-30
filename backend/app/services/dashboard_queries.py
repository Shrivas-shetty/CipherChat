"""Read-only dashboard queries. This module deliberately contains no HTTP logic."""
from datetime import timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session, aliased

from app.db.models import AuditLog, ChatSession, Message, SigningKey, User, to_iso_z, utc_now
from app.db.lab_models import BenchRun, CompareRun, ImageMetric, TextMetric
from app.db.network_models import PcapFile
from app.image import ImageFormatError, parse_image_meta
from app.ws.manager import manager

EVENT_CATEGORIES: dict[str, list[str]] = {
    "auth": ["REGISTER", "REGISTER_FAILED", "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_LOCKED", "LOGOUT", "TOKEN_REJECTED"],
    "session": ["WS_CONNECTED", "WS_DISCONNECTED", "WS_SUPERSEDED", "ROOM_FULL", "SESSION_WAITING", "SESSION_STARTED", "KEY_EXCHANGE_OK", "KEY_EXCHANGE_FAILED", "SESSION_ENDED"],
    "message": ["MESSAGE_SENT", "MESSAGE_REJECTED", "MESSAGE_VERIFIED", "TAMPER_DETECTED", "SIGNATURE_REJECTED"],
    "keys": ["SIGNING_KEY_REGISTERED", "SIGNING_KEY_RETIRED"],
    "demo": ["TAMPER_ARMED", "TAMPER_DISARMED", "TAMPER_APPLIED", "BASELINE_PLAINTEXT_USED"],
    "lab": ["METRICS_REJECTED", "LAB_DATA_CLEARED", "BENCH_RUN_RECORDED"],
    "network": ["NETWORK_INGEST_STARTED", "NETWORK_INGEST_DONE", "NETWORK_INGEST_FAILED", "NETWORK_CAPTURE_DELETED"],
    "compare": ["COMPARE_RUN_STARTED", "COMPARE_RUN_COMPLETED", "COMPARE_DATA_CLEARED"],
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
        raise ValueError("category must be auth, session, message, keys, demo, lab, network, or other")
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
            "signature_status": row.signature_status if row.signature is not None and len(row.signature) == 64 else None,
            "sig_verify_ms": row.sig_verify_ms if row.signature is not None and len(row.signature) == 64 else None,
            "sig_gen_ms": row.sig_gen_ms if row.signature is not None and len(row.signature) == 64 else None,
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


def query_summary(db: Session, lab_db: Optional[Session] = None, network_db: Optional[Session] = None) -> dict[str, Any]:
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
        "signatures": {
            "signed": db.query(func.count(Message.id)).filter(func.length(Message.signature) == 64).scalar() or 0,
            "valid": db.query(func.count(Message.id)).filter(func.length(Message.signature) == 64, Message.signature_status == "valid").scalar() or 0,
            "invalid": db.query(func.count(Message.id)).filter(func.length(Message.signature) == 64, Message.signature_status == "invalid").scalar() or 0,
            "keys_total": db.query(func.count(SigningKey.id)).scalar() or 0,
            "keys_active": db.query(func.count(SigningKey.id)).filter(SigningKey.retired_at.is_(None)).scalar() or 0,
        },
        "security": {"failed_logins_total": event_counts.get("LOGIN_FAILED", 0), "failed_logins_24h": failed_24h, "lockouts_total": event_counts.get("LOGIN_LOCKED", 0), "tamper_detected_total": event_counts.get("TAMPER_DETECTED", 0), "token_rejections_total": event_counts.get("TOKEN_REJECTED", 0), "room_full_total": event_counts.get("ROOM_FULL", 0)},
        "audit": {"rows": db.query(func.count(AuditLog.id)).scalar() or 0, "last_id": db.query(func.max(AuditLog.id)).scalar()},
        "lab": {
            "text_records": (lab_db.query(func.count(TextMetric.id)).scalar() or 0) if lab_db is not None else 0,
            "image_records": (lab_db.query(func.count(ImageMetric.id)).scalar() or 0) if lab_db is not None else 0,
            "bench_runs": (lab_db.query(func.count(BenchRun.id)).scalar() or 0) if lab_db is not None else 0,
        },
        "network": {"captures": (network_db.query(func.count(PcapFile.id)).scalar() or 0) if network_db is not None else 0},
        "compare": {"runs": (lab_db.query(func.count(CompareRun.id)).scalar() or 0) if lab_db is not None else 0},
    }


def query_perf_handshakes(db: Session, *, limit: int = 200) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 1000))
    rows = db.query(AuditLog).filter(AuditLog.event_type == "KEY_EXCHANGE_OK").order_by(AuditLog.id.desc()).limit(limit).all()
    items = []
    for row in rows:
        details = row.details or {}
        initiator_timings = details.get("timings_initiator") or {}
        responder_timings = details.get("timings_responder") or {}
        session = db.query(ChatSession).filter(ChatSession.id == row.session_id).first() if row.session_id else None
        items.append({"id": row.id, "ts": to_iso_z(row.ts), "session_id": row.session_id,
            "handshake_ms": details.get("duration_ms"),
            "initiator": session.user_a.username if session else details.get("initiator"),
            "responder": session.user_b.username if session else details.get("responder"),
            "initiator_keygen_ms": initiator_timings.get("keygen_ms"),
            "initiator_derive_ms": initiator_timings.get("derive_ms"),
            "responder_keygen_ms": responder_timings.get("keygen_ms"),
            "responder_derive_ms": responder_timings.get("derive_ms")})
    return items


def _message_dimensions(row: Message):
    if row.msg_type != "image":
        return None, None
    try:
        return parse_image_meta(row.meta_json)
    except ImageFormatError:
        return None, None


def query_hmac_records(db: Session, *, limit: int = 500, before_id: int | None = None,
                       msg_type: str | None = None) -> dict[str, Any]:
    limit = max(1, min(limit, 2000))
    if msg_type not in (None, "text", "image"):
        raise ValueError("msg_type must be text or image")
    filters = [Message.hmac_gen_us.isnot(None)]
    if msg_type:
        filters.append(Message.msg_type == msg_type)
    query = db.query(Message).filter(*filters)
    total = query.count()
    latest_id = query.order_by(None).with_entities(func.max(Message.id)).scalar()
    if before_id is not None:
        query = query.filter(Message.id < before_id)
    rows = query.order_by(Message.id.desc()).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = []
    for row in rows:
        w, h = _message_dimensions(row)
        items.append({"id": row.id, "created_at": to_iso_z(row.created_at), "msg_type": row.msg_type,
            "pt_len_bytes": row.pt_len_bytes, "w": w, "h": h,
            "n_pixels": w * h if w is not None and h is not None else None,
            "ct_len_bytes": len(row.ct), "hmac_gen_us": row.hmac_gen_us})
    return {"total": total, "items": items, "has_more_older": has_more, "latest_id": latest_id}


def query_signature_records(db: Session, *, limit: int = 500, before_id: int | None = None,
                            msg_type: str | None = None) -> dict[str, Any]:
    limit = max(1, min(limit, 2000))
    if msg_type not in (None, "text", "image"):
        raise ValueError("msg_type must be text or image")
    filters = [func.length(Message.signature) == 64]
    if msg_type:
        filters.append(Message.msg_type == msg_type)
    query = db.query(Message).filter(*filters)
    total = query.count()
    latest_id = query.order_by(None).with_entities(func.max(Message.id)).scalar()
    if before_id is not None:
        query = query.filter(Message.id < before_id)
    rows = query.order_by(Message.id.desc()).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    user_ids = {value for row in rows for value in (row.sender_id, row.recipient_id)}
    key_ids = {row.signer_key_id for row in rows if row.signer_key_id is not None}
    users = {row.id: row.username for row in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    keys = {row.id: row.fingerprint for row in db.query(SigningKey).filter(SigningKey.id.in_(key_ids)).all()} if key_ids else {}
    items = []
    for row in rows:
        w, h = _message_dimensions(row)
        items.append({"id": row.id, "created_at": to_iso_z(row.created_at),
            "sender": users.get(row.sender_id), "recipient": users.get(row.recipient_id),
            "msg_type": row.msg_type, "pt_len_bytes": row.pt_len_bytes, "w": w, "h": h,
            "n_pixels": w * h if w is not None and h is not None else None,
            "signer_key_id": row.signer_key_id, "key_fingerprint": keys.get(row.signer_key_id),
            "signature_len": len(row.signature), "signature_preview_hex": row.signature[:32].hex(),
            "sig_gen_ms": row.sig_gen_ms, "sig_verify_ms": row.sig_verify_ms,
            "signature_status": row.signature_status})
    return {"total": total, "items": items, "has_more_older": has_more, "latest_id": latest_id}


def query_signing_keys(db: Session, *, limit: int = 200) -> dict[str, Any]:
    limit = max(1, min(limit, 1000))
    total = db.query(func.count(SigningKey.id)).scalar() or 0
    rows = db.query(SigningKey).order_by(SigningKey.id.desc()).limit(limit).all()
    user_ids = {row.user_id for row in rows}
    usernames = {row.id: row.username for row in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    counts = dict(db.query(Message.signer_key_id, func.count(Message.id))
        .filter(Message.signer_key_id.in_([row.id for row in rows]), func.length(Message.signature) == 64)
        .group_by(Message.signer_key_id).all()) if rows else {}
    return {"total": total, "items": [{"id": row.id, "username": usernames.get(row.user_id),
        "fingerprint": row.fingerprint, "created_at": to_iso_z(row.created_at),
        "retired_at": to_iso_z(row.retired_at), "retire_reason": row.retire_reason,
        "active": row.retired_at is None, "keygen_ms": row.keygen_ms,
        "signed_count": counts.get(row.id, 0)} for row in rows]}
