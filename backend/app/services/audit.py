import hashlib
import json
import threading
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.db import base
from app.db.models import AuditLog, to_iso_z, utc_now

GENESIS_PREV_HASH = "0" * 64
_audit_lock = threading.Lock()


def canonical_json_for_row(
    ts_str: str,
    event_type: str,
    severity: str,
    user_id: Optional[int],
    username_attempted: Optional[str],
    success: bool,
    ip: Optional[str],
    session_id: Optional[str],
    details: Optional[dict[str, Any]],
) -> str:
    payload = {
        "ts": ts_str,
        "event_type": event_type,
        "severity": severity,
        "user_id": user_id,
        "username_attempted": username_attempted,
        "success": success,
        "ip": ip,
        "session_id": session_id,
        "details": details,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_row_hash(prev_hash: str, canonical_json: str) -> str:
    data = (prev_hash + canonical_json).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def log_event(
    event_type: str,
    *,
    severity: str = "info",
    user_id: Optional[int] = None,
    username_attempted: Optional[str] = None,
    success: bool = True,
    ip: Optional[str] = None,
    session_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> AuditLog:
    """
    Appends an audit log entry within its own DB transaction and computes the SHA-256 hash chain.
    Thread-safe via _audit_lock.
    """
    with _audit_lock:
        with base.SessionLocal() as db:
            last_row = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
            prev_hash = last_row.row_hash if last_row else GENESIS_PREV_HASH

            now_dt = utc_now()
            ts_str = to_iso_z(now_dt)
            canonical = canonical_json_for_row(
                ts_str=ts_str,
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                username_attempted=username_attempted,
                success=success,
                ip=ip,
                session_id=session_id,
                details=details,
            )
            row_hash = compute_row_hash(prev_hash, canonical)

            entry = AuditLog(
                ts=now_dt,
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                username_attempted=username_attempted,
                success=success,
                ip=ip,
                session_id=session_id,
                details=details,
                prev_hash=prev_hash,
                row_hash=row_hash,
            )
            db.add(entry)
            db.commit()
            db.refresh(entry)
            return entry


def verify_chain(db: Optional[Session] = None) -> tuple[bool, Optional[int]]:
    """
    Recomputes the entire audit log hash chain.
    Returns (True, None) if intact, or (False, first_bad_id) if corrupted.
    """
    close_after = False
    if db is None:
        db = base.SessionLocal()
        close_after = True

    try:
        rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        expected_prev_hash = GENESIS_PREV_HASH
        for row in rows:
            if row.prev_hash != expected_prev_hash:
                return False, row.id

            canonical = canonical_json_for_row(
                ts_str=to_iso_z(row.ts),
                event_type=row.event_type,
                severity=row.severity,
                user_id=row.user_id,
                username_attempted=row.username_attempted,
                success=row.success,
                ip=row.ip,
                session_id=row.session_id,
                details=row.details,
            )
            expected_row_hash = compute_row_hash(row.prev_hash, canonical)
            if row.row_hash != expected_row_hash:
                return False, row.id

            expected_prev_hash = row.row_hash

        return True, None
    finally:
        if close_after:
            db.close()
