from typing import Optional, Tuple

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.db.models import AuthSession, User, utc_now
from app.security.tokens import decode_token
from app.services.audit import log_event


def get_client_ip(request: Request) -> str:
    # Client IP = request.client.host. Do NOT trust X-Forwarded-For.
    if request.client:
        return request.client.host
    return "unknown"


def authenticate_token(
    token: Optional[str],
    db: Session,
    client_ip: str,
) -> Tuple[Optional[User], Optional[AuthSession], Optional[str]]:
    """
    Validates token and returns (User, AuthSession, None) on success,
    or (None, None, failure_reason) on error, where failure_reason is one of:
    'missing', 'malformed', 'expired', 'revoked', 'unknown_session'.
    Audits TOKEN_REJECTED on failure.
    """
    if not token or not token.strip():
        reason = "missing"
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            ip=client_ip,
            details={"reason": reason},
        )
        return None, None, reason

    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        reason = "expired"
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            ip=client_ip,
            details={"reason": reason},
        )
        return None, None, reason
    except Exception:
        reason = "malformed"
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            ip=client_ip,
            details={"reason": reason},
        )
        return None, None, reason

    jti = payload.get("jti")
    sub = payload.get("sub")
    if not jti or not sub:
        reason = "malformed"
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            ip=client_ip,
            details={"reason": reason},
        )
        return None, None, reason

    session = db.query(AuthSession).filter(AuthSession.jti == jti).first()
    if not session:
        reason = "unknown_session"
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            ip=client_ip,
            details={"reason": reason},
        )
        return None, None, reason

    if session.revoked_at is not None:
        reason = "revoked"
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            user_id=session.user_id,
            session_id=jti,
            ip=client_ip,
            details={"reason": reason},
        )
        return None, None, reason

    # Session expiration check (ensure timezone-aware comparison)
    session_exp = session.expires_at
    if session_exp.tzinfo is None:
        session_exp = session_exp.replace(tzinfo=utc_now().tzinfo)
    if session_exp < utc_now():
        reason = "expired"
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            user_id=session.user_id,
            session_id=jti,
            ip=client_ip,
            details={"reason": reason},
        )
        return None, None, reason

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        reason = "unknown_session"
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            ip=client_ip,
            details={"reason": reason},
        )
        return None, None, reason

    return user, session, None


def get_current_auth(
    request: Request,
    db: Session = Depends(get_db),
) -> Tuple[User, AuthSession]:
    client_ip = get_client_ip(request)
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        log_event(
            "TOKEN_REJECTED",
            severity="warning",
            success=False,
            ip=client_ip,
            details={"reason": "missing"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )

    token = auth_header[7:].strip()
    user, session, reason = authenticate_token(token, db, client_ip)
    if not user or not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token rejected ({reason})",
        )

    return user, session


def get_current_user(
    auth: Tuple[User, AuthSession] = Depends(get_current_auth),
) -> User:
    return auth[0]


def require_role(role: str):
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return current_user

    return role_checker

