from datetime import timedelta
import re
from typing import Any, Tuple
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import config
from app.db.base import get_db
from app.db.models import AuditLog, AuthSession, User, to_iso_z, utc_now
from app.deps import get_client_ip, get_current_auth, get_current_user
from app.security.passwords import (
    hash_password,
    validate_password,
    verify_dummy,
    verify_password,
)
from app.security.tokens import create_token
from app.services.audit import log_event
from app.ws.manager import manager

router = APIRouter(prefix="/api/auth", tags=["auth"])

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,20}$")


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    req: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    client_ip = get_client_ip(request)
    raw_username = req.username.strip()

    if not USERNAME_REGEX.match(raw_username):
        log_event(
            "REGISTER_FAILED",
            severity="warning",
            username_attempted=raw_username,
            success=False,
            ip=client_ip,
            details={"reason": "invalid_username_format"},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Username must be 3–20 characters and contain only letters, numbers, and underscores.",
        )

    pw_valid, pw_err = validate_password(req.password)
    if not pw_valid:
        log_event(
            "REGISTER_FAILED",
            severity="warning",
            username_attempted=raw_username,
            success=False,
            ip=client_ip,
            details={"reason": "weak_password", "error": pw_err},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=pw_err,
        )

    norm_username = raw_username.lower()
    existing = db.query(User).filter(User.username_norm == norm_username).first()
    if existing:
        log_event(
            "REGISTER_FAILED",
            severity="warning",
            username_attempted=raw_username,
            success=False,
            ip=client_ip,
            details={"reason": "username_taken"},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already taken.",
        )

    pw_hash = hash_password(req.password)
    user = User(
        username=raw_username,
        username_norm=norm_username,
        password_hash=pw_hash,
        role="user",  # Role is ALWAYS user for registration
        created_at=utc_now(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_event(
        "REGISTER",
        severity="info",
        user_id=user.id,
        username_attempted=user.username,
        success=True,
        ip=client_ip,
    )

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
    }


@router.post("/login")
async def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    client_ip = get_client_ip(request)
    raw_username = req.username.strip()
    norm_username = raw_username.lower()

    # Lockout check: >= LOGIN_MAX_FAILS in LOGIN_FAIL_WINDOW_MIN minutes
    window_start = utc_now() - timedelta(minutes=config.LOGIN_FAIL_WINDOW_MIN)
    failed_rows = (
        db.query(AuditLog)
        .filter(
            AuditLog.event_type == "LOGIN_FAILED",
            func.lower(AuditLog.username_attempted) == norm_username,
            AuditLog.ts >= window_start,
        )
        .order_by(AuditLog.ts.asc())
        .all()
    )

    if len(failed_rows) >= config.LOGIN_MAX_FAILS:
        oldest_fail_ts = failed_rows[0].ts
        if oldest_fail_ts.tzinfo is None:
            oldest_fail_ts = oldest_fail_ts.replace(tzinfo=utc_now().tzinfo)
        lockout_expiry = oldest_fail_ts + timedelta(minutes=config.LOGIN_FAIL_WINDOW_MIN)
        retry_after = max(1, int((lockout_expiry - utc_now()).total_seconds()))

        log_event(
            "LOGIN_LOCKED",
            severity="alert",
            username_attempted=raw_username,
            success=False,
            ip=client_ip,
            details={"reason": "max_fails_exceeded", "retry_after_seconds": retry_after},
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Too many failed attempts",
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    user = db.query(User).filter(User.username_norm == norm_username).first()
    if not user:
        verify_dummy(req.password)
        log_event(
            "LOGIN_FAILED",
            severity="alert",
            username_attempted=raw_username,
            success=False,
            ip=client_ip,
            details={"reason": "unknown_user", "unauthorized_access_attempt": True},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not verify_password(req.password, user.password_hash):
        log_event(
            "LOGIN_FAILED",
            severity="alert",
            user_id=user.id,
            username_attempted=raw_username,
            success=False,
            ip=client_ip,
            details={"reason": "bad_password", "unauthorized_access_attempt": True},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Success: issue session and token
    jti = str(uuid4())
    issued_at = utc_now()
    expires_at = issued_at + timedelta(hours=config.JWT_EXPIRE_HOURS)

    session = AuthSession(
        jti=jti,
        user_id=user.id,
        issued_at=issued_at,
        expires_at=expires_at,
        ip=client_ip,
        user_agent=request.headers.get("user-agent"),
    )
    user.last_login_at = issued_at
    db.add(session)
    db.commit()

    log_event(
        "LOGIN_SUCCESS",
        severity="info",
        user_id=user.id,
        username_attempted=user.username,
        success=True,
        ip=client_ip,
        session_id=jti,
    )

    token = create_token(
        user_id=user.id,
        role=user.role,
        jti=jti,
        issued_at=issued_at,
        expires_at=expires_at,
    )

    return {
        "access_token": token,
        "token": token,
        "token_type": "bearer",
        "expires_at": to_iso_z(expires_at),
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        },
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    auth: Tuple[User, AuthSession] = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    user, session = auth
    client_ip = get_client_ip(request)

    session.revoked_at = utc_now()
    db.commit()

    log_event(
        "LOGOUT",
        severity="info",
        user_id=user.id,
        username_attempted=user.username,
        success=True,
        ip=client_ip,
        session_id=session.jti,
    )

    # Terminate active chat session before closing ws
    from app.ws.session_coordinator import coordinator
    await coordinator.terminate_session(session_id=None, reason="logout")

    # Close user's active WebSocket connection if any
    await manager.close_user(str(user.id), reason="User logged out")

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me")
async def me(
    current_user: User = Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
    }
