from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso_z(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), nullable=False)
    username_norm = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    sessions = relationship("AuthSession", back_populates="user", cascade="all, delete-orphan")


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    jti = Column(String(36), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    ip = Column(String(50), nullable=True)
    user_agent = Column(String(255), nullable=True)

    user = relationship("User", back_populates="sessions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    event_type = Column(String(50), index=True, nullable=False)
    severity = Column(String(20), nullable=False)  # "info" | "warning" | "alert"
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username_attempted = Column(String(50), nullable=True)
    success = Column(Boolean, nullable=False, default=True)
    ip = Column(String(50), nullable=True)
    session_id = Column(String(36), nullable=True, index=True)
    details = Column(JSON, nullable=True)
    prev_hash = Column(String(64), nullable=False)
    row_hash = Column(String(64), nullable=False)


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id = Column(String(36), primary_key=True)
    user_a_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user_b_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(20), nullable=False)  # "negotiating" | "established" | "terminated"
    started_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    established_at = Column(DateTime(timezone=True), nullable=True)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    end_reason = Column(String(50), nullable=True)
    pub_a = Column(String(512), nullable=True)
    pub_b = Column(String(512), nullable=True)
    fingerprint_a = Column(String(32), nullable=True)
    fingerprint_b = Column(String(32), nullable=True)

    user_a = relationship("User", foreign_keys=[user_a_id])
    user_b = relationship("User", foreign_keys=[user_b_id])


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        UniqueConstraint("session_id", "sender_role", "counter", name="uq_session_role_counter"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    sender_role = Column(String(1), nullable=False)  # "I" | "R"
    msg_type = Column(String(20), nullable=False, default="text", index=True)
    counter = Column(Integer, nullable=False)
    meta_json = Column(String(255), nullable=False, default="{}")
    iv = Column(LargeBinary(16), nullable=False)
    ct = Column(LargeBinary, nullable=False)
    hmac = Column(LargeBinary(32), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    verification_status = Column(String(20), default="pending", nullable=False, index=True)  # "pending" | "verified" | "failed"
    verification_reason = Column(String(50), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    session = relationship("ChatSession")
    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])



