import base64
import binascii
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import config
from app.db.base import get_db
from app.db.models import ChatSession, Message, User, to_iso_z, utc_now
from app.deps import get_current_user
from app.services.audit import log_event
from app.services.tamper import tamper_service
from app.ws.manager import manager

router = APIRouter(prefix="/api/messages", tags=["messages"])

VALID_REASONS = {"bad_format", "replay", "hmac_mismatch", "decrypt_error"}


class SendMessageRequest(BaseModel):
    session_id: str
    counter: int
    msg_type: str = "text"
    meta_json: str = "{}"
    iv: str
    ct: str
    hmac: str


class VerifyMessageRequest(BaseModel):
    status: str  # "verified" | "failed"
    reason: Optional[str] = None


@router.post("", status_code=status.HTTP_201_CREATED)
async def send_message(
    req: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session_id = req.session_id.strip().lower()
    chat_session = db.query(ChatSession).filter(ChatSession.id == session_id).first()

    # Participant verification
    if not chat_session or current_user.id not in (
        chat_session.user_a_id,
        chat_session.user_b_id,
    ):
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "not_participant"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a session participant",
        )

    # Session established check
    if chat_session.status != "established":
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "session_not_established"},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="session_not_established",
        )

    # Validate message type & meta
    if req.msg_type != "text":
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "invalid_msg_type"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="msg_type must be 'text'",
        )

    if req.meta_json != "{}":
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "invalid_meta_json"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="meta_json must be '{}' for text messages",
        )

    # Determine sender role & recipient
    if current_user.id == chat_session.user_a_id:
        sender_role = "I"
        recipient_id = chat_session.user_b_id
    else:
        sender_role = "R"
        recipient_id = chat_session.user_a_id

    # Format & Base64 validation
    try:
        iv_bytes = base64.b64decode(req.iv, validate=True)
        hmac_bytes = base64.b64decode(req.hmac, validate=True)
        ct_bytes = base64.b64decode(req.ct, validate=True)
    except (binascii.Error, ValueError):
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "bad_format", "sub_reason": "invalid_base64"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 encoding",
        )

    if len(iv_bytes) != 16 or len(hmac_bytes) != 32:
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "bad_format", "sub_reason": "invalid_lengths"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IV or HMAC length",
        )

    if (
        len(ct_bytes) < 16
        or len(ct_bytes) > config.MESSAGE_CIPHERTEXT_MAX_BYTES
        or len(ct_bytes) % 16 != 0
    ):
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "bad_format", "sub_reason": "invalid_ct_size"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ciphertext must be between 16 and 8192 bytes and a multiple of 16",
        )

    # Counter validation
    if req.counter < 1:
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "bad_format", "sub_reason": "counter_below_1"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Counter must be >= 1",
        )

    max_c = (
        db.query(func.max(Message.counter))
        .filter(
            Message.session_id == session_id,
            Message.sender_role == sender_role,
        )
        .scalar()
    )
    if max_c is not None and req.counter <= max_c:
        log_event(
            "MESSAGE_REJECTED",
            severity="warning",
            user_id=current_user.id,
            session_id=session_id,
            details={"reason": "counter_not_increasing", "counter": req.counter, "last": max_c},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="counter_not_increasing",
        )

    # Insert message
    msg = Message(
        session_id=session_id,
        sender_id=current_user.id,
        recipient_id=recipient_id,
        sender_role=sender_role,
        msg_type=req.msg_type,
        counter=req.counter,
        meta_json=req.meta_json,
        iv=iv_bytes,
        ct=ct_bytes,
        hmac=hmac_bytes,
        size_bytes=len(ct_bytes),
        created_at=utc_now(),
        verification_status="pending",
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    log_event(
        "MESSAGE_SENT",
        severity="info",
        user_id=current_user.id,
        session_id=session_id,
        details={
            "message_id": msg.id,
            "msg_type": msg.msg_type,
            "counter": msg.counter,
            "size_bytes": msg.size_bytes,
        },
    )

    # WebSocket notification to recipient (never sends ciphertext over WS)
    recipient_conn = manager.get_user_by_id(str(recipient_id))
    if recipient_conn:
        await manager.send_json(
            recipient_conn.websocket,
            {
                "v": 1,
                "type": "message_available",
                "session_id": session_id,
                "message_id": msg.id,
                "from_role": sender_role,
                "counter": msg.counter,
            },
        )

    return {
        "id": msg.id,
        "created_at": to_iso_z(msg.created_at),
    }


@router.get("/{message_id}")
async def get_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    chat_session = db.query(ChatSession).filter(ChatSession.id == msg.session_id).first()
    if not chat_session or chat_session.status != "established":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="session_not_established",
        )

    # ONLY the recipient may fetch
    if msg.recipient_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the recipient may fetch this message",
        )

    # Record delivery timestamp on first fetch
    if msg.delivered_at is None:
        msg.delivered_at = utc_now()
        db.commit()

    # Tamper simulation
    ct_served = msg.ct
    if config.TAMPER_DEMO_ENABLED and tamper_service.is_armed():
        tampered_bytearray = bytearray(msg.ct)
        tampered_bytearray[0] ^= 0x01
        ct_served = bytes(tampered_bytearray)
        tamper_service.disarm()
        log_event(
            "TAMPER_APPLIED",
            severity="warning",
            user_id=current_user.id,
            session_id=msg.session_id,
            details={"message_id": msg.id},
        )

    return {
        "id": msg.id,
        "session_id": msg.session_id,
        "from_role": msg.sender_role,
        "msg_type": msg.msg_type,
        "counter": msg.counter,
        "meta_json": msg.meta_json,
        "iv": base64.b64encode(msg.iv).decode("ascii"),
        "ct": base64.b64encode(ct_served).decode("ascii"),
        "hmac": base64.b64encode(msg.hmac).decode("ascii"),
        "created_at": to_iso_z(msg.created_at),
    }


@router.post("/{message_id}/verification", status_code=status.HTTP_204_NO_CONTENT)
async def report_verification(
    message_id: int,
    req: VerifyMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    chat_session = db.query(ChatSession).filter(ChatSession.id == msg.session_id).first()
    if not chat_session or chat_session.status != "established":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="session_not_established",
        )

    # Only recipient may report verification
    if msg.recipient_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the recipient may report verification",
        )

    if msg.verification_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="already_reported",
        )

    if req.status not in ("verified", "failed"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="status must be 'verified' or 'failed'",
        )

    if req.status == "failed":
        if not req.reason or req.reason not in VALID_REASONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"reason is required on failure and must be one of {list(VALID_REASONS)}",
            )

    msg.verification_status = req.status
    msg.verification_reason = req.reason if req.status == "failed" else None
    msg.verified_at = utc_now()
    db.commit()

    if req.status == "verified":
        log_event(
            "MESSAGE_VERIFIED",
            severity="info",
            user_id=current_user.id,
            session_id=msg.session_id,
            details={
                "message_id": msg.id,
                "counter": msg.counter,
                "from_role": msg.sender_role,
            },
        )
    else:
        log_event(
            "TAMPER_DETECTED",
            severity="alert",
            user_id=current_user.id,
            session_id=msg.session_id,
            details={
                "message_id": msg.id,
                "reason": req.reason,
                "counter": msg.counter,
                "from_role": msg.sender_role,
            },
        )

    # Notify sender over WebSocket
    sender_conn = manager.get_user_by_id(str(msg.sender_id))
    if sender_conn:
        await manager.send_json(
            sender_conn.websocket,
            {
                "v": 1,
                "type": "message_status",
                "session_id": msg.session_id,
                "message_id": msg.id,
                "counter": msg.counter,
                "status": req.status,
                "reason": msg.verification_reason,
            },
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)

