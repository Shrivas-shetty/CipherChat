from datetime import datetime, timezone
import json
import logging
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import (
    CHAT_TEXT_MAX,
    CHAT_TEXT_MIN,
    PROTOCOL_VERSION,
)
from app.db import base
from app.deps import authenticate_token
from app.services.audit import log_event
from app.ws.manager import manager
from app.ws.session_coordinator import coordinator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


def _envelope(msg_type: str, **fields) -> dict:
    return {"v": PROTOCOL_VERSION, "type": msg_type, **fields}


async def _send_error(websocket: WebSocket, code: str, message: str) -> None:
    await manager.send_json(
        websocket, _envelope("error", code=code, message=message)
    )


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    client_ip = websocket.client.host if websocket.client else "unknown"
    logger.info("websocket connected client=%s", client_ip)

    authenticated_user = None
    session_jti = None
    disconnect_reason = "client_disconnected"

    try:
        # First frame MUST be auth: {"v": 1, "type": "auth", "token": "..."}
        raw_first = await websocket.receive_text()
        try:
            first_frame = json.loads(raw_first)
        except json.JSONDecodeError:
            await _send_error(websocket, "UNAUTHORIZED", "Malformed JSON")
            log_event(
                "TOKEN_REJECTED",
                severity="warning",
                success=False,
                ip=client_ip,
                details={"reason": "malformed"},
            )
            await websocket.close()
            return

        if (
            not isinstance(first_frame, dict)
            or first_frame.get("v") != PROTOCOL_VERSION
            or first_frame.get("type") != "auth"
        ):
            await _send_error(websocket, "UNAUTHORIZED", "First frame must be auth frame")
            log_event(
                "TOKEN_REJECTED",
                severity="warning",
                success=False,
                ip=client_ip,
                details={"reason": "missing"},
            )
            await websocket.close()
            return

        token = first_frame.get("token")
        with base.SessionLocal() as db:
            user, session, reason = authenticate_token(token, db, client_ip)
            if not user or not session:
                await _send_error(websocket, "UNAUTHORIZED", f"Authentication failed ({reason})")
                await websocket.close()
                return

            if user.role == "analyst":
                await _send_error(websocket, "FORBIDDEN_ROLE", "Analysts cannot join the chat")
                await websocket.close()
                return

            authenticated_user = user
            session_jti = session.jti
            user_id_str = str(user.id)
            user_name = user.username

        # Check if the same user is already connected in another tab/device
        existing = manager.get_user_by_id(user_id_str)
        if existing:
            await coordinator.terminate_session(session_id=None, reason="superseded")
            await _send_error(
                existing.websocket,
                "SUPERSEDED",
                "You were signed in from another tab or device",
            )
            manager.disconnect(existing.websocket)
            try:
                await existing.websocket.close()
            except Exception:
                pass
            log_event(
                "WS_SUPERSEDED",
                severity="info",
                user_id=authenticated_user.id,
                username_attempted=user_name,
                ip=client_ip,
                session_id=session_jti,
            )
        else:
            # Check room capacity (max 2 distinct users)
            if manager.room_full():
                await _send_error(websocket, "ROOM_FULL", "Chat room is full (max 2 users)")
                log_event(
                    "ROOM_FULL",
                    severity="warning",
                    user_id=authenticated_user.id,
                    username_attempted=user_name,
                    ip=client_ip,
                    session_id=session_jti,
                )
                await websocket.close()
                return

        # Register user in active connections
        user_conn = manager.add_user(websocket, user_id=user_id_str, username=user_name)
        log_event(
            "WS_CONNECTED",
            severity="info",
            user_id=authenticated_user.id,
            username_attempted=user_name,
            ip=client_ip,
            session_id=session_jti,
        )

        # Send joined frame
        await manager.send_json(
            websocket,
            _envelope("joined", user_id=user_id_str, username=user_name),
        )

        # Notify all connected users of room status
        for u in manager.joined_users():
            status = manager.status_payload(u)
            await manager.send_json(
                u.websocket,
                _envelope("status", state=status["state"], peer=status["peer"]),
            )

        # Trigger session coordinator for pairing/session start
        if user_conn:
            await coordinator.on_user_joined(user_conn)

        # Chat receive loop
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await _send_error(websocket, "BAD_FRAME", "Malformed JSON")
                continue

            if not isinstance(data, dict):
                await _send_error(websocket, "BAD_FRAME", "Frame must be a JSON object")
                continue

            msg_type = data.get("type")
            version = data.get("v")
            if version != PROTOCOL_VERSION or not isinstance(msg_type, str):
                await _send_error(websocket, "BAD_FRAME", "Invalid or unsupported frame")
                continue

            if msg_type == "auth":
                await _send_error(websocket, "BAD_FRAME", "Already authenticated")
                continue

            if msg_type == "dh_public":
                curr_user = manager.get_user_by_id(user_id_str)
                if curr_user:
                    await coordinator.handle_dh_public(curr_user, data)
                continue

            if msg_type == "key_confirm":
                curr_user = manager.get_user_by_id(user_id_str)
                if curr_user:
                    await coordinator.handle_key_confirm(curr_user, data)
                continue

            if msg_type == "key_verified":
                curr_user = manager.get_user_by_id(user_id_str)
                if curr_user:
                    await coordinator.handle_key_verified(curr_user, data)
                continue

            if msg_type == "key_failed":
                curr_user = manager.get_user_by_id(user_id_str)
                if curr_user:
                    await coordinator.handle_key_failed(curr_user, data)
                continue

            if msg_type == "request_session":
                curr_user = manager.get_user_by_id(user_id_str)
                if curr_user:
                    await coordinator.request_session(curr_user)
                continue

            if msg_type == "chat":
                if not coordinator.is_established():
                    await _send_error(
                        websocket,
                        "NO_SESSION",
                        "No secure session established",
                    )
                    continue

                raw_text = data.get("text")
                if not isinstance(raw_text, str):
                    await _send_error(websocket, "BAD_FRAME", "text must be a string")
                    continue
                text = raw_text.strip()
                if not (CHAT_TEXT_MIN <= len(text) <= CHAT_TEXT_MAX):
                    await _send_error(
                        websocket,
                        "BAD_FRAME",
                        f"text must be {CHAT_TEXT_MIN}–{CHAT_TEXT_MAX} characters",
                    )
                    continue

                # TEMP plaintext, replaced in Phase 4
                payload = _envelope(
                    "chat",
                    id=str(uuid4()),
                    sender={"user_id": user_id_str, "username": user_name},
                    text=text,
                    ts=_iso_utc_now(),
                )
                await manager.broadcast_json(payload)
                continue

            await _send_error(websocket, "BAD_FRAME", f"Unknown type: {msg_type}")

    except WebSocketDisconnect:
        disconnect_reason = "client_disconnected"
        logger.info("websocket disconnected client=%s", client_ip)
    except Exception as exc:
        disconnect_reason = f"error: {str(exc)}"
        logger.exception("websocket exception client=%s", client_ip)
    finally:
        departed = manager.disconnect(websocket)
        if departed and authenticated_user:
            # First terminate active session if any, notifying peer with session_terminated
            await coordinator.terminate_session(session_id=None, reason="disconnect")
            log_event(
                "WS_DISCONNECTED",
                severity="info",
                user_id=authenticated_user.id,
                username_attempted=departed.username,
                ip=client_ip,
                session_id=session_jti,
                details={"reason": disconnect_reason},
            )
            remaining = manager.joined_users()
            if remaining:
                left_payload = _envelope("peer_left", username=departed.username)
                for u in remaining:
                    await manager.send_json(u.websocket, left_payload)
                    status = manager.status_payload(u)
                    await manager.send_json(
                        u.websocket,
                        _envelope("status", state=status["state"], peer=status["peer"]),
                    )
