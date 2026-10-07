import json
import logging
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import (
    CHAT_TEXT_MAX,
    CHAT_TEXT_MIN,
    DISPLAY_NAME_MAX,
    DISPLAY_NAME_MIN,
    PROTOCOL_VERSION,
)
from app.ws.manager import manager

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
    logger.info("websocket connected client=%s", websocket.client)

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("malformed JSON from client=%s", websocket.client)
                await _send_error(websocket, "BAD_FRAME", "Malformed JSON")
                continue

            if not isinstance(data, dict):
                await _send_error(websocket, "BAD_FRAME", "Frame must be a JSON object")
                continue

            msg_type = data.get("type")
            version = data.get("v")
            if version != PROTOCOL_VERSION or not isinstance(msg_type, str):
                await _send_error(
                    websocket, "BAD_FRAME", "Invalid or unsupported frame"
                )
                continue

            joined = manager.is_joined(websocket)

            if not joined:
                if msg_type != "join":
                    await _send_error(
                        websocket, "NOT_JOINED", "First frame must be join"
                    )
                    await websocket.close()
                    return
                keep_open = await _handle_join(websocket, data)
                if not keep_open:
                    return
                continue

            if msg_type == "join":
                await _send_error(websocket, "BAD_FRAME", "Already joined")
                continue
            if msg_type == "chat":
                keep_open = await _handle_chat(websocket, data)
                if not keep_open:
                    return
                continue

            await _send_error(websocket, "BAD_FRAME", f"Unknown type: {msg_type}")

    except WebSocketDisconnect:
        logger.info("websocket disconnected client=%s", websocket.client)
    except Exception:
        logger.exception("websocket error client=%s", websocket.client)
    finally:
        await _cleanup(websocket)


async def _handle_join(websocket: WebSocket, data: dict) -> bool:
    """Process join. Returns False if the socket was closed and the handler should exit."""
    raw_name = data.get("display_name")
    if not isinstance(raw_name, str):
        await _send_error(websocket, "BAD_FRAME", "display_name must be a string")
        return True

    display_name = raw_name.strip()
    if not (DISPLAY_NAME_MIN <= len(display_name) <= DISPLAY_NAME_MAX):
        await _send_error(
            websocket,
            "BAD_FRAME",
            f"display_name must be {DISPLAY_NAME_MIN}-{DISPLAY_NAME_MAX} characters",
        )
        return True

    user, err = await manager.join(websocket, display_name)
    if err == "ROOM_FULL":
        await _send_error(websocket, "ROOM_FULL", "Chat room is full (max 2 users)")
        await websocket.close()
        return False
    if err == "NAME_TAKEN":
        await _send_error(
            websocket, "NAME_TAKEN", "That display name is already in use"
        )
        return True

    assert user is not None
    await manager.send_json(
        websocket,
        _envelope(
            "joined",
            display_name=user.display_name,
            user_id=user.user_id,
        ),
    )

    # Notify all joined users of current status (waiting or paired)
    for u in manager.joined_users():
        status = manager.status_payload(u)
        await manager.send_json(
            u.websocket,
            _envelope("status", state=status["state"], peer=status["peer"]),
        )
    return True


async def _handle_chat(websocket: WebSocket, data: dict) -> bool:
    """Process chat. Returns False if the socket was closed and the handler should exit."""
    user = manager.get_user(websocket)
    if user is None:
        await _send_error(websocket, "NOT_JOINED", "Not joined")
        await websocket.close()
        return False

    raw_text = data.get("text")
    if not isinstance(raw_text, str):
        await _send_error(websocket, "BAD_FRAME", "text must be a string")
        return True

    text = raw_text.strip()
    if not (CHAT_TEXT_MIN <= len(text) <= CHAT_TEXT_MAX):
        await _send_error(
            websocket,
            "BAD_FRAME",
            f"text must be {CHAT_TEXT_MIN}-{CHAT_TEXT_MAX} characters after trim",
        )
        return True

    payload = _envelope(
        "chat",
        id=str(uuid4()),
        sender={"user_id": user.user_id, "display_name": user.display_name},
        text=text,
        ts=_iso_utc_now(),
    )
    await manager.broadcast_json(payload)
    return True


async def _cleanup(websocket: WebSocket) -> None:
    departed = manager.disconnect(websocket)
    if departed is None:
        return

    remaining = manager.joined_users()
    if not remaining:
        return

    left_payload = _envelope("peer_left", display_name=departed.display_name)
    for u in remaining:
        await manager.send_json(u.websocket, left_payload)
        status = manager.status_payload(u)
        await manager.send_json(
            u.websocket,
            _envelope("status", state=status["state"], peer=status["peer"]),
        )
