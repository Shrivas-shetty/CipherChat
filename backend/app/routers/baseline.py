import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, Field
from sqlalchemy.orm import Session

from app import config
from app.db.base import get_db
from app.db.models import ChatSession, User
from app.deps import get_current_user
from app.services.audit import log_event
from app.services.baseline_store import store
from app.ws.manager import manager

router = APIRouter(prefix="/api/baseline", tags=["baseline"])


class BaselineMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: StrictStr = Field(max_length=64)
    kind: StrictStr
    text: StrictStr | None = None
    w: StrictInt | None = None
    h: StrictInt | None = None
    data_b64: StrictStr | None = None


def enabled():
    if not config.ALLOW_PLAINTEXT_BASELINE:
        raise HTTPException(status_code=404, detail="Not found")


@router.post("/messages", status_code=status.HTTP_201_CREATED)
async def send_baseline(req: BaselineMessage, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    enabled()
    session_id = req.session_id.strip().lower()
    session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session or current.id not in (session.user_a_id, session.user_b_id):
        raise HTTPException(403, "Not a session participant")
    if session.status != "established":
        raise HTTPException(409, "session_not_established")
    if current.id == session.user_a_id:
        recipient_id = session.user_b_id
    else:
        recipient_id = session.user_a_id
    if req.kind == "text":
        if not (req.text and 1 <= len(req.text) <= 2000) or any(v is not None for v in (req.w, req.h, req.data_b64)):
            raise HTTPException(400, "invalid_text")
        value, size = {"text": req.text}, len(req.text.encode("utf-8"))
    elif req.kind == "image":
        if req.text is not None or req.w is None or req.h is None or req.data_b64 is None or not (1 <= req.w <= 512 and 1 <= req.h <= 512):
            raise HTTPException(400, "invalid_image")
        try:
            raw = base64.b64decode(req.data_b64, validate=True)
        except (ValueError, binascii.Error):
            raise HTTPException(400, "invalid_image")
        if len(raw) != req.w * req.h * 3:
            raise HTTPException(400, "invalid_image")
        value, size = {"w": req.w, "h": req.h, "data_b64": req.data_b64}, len(raw)
    else:
        raise HTTPException(400, "invalid_kind")
    item_id, first = store.add(session_id, recipient_id, req.kind, value, size,
        config.BASELINE_TTL_SECONDS, config.BASELINE_MAX_ITEMS, config.BASELINE_MAX_TOTAL_BYTES)
    if first:
        log_event("BASELINE_PLAINTEXT_USED", severity="warning", user_id=current.id,
                  session_id=session_id, details={"kind": req.kind})
    recipient = manager.get_user_by_id(str(recipient_id))
    if recipient:
        await manager.send_json(recipient.websocket, {"v": 1, "type": "baseline_available",
            "session_id": session_id, "message_id": item_id, "kind": req.kind})
    return {"id": item_id}


@router.get("/messages/{message_id}")
def fetch_baseline(message_id: int, current: User = Depends(get_current_user)):
    enabled()
    item = store.get(message_id, config.BASELINE_TTL_SECONDS)
    if item is None:
        raise HTTPException(404, "Message not found")
    if item.recipient_id != current.id:
        raise HTTPException(403, "Only the recipient may fetch this message")
    item = store.consume(message_id, config.BASELINE_TTL_SECONDS)
    if item is None:
        raise HTTPException(404, "Message not found")
    return {"id": item.id, "session_id": item.session_id, "kind": item.kind, **item.value}
