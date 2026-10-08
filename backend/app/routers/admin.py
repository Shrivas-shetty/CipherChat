from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app import config
from app.db.models import User
from app.deps import require_role
from app.services.audit import log_event
from app.services.tamper import tamper_service

router = APIRouter(prefix="/api/admin", tags=["admin"])


class TamperRequest(BaseModel):
    armed: bool


@router.get("/tamper")
async def get_tamper_state(
    current_user: User = Depends(require_role("analyst")),
):
    if not config.TAMPER_DEMO_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tamper demo is disabled",
        )
    return {"armed": tamper_service.is_armed()}


@router.post("/tamper")
async def set_tamper_state(
    req: TamperRequest,
    current_user: User = Depends(require_role("analyst")),
):
    if not config.TAMPER_DEMO_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tamper demo is disabled",
        )

    if req.armed:
        tamper_service.arm()
        log_event(
            "TAMPER_ARMED",
            severity="warning",
            user_id=current_user.id,
            username_attempted=current_user.username,
        )
    else:
        tamper_service.disarm()
        log_event(
            "TAMPER_DISARMED",
            severity="warning",
            user_id=current_user.id,
            username_attempted=current_user.username,
        )

    return {"armed": tamper_service.is_armed()}

