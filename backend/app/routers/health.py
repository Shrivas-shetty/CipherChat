from datetime import datetime, timezone

from fastapi import APIRouter

from app.ws.manager import manager

router = APIRouter(tags=["health"])


@router.get("/api/health")
async def health():
    return {
        "status": "ok",
        "server_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "online_users": manager.online_users,
    }
