from contextlib import asynccontextmanager
import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import CORS_ORIGIN_REGEX
from app.db.base import init_db
from app.routers import admin, auth, health, messages, ws

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    from app.db import base
    from app.db.models import ChatSession, utc_now

    with base.SessionLocal() as db:
        pending = db.query(ChatSession).filter(ChatSession.status != "terminated").all()
        now = utc_now()
        for s in pending:
            s.status = "terminated"
            s.ended_at = now
            s.end_reason = "server_restart"
        if pending:
            db.commit()
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title="CipherChat",
        version="0.2.0",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origin_regex=CORS_ORIGIN_REGEX,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(messages.router)
    application.include_router(admin.router)
    application.include_router(ws.router)

    dist_dir = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if dist_dir.is_dir() and (dist_dir / "index.html").is_file():
        assets_dir = dist_dir / "assets"
        if assets_dir.is_dir():
            application.mount(
                "/assets", StaticFiles(directory=str(assets_dir)), name="assets"
            )

        @application.get("/{full_path:path}")
        async def spa_fallback(full_path: str):
            # API and /ws are registered above and take precedence.
            candidate = dist_dir / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(dist_dir / "index.html")

    return application


app = create_app()
