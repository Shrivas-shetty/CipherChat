from contextlib import asynccontextmanager
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles

from app.config import CORS_ORIGIN_REGEX
from app.db.base import init_db
from app.db.lab_base import init_lab_db
from app.routers import admin, auth, dashboard, health, lab, messages, ws

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    init_lab_db()
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

    @application.exception_handler(RequestValidationError)
    async def sanitized_validation_error(_request: Request, exc: RequestValidationError):
        # Do not echo rejected request values; this also serializes NaN/Infinity safely.
        errors = [{"loc": error.get("loc", []), "msg": error.get("msg", "Invalid value"), "type": error.get("type", "value_error")} for error in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})

    application.add_middleware(
        CORSMiddleware,
        allow_origin_regex=CORS_ORIGIN_REGEX,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def limit_message_post_size(request, call_next):
        if request.method == "POST" and request.url.path == "/api/messages":
            raw_length = request.headers.get("content-length", "")
            if raw_length.isdigit() and int(raw_length) > 1_200_000:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        if request.method == "POST" and request.url.path == "/api/lab/text-metrics":
            raw_length = request.headers.get("content-length", "")
            body = await request.body()
            if (raw_length.isdigit() and int(raw_length) > 4096) or len(body) > 4096:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        return await call_next(request)

    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(messages.router)
    application.include_router(admin.router)
    application.include_router(dashboard.router)
    application.include_router(lab.router)
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
