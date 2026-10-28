from contextlib import asynccontextmanager
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles

from app import config
from app.config import CORS_ORIGIN_REGEX
from app.db.base import init_db
from app.db.lab_base import init_lab_db
from app.db.network_base import init_network_db, NetworkSessionLocal
from app.db.network_models import PcapFile
from sqlalchemy import update
from app.routers import admin, auth, baseline, bench, dashboard, health, lab, messages, network, ws, keys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    if config.ALLOW_PLAINTEXT_BASELINE:
        logging.getLogger(__name__).warning("Plaintext baseline endpoints are ENABLED (benchmark use only)")
    init_db()
    init_lab_db()
    config.get_pcap_dir()
    init_network_db()
    with NetworkSessionLocal() as network_db:
        network_db.execute(update(PcapFile).where(PcapFile.status.in_(("queued", "running"))).values(status="failed", error="server_restart"))
        network_db.commit()
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
        if request.url.path.startswith("/api/baseline/") and not config.ALLOW_PLAINTEXT_BASELINE:
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        if request.method == "POST" and request.url.path == "/api/baseline/messages":
            raw_length = request.headers.get("content-length", "")
            body = await request.body()
            if (raw_length.isdigit() and int(raw_length) > 1_200_000) or len(body) > 1_200_000:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        if request.method == "POST" and request.url.path == "/api/dashboard/bench/runs":
            raw_length = request.headers.get("content-length", "")
            body = await request.body()
            if (raw_length.isdigit() and int(raw_length) > 512_000) or len(body) > 512_000:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        if request.method == "POST" and request.url.path == "/api/messages":
            raw_length = request.headers.get("content-length", "")
            if raw_length.isdigit() and int(raw_length) > 1_200_000:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        if request.method == "POST" and request.url.path in {"/api/lab/text-metrics", "/api/lab/image-metrics"}:
            raw_length = request.headers.get("content-length", "")
            body = await request.body()
            if (raw_length.isdigit() and int(raw_length) > 4096) or len(body) > 4096:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        return await call_next(request)

    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(keys.router)
    application.include_router(messages.router)
    application.include_router(baseline.router)
    application.include_router(admin.router)
    application.include_router(dashboard.router)
    application.include_router(bench.router)
    application.include_router(network.router)
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
            if full_path and full_path != "index.html" and candidate.is_file():
                return FileResponse(candidate)
            # The HTML references content-hashed chunks. Keeping an older index
            # cached after a rebuild makes browsers request chunks that no
            # longer exist, which leaves the SPA blank.
            return FileResponse(
                dist_dir / "index.html",
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )

    return application


app = create_app()
