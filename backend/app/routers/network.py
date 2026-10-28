import importlib.util
from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import MAX_PCAP_MB, get_bench_dir, get_pcap_dir
from app.db.network_base import get_network_db
from app.db.network_models import PcapFile
from app.db.models import User
from app.deps import require_role
from app.network import launcher
from app.network.tshark_locator import find_tshark, tshark_version
from app.network.validation import FILENAME_RE, SIDECAR_RE, InvalidInput, read_sidecar, read_sidecar_marker, validate_ingest
from app.services import network_queries as queries
from app.services.audit import log_event

router = APIRouter(prefix="/api/dashboard/network", tags=["network analysis"])
analyst = Depends(require_role("analyst"))

class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: StrictStr
    label: StrictStr
    scenario: StrictStr
    marker: StrictStr | None = None
    sidecar: StrictStr | None = None
    server_port: StrictInt = 8000
    replace: StrictBool = False

def _capture(db, pcap_id):
    if db.get(PcapFile, pcap_id) is None:
        raise HTTPException(404, "capture_not_found")

@router.get("/status")
def status(_: User = analyst):
    tshark = find_tshark()
    return {"pyshark_installed": importlib.util.find_spec("pyshark") is not None,
            "tshark_path": tshark, "tshark_version": tshark_version(tshark),
            "pcap_dir": "backend/data/pcaps", "ingest_running": launcher.ingest_running()}

@router.get("/files")
def files(db: Session = Depends(get_network_db), _: User = analyst):
    root = get_pcap_dir(); bench = get_bench_dir()
    indexed = {row.filename: row for row in db.scalars(select(PcapFile)).all()}
    pcaps = []
    for path in root.iterdir():
        if not path.is_file() or not FILENAME_RE.fullmatch(path.name): continue
        try: path.resolve().relative_to(root.resolve())
        except ValueError: continue
        st = path.stat(); row = indexed.get(path.name)
        pcaps.append({"filename": path.name, "size_bytes": st.st_size,
            "modified_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "ingested": {"id": row.id, "status": row.status, "label": row.label, "scenario": row.scenario} if row else None})
    sidecars = []
    if bench.is_dir():
        for path in bench.iterdir():
            if not path.is_file() or not SIDECAR_RE.fullmatch(path.name) or path.stat().st_size > 65536: continue
            try: path.resolve().relative_to(bench.resolve())
            except ValueError: continue
            try:
                data = read_sidecar(path.name)
                marker = read_sidecar_marker(path.name)
                st = path.stat()
                sidecars.append({"filename": path.name, "size_bytes": st.st_size,
                    "modified_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                    **{key: data.get(key) for key in ("mode", "messages")},"marker":marker})
            except (OSError, UnicodeError, ValueError): continue
    pcaps.sort(key=lambda row: row["modified_at"], reverse=True)
    sidecars.sort(key=lambda row: row["modified_at"], reverse=True)
    return {"pcaps": pcaps, "sidecars": sidecars}

@router.post("/ingest", status_code=202)
def ingest(req: IngestRequest, db: Session = Depends(get_network_db), user: User = Depends(require_role("analyst"))):
    try: path = validate_ingest(req.filename, req.label, req.scenario, req.marker, req.server_port, req.sidecar)
    except InvalidInput as exc: raise HTTPException(400, str(exc)) from exc
    except FileNotFoundError as exc: raise HTTPException(404, "file_not_found") from exc
    if not path.is_file(): raise HTTPException(404, "file_not_found")
    if path.stat().st_size > MAX_PCAP_MB * 1024 * 1024: raise HTTPException(413, "pcap_too_large")
    if req.sidecar:
        try:
            sidecar_info = read_sidecar(req.sidecar)
            marker = req.marker or read_sidecar_marker(req.sidecar)
        except FileNotFoundError as exc: raise HTTPException(404, "sidecar_not_found") from exc
        except InvalidInput as exc: raise HTTPException(400, str(exc)) from exc
    else: sidecar_info, marker = None, req.marker
    tshark = find_tshark()
    if not importlib.util.find_spec("pyshark") or not tshark_version(tshark): raise HTTPException(503, "tshark_unavailable")
    try:
        pcap_id = launcher.launch_ingest(db, filename=req.filename, pcap_path=path, label=req.label,
            scenario=req.scenario, marker=marker, server_port=req.server_port, sidecar=req.sidecar,
            sidecar_info=sidecar_info, replace=req.replace, user_id=user.id)
    except FileExistsError as exc: raise HTTPException(409, "already_ingested") from exc
    except RuntimeError as exc: raise HTTPException(409, "ingest_busy") from exc
    return {"id": pcap_id}

@router.get("/captures")
def captures(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_network_db), _: User = analyst):
    return {"items": queries.query_captures(db, limit)}

@router.get("/captures/{pcap_id}")
def capture_detail(pcap_id: int, db: Session = Depends(get_network_db), _: User = analyst):
    result = queries.query_capture_detail(db, pcap_id)
    if result is None: raise HTTPException(404, "capture_not_found")
    return result

@router.get("/captures/{pcap_id}/timeline")
def timeline(pcap_id: int, bucket_ms: int | None = Query(None), db: Session = Depends(get_network_db), _: User = analyst):
    result = queries.query_timeline(db, pcap_id, bucket_ms)
    if result is None: raise HTTPException(404, "capture_not_found")
    return result

@router.get("/captures/{pcap_id}/packets")
def packets(pcap_id: int, limit: int = Query(100, ge=1), after_frame: int | None = None,
    protocol: str | None = None, direction: Literal["c2s", "s2c", "other"] | None = None,
    src_ip: str | None = None, dst_ip: str | None = None, min_length: int | None = Query(None, ge=0),
    flags: Literal["syn", "fin", "rst", "retransmission"] | None = None,
    db: Session = Depends(get_network_db), _: User = analyst):
    _capture(db, pcap_id)
    return queries.query_packets(db, pcap_id, limit=limit, after_frame=after_frame, protocol=protocol,
        direction=direction, src_ip=src_ip, dst_ip=dst_ip, min_length=min_length, flags=flags)

@router.get("/captures/{pcap_id}/http")
def http(pcap_id: int, limit: int = Query(100, ge=1), after_frame: int | None = None,
    endpoint_class: str | None = None, db: Session = Depends(get_network_db), _: User = analyst):
    _capture(db, pcap_id)
    return queries.query_http(db, pcap_id, limit=limit, after_frame=after_frame, endpoint_class=endpoint_class)

@router.delete("/captures/{pcap_id}", status_code=204)
def delete(pcap_id: int, db: Session = Depends(get_network_db), user: User = Depends(require_role("analyst"))):
    if launcher.is_ingesting(pcap_id): raise HTTPException(409, "ingest_busy")
    filename = queries.delete_capture(db, pcap_id)
    if filename is None: raise HTTPException(404, "capture_not_found")
    log_event("NETWORK_CAPTURE_DELETED", severity="warning", user_id=user.id, details={"filename": filename})
    return Response(status_code=204)
