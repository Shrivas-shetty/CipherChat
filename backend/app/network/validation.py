import json,re
from datetime import datetime
from pathlib import Path
from app.config import get_bench_dir,get_pcap_dir

FILENAME_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.(?:pcap|pcapng)$")
SIDECAR_RE=re.compile(r"^traffic_[A-Za-z0-9._-]{1,120}\.json$")
LABEL_RE=re.compile(r"^[A-Za-z0-9 _.\-]{1,64}$")
MARKER_RE=re.compile(r"^[A-Za-z0-9_.\-]{3,64}$")
SCENARIOS={"secure_traffic","plain_baseline","login_attempt","browser_session","tamper_demo","other"}
class InvalidInput(ValueError):pass

def pcap_path(filename):
    if not isinstance(filename,str) or not FILENAME_RE.fullmatch(filename):raise InvalidInput("invalid_filename")
    root=get_pcap_dir().resolve();path=(root/filename).resolve()
    try:path.relative_to(root)
    except ValueError as exc:raise InvalidInput("invalid_filename") from exc
    if path.is_symlink():raise InvalidInput("invalid_filename")
    return path
def sidecar_path(filename):
    if not isinstance(filename,str) or not SIDECAR_RE.fullmatch(filename):raise InvalidInput("invalid_sidecar")
    root=get_bench_dir().resolve();path=(root/filename).resolve()
    try:path.relative_to(root)
    except ValueError as exc:raise InvalidInput("invalid_sidecar") from exc
    if path.is_symlink():raise InvalidInput("invalid_sidecar")
    return path
def _raw_sidecar(filename):
    path=sidecar_path(filename)
    if not path.is_file():raise FileNotFoundError("sidecar_not_found")
    if path.stat().st_size>65536:raise InvalidInput("invalid_sidecar")
    try:value=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,UnicodeError,json.JSONDecodeError) as exc:raise InvalidInput("invalid_sidecar") from exc
    if not isinstance(value,dict):raise InvalidInput("invalid_sidecar")
    return value
def read_sidecar(filename):
    raw=_raw_sidecar(filename);safe={}
    if "mode" in raw:
        if raw["mode"] not in ("secure","plain"):raise InvalidInput("invalid_sidecar")
        safe["mode"]=raw["mode"]
    if "messages" in raw:
        value=raw["messages"]
        if isinstance(value,bool) or not isinstance(value,int) or value<0:raise InvalidInput("invalid_sidecar")
        safe["messages"]=value
    if "with_images" in raw:
        if not isinstance(raw["with_images"],bool):raise InvalidInput("invalid_sidecar")
        safe["with_images"]=raw["with_images"]
    for key in ("started_at_utc","ended_at_utc"):
        if key in raw:
            value=raw[key]
            try:
                if not isinstance(value,str) or len(value)>64:raise ValueError
                datetime.fromisoformat(value.replace("Z","+00:00"))
            except ValueError as exc:raise InvalidInput("invalid_sidecar") from exc
            safe[key]=value
    if "pause_ms" in raw:
        value=raw["pause_ms"]
        if isinstance(value,bool) or not isinstance(value,int) or not 0<=value<=60000:raise InvalidInput("invalid_sidecar")
        safe["pause_ms"]=value
    return safe
def read_sidecar_marker(filename):
    value=_raw_sidecar(filename).get("marker")
    if value is None:return None
    if not isinstance(value,str) or not MARKER_RE.fullmatch(value):raise InvalidInput("invalid_marker")
    return value
def validate_ingest(filename,label,scenario,marker,server_port,sidecar):
    if not LABEL_RE.fullmatch(label or ""):raise InvalidInput("invalid_label")
    if scenario not in SCENARIOS:raise InvalidInput("invalid_scenario")
    if marker is not None and (not isinstance(marker,str) or not MARKER_RE.fullmatch(marker)):raise InvalidInput("invalid_marker")
    if isinstance(server_port,bool) or not isinstance(server_port,int) or not 1<=server_port<=65535:raise InvalidInput("invalid_server_port")
    path=pcap_path(filename)
    if sidecar is not None:sidecar_path(sidecar)
    return path
