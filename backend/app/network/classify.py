import re
from urllib.parse import urlsplit

_UUID=re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

def normalize_path(uri: str | None) -> str:
    if not uri: return "/"
    path=urlsplit(uri).path or "/"
    segments=["{uuid}" if _UUID.fullmatch(s) else "{id}" if s.isdigit() else s for s in path.split("/")]
    return "/".join(segments)[:120]

def classify_endpoint(method: str | None,path_norm: str,status_code: int | None=None) -> str:
    method=(method or "").upper(); path=normalize_path(path_norm)
    if status_code==101 or (method=="GET" and path=="/ws"): return "websocket_upgrade"
    known={("POST","/api/auth/register"):"register",("POST","/api/auth/login"):"login",("POST","/api/auth/logout"):"logout",("GET","/api/auth/me"):"me"}
    if (method,path) in known:return known[(method,path)]
    if method=="POST" and path=="/api/messages":return "message_send"
    if method=="GET" and re.fullmatch(r"/api/messages/\{id\}",path):return "message_fetch"
    if method=="POST" and re.fullmatch(r"/api/messages/\{id\}/verification",path):return "message_verify"
    if method=="POST" and path=="/api/baseline/messages":return "baseline_send"
    if method=="GET" and re.fullmatch(r"/api/baseline/messages/\{id\}",path):return "baseline_fetch"
    if path.startswith("/api/lab/"):return "metrics_post"
    if path.startswith("/api/dashboard/"):return "dashboard"
    if path.startswith("/api/admin/"):return "admin"
    if path=="/api/health":return "health"
    if method=="GET" and not path.startswith("/api/"):return "static"
    return "other"
