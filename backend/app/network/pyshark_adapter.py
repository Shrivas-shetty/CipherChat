"""Optional parser adapter; this is the only module importing PyShark."""
import asyncio
from datetime import datetime
import re
from app.network.models import HttpInfo,PacketRecord,WsInfo

def _safe(obj,name):
    try:
        value=getattr(obj,name)
        return None if value in (None,"") else value
    except (AttributeError,KeyError,ValueError,TypeError):return None
def _field(obj,name):
    fields=_safe(obj,"_all_fields")
    def find(value):
        if not isinstance(value,dict):return None
        if name in value:return value[name]
        for child in value.values():
            found=find(child)
            if found is not None:return found
        return None
    return find(fields)
def _layer(packet,name):
    try:return packet[name]
    except (AttributeError,KeyError,IndexError,ValueError,TypeError):return None
def _integer(value):
    try:return int(str(value),0)
    except (TypeError,ValueError):
        try:return int(value)
        except (TypeError,ValueError):return None
def _epoch(value):
    if value is None:return 0.0
    try:return float(value)
    except (TypeError,ValueError):
        try:return datetime.fromisoformat(str(value).replace("Z","+00:00")).timestamp()
        except (TypeError,ValueError,OverflowError):return 0.0
def _flag(value):return str(value or "0").lower() in ("1","true","yes")

def iter_packets(path,server_port,tshark_path):
    import pyshark
    loop=None;owns_loop=False;capture=None
    try:
        try:asyncio.get_running_loop()
        except RuntimeError:
            try:loop=asyncio.get_event_loop_policy().get_event_loop()
            except RuntimeError:
                loop=asyncio.new_event_loop();asyncio.set_event_loop(loop);owns_loop=True
        capture=pyshark.FileCapture(str(path),keep_packets=False,use_json=True,tshark_path=tshark_path,
            decode_as={f"tcp.port=={server_port}":"http"},custom_parameters=["-2"])
        for pkt in capture:
            frame=_layer(pkt,"frame");tcp=_layer(pkt,"tcp");ip=_layer(pkt,"ip");ip6=_layer(pkt,"ipv6")
            src=_safe(ip,"src") or _safe(ip6,"src");dst=_safe(ip,"dst") or _safe(ip6,"dst")
            payload_text=_safe(tcp,"payload")
            try:payload=bytes.fromhex(str(payload_text).replace(":","")) if payload_text else b""
            except ValueError:payload=b""
            http_layer=_layer(pkt,"http");http=None
            if http_layer is not None:
                method=_safe(http_layer,"request_method") or _field(http_layer,"http.request.method")
                status=_integer(_safe(http_layer,"response_code") or _field(http_layer,"http.response.code"))
                request_line=_safe(http_layer,"request_line") or _field(http_layer,"http.request.line")
                response_line=_safe(http_layer,"response_line") or _field(http_layer,"http.response.line")
                if request_line:
                    parts=str(request_line).split()
                    if len(parts)>=2:method=method or parts[0]
                if status is None and response_line:
                    found=re.match(r"\S+\s+(\d{3})",str(response_line));status=int(found.group(1)) if found else None
                elapsed=_safe(http_layer,"time") or _field(http_layer,"http.time")
                try:elapsed=float(elapsed) if elapsed is not None else None
                except (TypeError,ValueError):elapsed=None
                http=HttpInfo(method is not None,str(method) if method else None,
                    str(_safe(http_layer,"request_full_uri") or _field(http_layer,"http.request.full_uri") or _safe(http_layer,"full_uri") or _safe(http_layer,"request_uri") or _field(http_layer,"http.request.uri") or ((str(request_line).split()[1]) if request_line and len(str(request_line).split())>=2 else "") or "") or None,
                    status,_integer(_safe(http_layer,"content_length") or _safe(http_layer,"content_length_header") or _field(http_layer,"http.content_length") or _safe(http_layer,"file_data_len")),_integer(_safe(http_layer,"request_in") or _field(http_layer,"http.request_in")),elapsed)
            ws_layer=_layer(pkt,"websocket");ws=None
            if ws_layer is not None:ws=WsInfo(_integer(_safe(ws_layer,"opcode") or _field(ws_layer,"websocket.opcode")),_integer(_safe(ws_layer,"payload_length") or _safe(ws_layer,"payload_len") or _field(ws_layer,"websocket.payload_length")))
            try: retransmitted=_safe(tcp,"analysis_retransmission") is not None or _field(tcp,"tcp.analysis.retransmission") is not None
            except Exception:retransmitted=False
            yield PacketRecord(_integer(_safe(frame,"number") or _safe(pkt,"number")) or 0,_epoch(_safe(pkt,"sniff_timestamp") or _safe(frame,"time_epoch")),
                _integer(_safe(frame,"len") or _safe(pkt,"length")) or 0,str(src) if src else None,str(dst) if dst else None,
                _integer(_safe(tcp,"srcport")),_integer(_safe(tcp,"dstport")),str(_safe(pkt,"highest_layer") or "DATA").upper(),
                _integer(_safe(tcp,"stream") or _field(tcp,"tcp.stream")),_flag(_safe(tcp,"flags_syn") or _field(tcp,"tcp.flags.syn")) and not _flag(_safe(tcp,"flags_ack") or _field(tcp,"tcp.flags.ack")),_flag(_safe(tcp,"flags_fin") or _field(tcp,"tcp.flags.fin")),_flag(_safe(tcp,"flags_reset") or _field(tcp,"tcp.flags.reset")),
                retransmitted,payload,http,ws)
    finally:
        if capture is not None:
            try:capture.close()
            except RuntimeError as exc:
                if "event loop is closed" not in str(exc).lower():raise
        if owns_loop and loop is not None:
            asyncio.set_event_loop(None);loop.close()
