from dataclasses import dataclass

@dataclass(frozen=True)
class HttpInfo:
    is_request: bool
    method: str | None = None
    uri: str | None = None
    status_code: int | None = None
    content_length: int | None = None
    request_in: int | None = None
    time_since_request: float | None = None

@dataclass(frozen=True)
class WsInfo:
    opcode: int | None = None
    payload_len: int | None = None

@dataclass(frozen=True)
class PacketRecord:
    frame_no: int
    ts: float
    length: int
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    tcp_stream: int | None
    is_syn: bool = False
    is_fin: bool = False
    is_rst: bool = False
    is_retransmission: bool = False
    payload: bytes = b""
    http: HttpInfo | None = None
    ws: WsInfo | None = None
