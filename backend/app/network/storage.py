"""Network-only SQL schema, safe for the isolated ingestion worker to import."""
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class NetworkBase(DeclarativeBase): pass
def utc_now(): return datetime.now(timezone.utc)
class PcapFile(NetworkBase):
    __tablename__="pcap_files"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    filename:Mapped[str]=mapped_column(String(100),unique=True,nullable=False)
    size_bytes:Mapped[int]=mapped_column(Integer,nullable=False);label:Mapped[str]=mapped_column(String(64),nullable=False)
    scenario:Mapped[str]=mapped_column(String(32),nullable=False);marker:Mapped[str|None]=mapped_column(String(64))
    server_port:Mapped[int]=mapped_column(Integer,nullable=False,default=8000);sidecar_name:Mapped[str|None]=mapped_column(String(140))
    sidecar_info:Mapped[dict[str,Any]|None]=mapped_column(JSON);status:Mapped[str]=mapped_column(String(16),nullable=False,default="queued")
    error:Mapped[str|None]=mapped_column(String(300));created_at:Mapped[datetime]=mapped_column(default=utc_now,nullable=False);ingested_at:Mapped[datetime|None]=mapped_column()
    tshark_version:Mapped[str|None]=mapped_column(String(200));packet_count:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    first_ts:Mapped[float|None]=mapped_column(Float);last_ts:Mapped[float|None]=mapped_column(Float);duration_s:Mapped[float]=mapped_column(Float,nullable=False,default=0)
    total_frame_bytes:Mapped[int]=mapped_column(Integer,nullable=False,default=0);total_tcp_payload_bytes:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    tcp_streams:Mapped[int]=mapped_column(Integer,nullable=False,default=0);syn_count:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    retransmissions:Mapped[int]=mapped_column(Integer,nullable=False,default=0);http_requests:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    http_responses:Mapped[int]=mapped_column(Integer,nullable=False,default=0);ws_frames:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    ws_payload_bytes:Mapped[int]=mapped_column(Integer,nullable=False,default=0);truncated:Mapped[bool]=mapped_column(Boolean,nullable=False,default=False)
    client_ips:Mapped[list[str]]=mapped_column(JSON,nullable=False,default=list);server_ips:Mapped[list[str]]=mapped_column(JSON,nullable=False,default=list)
class Packet(NetworkBase):
    __tablename__="packets"
    __table_args__=(Index("ix_packets_pcap_frame","pcap_id","frame_no",unique=True),Index("ix_packets_pcap_rel","pcap_id","rel_ts"))
    id:Mapped[int]=mapped_column(Integer,primary_key=True);pcap_id:Mapped[int]=mapped_column(ForeignKey("pcap_files.id",ondelete="CASCADE"),index=True)
    frame_no:Mapped[int]=mapped_column(Integer,nullable=False);ts:Mapped[float]=mapped_column(Float,nullable=False);rel_ts:Mapped[float]=mapped_column(Float,nullable=False)
    src_ip:Mapped[str|None]=mapped_column(String(64));dst_ip:Mapped[str|None]=mapped_column(String(64));src_port:Mapped[int|None]=mapped_column(Integer);dst_port:Mapped[int|None]=mapped_column(Integer)
    protocol:Mapped[str]=mapped_column(String(32),nullable=False);length:Mapped[int]=mapped_column(Integer,nullable=False);payload_len:Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    tcp_stream:Mapped[int|None]=mapped_column(Integer);direction:Mapped[str]=mapped_column(String(8),nullable=False)
    is_syn:Mapped[bool]=mapped_column(Boolean,nullable=False,default=False);is_fin:Mapped[bool]=mapped_column(Boolean,nullable=False,default=False)
    is_rst:Mapped[bool]=mapped_column(Boolean,nullable=False,default=False);is_retransmission:Mapped[bool]=mapped_column(Boolean,nullable=False,default=False)
class HttpTransaction(NetworkBase):
    __tablename__="http_transactions"
    id:Mapped[int]=mapped_column(Integer,primary_key=True);pcap_id:Mapped[int]=mapped_column(ForeignKey("pcap_files.id",ondelete="CASCADE"),index=True)
    request_frame:Mapped[int]=mapped_column(Integer,nullable=False);response_frame:Mapped[int|None]=mapped_column(Integer);ts:Mapped[float]=mapped_column(Float,nullable=False)
    tcp_stream:Mapped[int|None]=mapped_column(Integer);client_ip:Mapped[str|None]=mapped_column(String(64));method:Mapped[str]=mapped_column(String(16),nullable=False)
    endpoint_class:Mapped[str]=mapped_column(String(32),nullable=False);path_norm:Mapped[str]=mapped_column(String(120),nullable=False);status_code:Mapped[int|None]=mapped_column(Integer)
    request_body_bytes:Mapped[int|None]=mapped_column(Integer);response_body_bytes:Mapped[int|None]=mapped_column(Integer);latency_ms:Mapped[float|None]=mapped_column(Float)
class Exposure(NetworkBase):
    __tablename__="exposures"
    id:Mapped[int]=mapped_column(Integer,primary_key=True);pcap_id:Mapped[int]=mapped_column(ForeignKey("pcap_files.id",ondelete="CASCADE"),index=True)
    kind:Mapped[str]=mapped_column(String(20),nullable=False);count:Mapped[int]=mapped_column(Integer,nullable=False);frames:Mapped[list[int]]=mapped_column(JSON,nullable=False,default=list);snippet:Mapped[str|None]=mapped_column(Text)
