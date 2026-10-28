"""Transactional capture metadata ingestion in its own isolated worker process."""
from collections import defaultdict,deque
from datetime import datetime,timezone
from pathlib import Path
import re
from sqlalchemy import create_engine,delete,insert
from sqlalchemy.orm import Session
from app.config import MAX_PACKETS_PER_FILE
from app.network.storage import Exposure,HttpTransaction,NetworkBase,Packet,PcapFile
from app.network.classify import classify_endpoint,normalize_path
from app.network.models import PacketRecord
from app.network.scanner import StreamScanner

def _clean_error(exc):
    s=str(exc)
    s=re.sub(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}","[redacted]",s)
    s=re.sub(r'(?i)(password\s*[=:]\s*)[^\s,;]+',r'\1[redacted]',s)
    s=re.sub(r"(?:[A-Za-z]:)?[/\\](?:[^\s'\"]+[/\\])*[^\s'\"]+","<path>",s)
    return (s or type(exc).__name__)[:300]

def run_ingest(db_path,pcap_path,meta,packet_source):
    engine=create_engine(f"sqlite:///{Path(db_path).resolve()}",connect_args={"check_same_thread":False})
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    NetworkBase.metadata.create_all(engine);pcap_id=int(meta["pcap_id"]);port=int(meta.get("server_port",8000))
    scanner=StreamScanner(meta.get("marker"));rows=[];transactions=[];pending_by_frame={};queues=defaultdict(deque)
    streams=set();clients=set();servers=set()
    summary={"packet_count":0,"first_ts":None,"last_ts":None,"duration_s":0.0,"total_frame_bytes":0,"total_tcp_payload_bytes":0,"tcp_streams":0,"syn_count":0,"retransmissions":0,"http_requests":0,"http_responses":0,"ws_frames":0,"ws_payload_bytes":0,"truncated":False}
    try:
        with Session(engine) as db:
            cap=db.get(PcapFile,pcap_id)
            if not cap:raise ValueError("capture_not_found")
            cap.status="running";cap.error=None;db.commit()
        with Session(engine) as db,db.begin():
            cap=db.get(PcapFile,pcap_id)
            db.execute(delete(Packet).where(Packet.pcap_id==pcap_id));db.execute(delete(HttpTransaction).where(HttpTransaction.pcap_id==pcap_id));db.execute(delete(Exposure).where(Exposure.pcap_id==pcap_id))
            for packet in packet_source:
                if summary["packet_count"]>=MAX_PACKETS_PER_FILE:summary["truncated"]=True;break
                if not isinstance(packet,PacketRecord):raise TypeError("packet_source must yield PacketRecord")
                if summary["first_ts"] is None:summary["first_ts"]=packet.ts
                summary["last_ts"]=packet.ts;summary["packet_count"]+=1;summary["total_frame_bytes"]+=max(0,packet.length);summary["total_tcp_payload_bytes"]+=len(packet.payload)
                if packet.tcp_stream is not None:streams.add(packet.tcp_stream)
                if packet.is_syn:summary["syn_count"]+=1
                if packet.is_retransmission:summary["retransmissions"]+=1
                src_server=packet.src_port==port;dst_server=packet.dst_port==port
                direction="s2c" if src_server else "c2s" if dst_server else "other"
                if src_server and packet.src_ip:servers.add(packet.src_ip)
                if dst_server and packet.dst_ip:servers.add(packet.dst_ip)
                if src_server and packet.dst_ip:clients.add(packet.dst_ip)
                if dst_server and packet.src_ip:clients.add(packet.src_ip)
                rows.append({"pcap_id":pcap_id,"frame_no":packet.frame_no,"ts":packet.ts,"rel_ts":packet.ts-summary["first_ts"],"src_ip":packet.src_ip,"dst_ip":packet.dst_ip,"src_port":packet.src_port,"dst_port":packet.dst_port,"protocol":packet.protocol.upper()[:32],"length":max(0,packet.length),"payload_len":len(packet.payload),"tcp_stream":packet.tcp_stream,"direction":direction,"is_syn":packet.is_syn,"is_fin":packet.is_fin,"is_rst":packet.is_rst,"is_retransmission":packet.is_retransmission})
                if packet.payload:scanner.feed((packet.tcp_stream,direction),packet.payload,packet.frame_no,packet.is_retransmission)
                if packet.ws:summary["ws_frames"]+=1;summary["ws_payload_bytes"]+=max(0,packet.ws.payload_len or 0)
                info=packet.http
                if info:
                    if info.is_request:
                        summary["http_requests"]+=1;path=normalize_path(info.uri)
                        tx={"pcap_id":pcap_id,"request_frame":packet.frame_no,"response_frame":None,"ts":packet.ts,"tcp_stream":packet.tcp_stream,"client_ip":packet.src_ip if direction=="c2s" else packet.dst_ip,"method":(info.method or "OTHER")[:16],"endpoint_class":classify_endpoint(info.method,path),"path_norm":path,"status_code":None,"request_body_bytes":info.content_length,"response_body_bytes":None,"latency_ms":None}
                        pending_by_frame[packet.frame_no]=tx;queues[packet.tcp_stream].append(tx)
                    else:
                        summary["http_responses"]+=1;tx=pending_by_frame.get(info.request_in) if info.request_in is not None else None
                        if tx is None:
                            q=queues[packet.tcp_stream];tx=q.popleft() if q else None
                        else:
                            try:queues[packet.tcp_stream].remove(tx)
                            except ValueError:pass
                        if tx:
                            tx["response_frame"]=packet.frame_no;tx["status_code"]=info.status_code;tx["response_body_bytes"]=info.content_length
                            elapsed=info.time_since_request if info.time_since_request is not None else packet.ts-tx["ts"]
                            tx["latency_ms"]=max(0,elapsed*1000);tx["endpoint_class"]=classify_endpoint(tx["method"],tx["path_norm"],info.status_code)
                            if tx not in transactions:transactions.append(tx)
                if len(rows)>=2000:db.execute(insert(Packet),rows);rows.clear()
            if rows:db.execute(insert(Packet),rows)
            transactions.extend(tx for tx in pending_by_frame.values() if tx not in transactions)
            if transactions:db.execute(insert(HttpTransaction),transactions)
            for kind,f in scanner.result().items():
                if f["count"]:db.add(Exposure(pcap_id=pcap_id,kind=kind,count=f["count"],frames=f["frames"],snippet=f["snippet"] if kind=="marker" else None))
            summary["tcp_streams"]=len(streams);summary["duration_s"]=max(0,(summary["last_ts"] or 0)-(summary["first_ts"] or 0)) if summary["first_ts"] is not None else 0
            cap.status="done";cap.error=None;cap.ingested_at=datetime.now(timezone.utc);cap.tshark_version=meta.get("tshark_version")
            for key,value in summary.items():setattr(cap,key,value)
            cap.client_ips=sorted(clients)[:5];cap.server_ips=sorted(servers)[:5]
        return {**summary,"exposures":scanner.result()}
    except Exception as exc:
        with Session(engine) as db,db.begin():
            cap=db.get(PcapFile,pcap_id)
            if cap:
                db.execute(delete(Packet).where(Packet.pcap_id==pcap_id));db.execute(delete(HttpTransaction).where(HttpTransaction.pcap_id==pcap_id));db.execute(delete(Exposure).where(Exposure.pcap_id==pcap_id))
                cap.status="failed";cap.error=_clean_error(exc);cap.ingested_at=datetime.now(timezone.utc)
        raise
    finally:engine.dispose()

if __name__=="__main__":
    from app.network.cli import main
    raise SystemExit(main())
