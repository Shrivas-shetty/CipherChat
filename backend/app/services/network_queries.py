"""Read-only SQL queries for network metadata (no FastAPI imports)."""
import math
from sqlalchemy import Integer,case,func,select
from sqlalchemy.orm import Session
from app.db.network_models import Exposure,HttpTransaction,Packet,PcapFile

def capture_summary(row):
    return {c.name:getattr(row,c.name) for c in PcapFile.__table__.columns if c.name not in {"sidecar_info","sidecar_name"}}
def query_captures(db,limit=50):
    rows=db.scalars(select(PcapFile).order_by(PcapFile.created_at.desc(),PcapFile.id.desc()).limit(max(1,min(limit,200)))).all()
    return [capture_summary(x) for x in rows]
def query_capture_detail(db,pcap_id):
    cap=db.get(PcapFile,pcap_id)
    if cap is None:return None
    protocol=db.execute(select(Packet.protocol,func.count(Packet.id),func.sum(Packet.length)).where(Packet.pcap_id==pcap_id).group_by(Packet.protocol).order_by(func.count(Packet.id).desc())).all()
    conversations=db.execute(select(Packet.src_ip,Packet.src_port,Packet.dst_ip,Packet.dst_port,func.count(Packet.id),func.sum(Packet.length),Packet.direction).where(Packet.pcap_id==pcap_id).group_by(Packet.src_ip,Packet.src_port,Packet.dst_ip,Packet.dst_port,Packet.direction).order_by(func.count(Packet.id).desc()).limit(10)).all()
    classes=db.execute(select(HttpTransaction.endpoint_class,func.count(HttpTransaction.id),func.sum(HttpTransaction.request_body_bytes),func.sum(HttpTransaction.response_body_bytes),func.avg(HttpTransaction.latency_ms)).where(HttpTransaction.pcap_id==pcap_id).group_by(HttpTransaction.endpoint_class).order_by(HttpTransaction.endpoint_class)).all()
    lengths=list(db.scalars(select(Packet.length).where(Packet.pcap_id==pcap_id).order_by(Packet.length)).all());n=len(lengths)
    bins=[("0-63",0,63),("64-127",64,127),("128-255",128,255),("256-511",256,511),("512-1023",512,1023),("1024-1514",1024,1514),(">1514",1515,None)]
    histogram=[]
    for label,low,high in bins:
        filters=[Packet.pcap_id==pcap_id,Packet.length>=low]
        if high is not None:filters.append(Packet.length<=high)
        histogram.append({"label":label,"min":low,"max":high,"count":db.scalar(select(func.count(Packet.id)).where(*filters)) or 0})
    median=(lengths[n//2] if n%2 else (lengths[n//2-1]+lengths[n//2])/2) if n else None
    exposures=db.scalars(select(Exposure).where(Exposure.pcap_id==pcap_id).order_by(Exposure.kind)).all()
    safe_sidecar={k:v for k,v in (cap.sidecar_info or {}).items() if k in {"mode","messages","with_images","started_at_utc","ended_at_utc","pause_ms"}}
    return {"capture":capture_summary(cap),"sidecar_info":safe_sidecar or None,"exposures":[{"kind":x.kind,"count":x.count,"frames":x.frames,"snippet":x.snippet} for x in exposures],
      "http_by_class":[{"endpoint_class":x[0],"count":x[1],"request_body_bytes_total":x[2] or 0,"response_body_bytes_total":x[3] or 0,"mean_latency_ms":x[4]} for x in classes],
      "protocols":[{"protocol":x[0],"packets":x[1],"bytes":x[2] or 0} for x in protocol],
      "conversations":[{"src_ip":x[0],"src_port":x[1],"dst_ip":x[2],"dst_port":x[3],"packets":x[4],"bytes":x[5] or 0,"direction":x[6]} for x in conversations],
      "size_histogram":histogram,"packet_size_stats":{"min":lengths[0] if n else None,"max":lengths[-1] if n else None,"mean":sum(lengths)/n if n else None,"median":median}}
def query_timeline(db,pcap_id,bucket_ms=None):
    cap=db.get(PcapFile,pcap_id)
    if cap is None:return None
    duration=max(0,cap.duration_s or 0);bucket=max(10,min(60000,math.ceil(duration*1000/60))) if bucket_ms is None else max(1,min(600000,bucket_ms))
    if duration*1000/bucket>2000:bucket=math.ceil(duration*1000/2000)
    idx=func.cast(Packet.rel_ts*1000/bucket,Integer)
    rows=db.execute(select(idx,func.count(Packet.id),func.sum(Packet.length),func.sum(case((Packet.direction=="c2s",Packet.length),else_=0)),func.sum(case((Packet.direction=="s2c",Packet.length),else_=0))).where(Packet.pcap_id==pcap_id).group_by(idx).order_by(idx)).all()
    return {"bucket_ms":bucket,"buckets":[{"t":int(r[0])*bucket/1000,"packets":r[1],"bytes":r[2] or 0,"c2s_bytes":r[3] or 0,"s2c_bytes":r[4] or 0} for r in rows]}
def query_packets(db,pcap_id,*,limit=100,after_frame=None,protocol=None,direction=None,src_ip=None,dst_ip=None,min_length=None,flags=None):
    filters=[Packet.pcap_id==pcap_id]
    if after_frame is not None:filters.append(Packet.frame_no>after_frame)
    if protocol:filters.append(Packet.protocol==protocol.upper())
    if direction:filters.append(Packet.direction==direction)
    if src_ip:filters.append(Packet.src_ip==src_ip)
    if dst_ip:filters.append(Packet.dst_ip==dst_ip)
    if min_length is not None:filters.append(Packet.length>=min_length)
    flag={"syn":Packet.is_syn,"fin":Packet.is_fin,"rst":Packet.is_rst,"retransmission":Packet.is_retransmission}.get(flags)
    if flags and flag is not None:filters.append(flag.is_(True))
    limit=max(1,min(limit,500));rows=db.scalars(select(Packet).where(*filters).order_by(Packet.frame_no.asc()).limit(limit+1)).all();more=len(rows)>limit;rows=rows[:limit]
    items=[{c.name:getattr(x,c.name) for c in Packet.__table__.columns if c.name not in {"pcap_id","id"}} for x in rows]
    return {"items":items,"next_after_frame":rows[-1].frame_no if more and rows else None}
def query_http(db,pcap_id,*,limit=100,after_frame=None,endpoint_class=None):
    filters=[HttpTransaction.pcap_id==pcap_id]
    if after_frame is not None:filters.append(HttpTransaction.request_frame>after_frame)
    if endpoint_class:filters.append(HttpTransaction.endpoint_class==endpoint_class)
    limit=max(1,min(limit,500));rows=db.scalars(select(HttpTransaction).where(*filters).order_by(HttpTransaction.request_frame.asc()).limit(limit+1)).all();more=len(rows)>limit;rows=rows[:limit]
    return {"items":[{c.name:getattr(x,c.name) for c in HttpTransaction.__table__.columns if c.name not in {"pcap_id","id"}} for x in rows],"next_after_frame":rows[-1].request_frame if more and rows else None}
def delete_capture(db,pcap_id):
    row=db.get(PcapFile,pcap_id)
    if row is None:return None
    name=row.filename;db.delete(row);db.commit();return name
