import sqlite3
from pathlib import Path
import pytest
from sqlalchemy import create_engine,select
from sqlalchemy.orm import Session
from app.db.network_models import Exposure,HttpTransaction,NetworkBase,Packet,PcapFile
from app.network.ingest import run_ingest
from app.network.models import HttpInfo,PacketRecord,WsInfo

def packet(n,**kw):
    base=dict(frame_no=n,ts=1000+n*.01,length=100,src_ip="10.0.0.2",dst_ip="10.0.0.1",src_port=5000,dst_port=8000,protocol="TCP",tcp_stream=1)
    base.update(kw);return PacketRecord(**base)
def prepared(db):
    NetworkBase.metadata.create_all(create_engine(f"sqlite:///{db}"))
    with Session(create_engine(f"sqlite:///{db}")) as s:
        c=PcapFile(filename="test.pcap",size_bytes=100,label="test",scenario="plain_baseline",marker="SECRETWORD123",server_port=8000,status="queued");s.add(c);s.commit();return c.id

def test_ingest_counters_directions_http_pairing_exposure_and_no_secret(tmp_path,monkeypatch):
    import app.network.ingest as ingest
    db=tmp_path/"network.db";pid=prepared(db)
    password=b'"password":"test-password-93"';jwt=b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature";body=b"private baseline text"
    source=[packet(1,is_syn=True,payload=b"POST /api/auth/login HTTP/1.1\r\n"+password+ b"\r\n"+jwt),
      packet(2,dst_port=8000,src_port=8000,src_ip="10.0.0.1",dst_ip="10.0.0.2",protocol="WEBSOCKET",ws=WsInfo(1,8)),
      packet(3,http=HttpInfo(True,"POST","/api/baseline/messages",content_length=len(body)),payload=body[:8]+b"SECRET"),
      packet(4,http=HttpInfo(False,status_code=200,content_length=2,request_in=3,time_since_request=.02),payload=b"WORD123",is_retransmission=False),
      packet(5,http=HttpInfo(True,"GET","/api/messages/42?token=x"),tcp_stream=2),
      packet(6,http=HttpInfo(False,status_code=200,request_in=None,content_length=5),tcp_stream=2)]
    result=run_ingest(db,tmp_path/"test.pcap",{"pcap_id":pid,"server_port":8000,"marker":"SECRETWORD123"},iter(source))
    assert result["packet_count"]==6 and result["total_frame_bytes"]==600 and result["tcp_streams"]==2
    assert result["syn_count"]==1 and result["ws_frames"]==1 and result["ws_payload_bytes"]==8
    with Session(create_engine(f"sqlite:///{db}")) as s:
        packets=s.scalars(select(Packet).where(Packet.pcap_id==pid).order_by(Packet.frame_no)).all()
        assert packets[0].direction=="c2s" and packets[1].direction=="s2c"
        tx=s.scalars(select(HttpTransaction).where(HttpTransaction.pcap_id==pid).order_by(HttpTransaction.request_frame)).all()
        assert tx[0].endpoint_class=="baseline_send" and tx[0].response_frame==4 and tx[0].latency_ms==pytest.approx(20)
        assert tx[1].endpoint_class=="message_fetch" and tx[1].response_frame==6
        ex=s.scalars(select(Exposure).where(Exposure.pcap_id==pid)).all();assert {x.kind:x.count for x in ex}=={"jwt":1,"password_field":1,"marker":1}
        assert next(x for x in ex if x.kind=="marker").snippet and all(x.snippet is None for x in ex if x.kind!="marker")
    data=db.read_bytes();assert b"test-password-93" not in data and jwt not in data and body not in data

def test_ingest_truncation_and_failure_cleanup(tmp_path,monkeypatch):
    import app.network.ingest as ingest
    db=tmp_path/"n.db";pid=prepared(db);monkeypatch.setattr(ingest,"MAX_PACKETS_PER_FILE",2)
    summary=run_ingest(db,"x",{"pcap_id":pid},iter([packet(1),packet(2),packet(3)]));assert summary["packet_count"]==2 and summary["truncated"]
    monkeypatch.setattr(ingest,"MAX_PACKETS_PER_FILE",300000)
    def broken():yield packet(10);raise RuntimeError("password=must-not-leak")
    with pytest.raises(RuntimeError):run_ingest(db,"x",{"pcap_id":pid},broken())
    with Session(create_engine(f"sqlite:///{db}")) as s:
        assert s.query(Packet).filter_by(pcap_id=pid).count()==0
        c=s.get(PcapFile,pid);assert c.status=="failed" and "must-not-leak" not in c.error
