import pytest
import threading
import time
from sqlalchemy import create_engine,func
from sqlalchemy.orm import Session
from app import config
from app.db import base
from app.db.models import AuditLog
from app.db.network_base import NetworkSessionLocal,set_network_engine_and_session
from app.db.network_models import Exposure,HttpTransaction,NetworkBase,Packet,PcapFile
from app.network.models import HttpInfo,PacketRecord
from app.services.audit import verify_chain_detailed
from app.services.dashboard_queries import EVENT_CATEGORIES
from tests.test_lab_text_metrics import _auth
pytest_plugins=["tests.test_lab_text_metrics"]

@pytest.fixture
def net(scenario,tmp_path,monkeypatch):
    old=NetworkSessionLocal
    engine=create_engine(f"sqlite:///{tmp_path/'network.db'}",connect_args={"check_same_thread":False})
    set_network_engine_and_session(engine);NetworkBase.metadata.create_all(engine)
    from app.routers import network as router
    pcap_dir=tmp_path/"pcaps";bench_dir=tmp_path/"bench";pcap_dir.mkdir();bench_dir.mkdir()
    monkeypatch.setattr(router,"get_pcap_dir",lambda:pcap_dir);monkeypatch.setattr(router,"get_bench_dir",lambda:bench_dir)
    from app.network import validation
    monkeypatch.setattr(validation,"get_pcap_dir",lambda:pcap_dir);monkeypatch.setattr(validation,"get_bench_dir",lambda:bench_dir)
    yield {"scenario":scenario,"engine":engine,"pcaps":pcap_dir,"bench":bench_dir,"router":router}
    engine.dispose();set_network_engine_and_session(old.kw["bind"])

def seed(net):
    path=net["pcaps"]/"capture.pcap";path.write_bytes(b"pcap")
    with Session(net["engine"]) as db:
        c=PcapFile(filename=path.name,size_bytes=4,label="test",scenario="plain_baseline",marker="SECRETWORD123",server_port=8000,status="done",packet_count=3,duration_s=.2,total_frame_bytes=300,total_tcp_payload_bytes=10,tcp_streams=1,syn_count=1,http_requests=1,http_responses=1)
        db.add(c);db.flush();pid=c.id
        for n,direction in ((1,"c2s"),(2,"s2c"),(3,"c2s")):
            db.add(Packet(pcap_id=pid,frame_no=n,ts=100+n*.1,rel_ts=n*.1,src_ip="10.0.0.2",dst_ip="10.0.0.1",src_port=5000,dst_port=8000,protocol="TCP",length=100,payload_len=3,tcp_stream=1,direction=direction,is_syn=n==1))
        db.add(HttpTransaction(pcap_id=pid,request_frame=2,response_frame=3,ts=1,tcp_stream=1,client_ip="10.0.0.2",method="POST",endpoint_class="baseline_send",path_norm="/api/baseline/messages",status_code=200,request_body_bytes=5,response_body_bytes=4,latency_ms=2))
        db.add(Exposure(pcap_id=pid,kind="marker",count=1,frames=[2],snippet="xx SECRETWORD123 yy"));db.commit()
    return path,pid

def test_auth_status_files_validation_and_launch_errors(net,monkeypatch):
    c=net["scenario"]["client"];analyst=net["scenario"]["analyst"];user=net["scenario"]["alice"]
    endpoints=[("get","/status"),("get","/files"),("get","/captures"),("get","/captures/1"),("get","/captures/1/timeline"),("get","/captures/1/packets"),("get","/captures/1/http"),("delete","/captures/1")]
    for method,path in endpoints:
        assert getattr(c,method)("/api/dashboard/network"+path).status_code==401
        assert getattr(c,method)("/api/dashboard/network"+path,headers=_auth(user)).status_code==403
    monkeypatch.setattr(net["router"],"find_tshark",lambda:None)
    status=c.get("/api/dashboard/network/status",headers=_auth(analyst)).json()
    assert status=={"pyshark_installed":pytest.importorskip("importlib").util.find_spec("pyshark") is not None,"tshark_path":None,"tshark_version":None,"pcap_dir":"backend/data/pcaps","ingest_running":False}
    assert "network" in EVENT_CATEGORIES
    for name in ("../x.pcap","..\\x.pcap","C:\\Windows\\x.pcap","has space.pcap","x.txt"):
        res=c.post("/api/dashboard/network/ingest",headers=_auth(analyst),json={"filename":name,"label":"ok","scenario":"other"})
        assert res.status_code==400
    bad=c.post("/api/dashboard/network/ingest",headers=_auth(analyst),json={"filename":"capture.pcap","label":"ok","scenario":"other","unknown":1})
    assert bad.status_code==422
    (net["pcaps"] / "capture.pcap").write_bytes(b"pcap")
    valid={"filename":"capture.pcap","label":"ok","scenario":"other"}
    assert c.post("/api/dashboard/network/ingest",headers=_auth(analyst),json=valid).status_code==503
    assert c.post("/api/dashboard/network/ingest",headers=_auth(analyst),json={**valid,"marker":"x"}).status_code==400
    assert c.post("/api/dashboard/network/ingest",json=valid).status_code==401
    assert c.post("/api/dashboard/network/ingest",headers=_auth(user),json=valid).status_code==403
    for port in (0,65536):
        assert c.post("/api/dashboard/network/ingest",headers=_auth(analyst),json={**valid,"server_port":port}).status_code==400
    sidecar=(net["bench"]/"traffic_secure.json");sidecar.write_text('{"mode":"secure","messages":2,"marker":"SECRETWORD123","password":"never expose"}')
    (net["bench"]/"invalid name.json").write_text('{}')
    (net["bench"]/"traffic_nested.json").write_text('{"mode":{"token":"must not leak"}}')
    listed=c.get("/api/dashboard/network/files",headers=_auth(analyst)).json()
    assert [x["filename"] for x in listed["sidecars"]]==["traffic_secure.json"]
    assert "must not leak" not in repr(listed)

def test_queries_privacy_paging_delete_and_audits(net):
    path,pid=seed(net);c=net["scenario"]["client"];analyst=net["scenario"]["analyst"]
    with base.SessionLocal() as appdb:before=appdb.query(func.count(AuditLog.id)).scalar()
    assert c.get("/api/dashboard/network/status",headers=_auth(analyst)).status_code==200
    assert c.get("/api/dashboard/network/files",headers=_auth(analyst)).json()["pcaps"][0]["filename"]=="capture.pcap"
    listed=c.get("/api/dashboard/network/captures",headers=_auth(analyst)).json()["items"];assert listed[0]["id"]==pid
    detail=c.get(f"/api/dashboard/network/captures/{pid}",headers=_auth(analyst)).json()
    assert detail["capture"]["packet_count"]==3 and detail["exposures"][0]["kind"]=="marker"
    assert detail["http_by_class"][0]["endpoint_class"]=="baseline_send"
    timeline=c.get(f"/api/dashboard/network/captures/{pid}/timeline?bucket_ms=1",headers=_auth(analyst)).json()
    assert sum(x["packets"] for x in timeline["buckets"])==3
    page1=c.get(f"/api/dashboard/network/captures/{pid}/packets?limit=2",headers=_auth(analyst)).json();page2=c.get(f"/api/dashboard/network/captures/{pid}/packets?limit=2&after_frame={page1['next_after_frame']}",headers=_auth(analyst)).json()
    assert [x["frame_no"] for x in page1["items"]+page2["items"]]==[1,2,3]
    http=c.get(f"/api/dashboard/network/captures/{pid}/http?endpoint_class=baseline_send",headers=_auth(analyst)).json();assert len(http["items"])==1
    def keys(value):
        if isinstance(value,dict):
            for key,child in value.items():yield key.lower();yield from keys(child)
        elif isinstance(value,list):
            for child in value:yield from keys(child)
    assert not set(keys(detail)) & {"payload","body","token","password","header","headers"}
    with base.SessionLocal() as appdb:assert appdb.query(func.count(AuditLog.id)).scalar()==before
    assert c.delete(f"/api/dashboard/network/captures/{pid}",headers=_auth(analyst)).status_code==204
    assert path.is_file()
    with base.SessionLocal() as appdb:
        assert appdb.query(AuditLog).filter(AuditLog.event_type=="NETWORK_CAPTURE_DELETED").count()==1
        assert verify_chain_detailed(appdb)["ok"]

def test_worker_isolated_and_api_watcher_audits(net,monkeypatch):
    from pathlib import Path
    import app.network.cli as cli
    import app.network.ingest as worker
    import app.network.launcher as launcher
    assert "app.db" not in Path(worker.__file__).read_text(encoding="utf-8")
    assert "app.db" not in Path(cli.__file__).read_text(encoding="utf-8")
    assert "services.audit" not in Path(worker.__file__).read_text(encoding="utf-8")
    assert "services.audit" not in Path(cli.__file__).read_text(encoding="utf-8")
    path=net["pcaps"]/"watch.pcap";path.write_bytes(b"pcap")
    analyst=net["scenario"]["analyst"]
    class FakeProc:
        def __init__(self,success):self.success=success
        def wait(self,timeout=None):
            with Session(net["engine"]) as db:
                row=db.query(PcapFile).filter_by(filename=path.name).one();row.status="done" if self.success else "failed";row.error=None if self.success else "fake_failure";db.commit()
            return 0 if self.success else 1
        def kill(self):raise AssertionError("not timed out")
    for success,event_type in ((True,"NETWORK_INGEST_DONE"),(False,"NETWORK_INGEST_FAILED")):
        monkeypatch.setattr(launcher.subprocess,"Popen",lambda *args,success=success,**kwargs:FakeProc(success))
        with Session(net["engine"]) as db:
            pid=launcher.launch_ingest(db,filename=path.name,pcap_path=path,label="watch",scenario="other",marker=None,server_port=8000,sidecar=None,sidecar_info=None,replace=not success,user_id=None)
        deadline=time.time()+3
        while time.time()<deadline:
            with base.SessionLocal() as db:
                if db.query(AuditLog).filter_by(event_type=event_type).count():break
            time.sleep(.02)
        with base.SessionLocal() as db:
            assert db.query(AuditLog).filter_by(event_type=event_type).count()==1
            assert verify_chain_detailed(db)["ok"]
