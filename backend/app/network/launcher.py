from pathlib import Path
import subprocess,sys,threading
from sqlalchemy.orm import Session
from app import config
from app.config import get_pcap_dir
from app.db import network_base
from app.db.network_models import PcapFile
from app.services.audit import log_event

_lock=threading.Lock();_active_ids=set()
def ingest_running():
    with _lock:return bool(_active_ids)
def is_ingesting(pcap_id):
    with _lock:return pcap_id in _active_ids
def launch_ingest(db:Session,*,filename,pcap_path,label,scenario,marker,server_port,sidecar,sidecar_info,replace,user_id=None):
    capture=db.query(PcapFile).filter(PcapFile.filename==filename).first()
    if capture and not replace:raise FileExistsError("already_ingested")
    if capture and capture.status in ("queued","running"):raise RuntimeError("ingest_busy")
    with _lock:
        if _active_ids:raise RuntimeError("ingest_busy")
        if capture:
            capture.size_bytes=pcap_path.stat().st_size;capture.label=label;capture.scenario=scenario;capture.marker=marker;capture.server_port=server_port;capture.sidecar_name=sidecar;capture.sidecar_info=sidecar_info;capture.status="queued";capture.error=None;capture.ingested_at=None
        else:
            capture=PcapFile(filename=filename,size_bytes=pcap_path.stat().st_size,label=label,scenario=scenario,marker=marker,server_port=server_port,sidecar_name=sidecar,sidecar_info=sidecar_info,status="queued");db.add(capture)
        db.commit();db.refresh(capture);pcap_id=capture.id
        args=[sys.executable,"-m","app.network.ingest",filename,"--label",label,"--scenario",scenario,"--server-port",str(server_port),"--pcap-id",str(pcap_id)]
        if marker:args.extend(["--marker",marker])
        if sidecar:args.extend(["--sidecar",sidecar])
        if replace:args.append("--replace")
        log=(get_pcap_dir()/f".ingest_{pcap_id}.log").open("ab")
        try:proc=subprocess.Popen(args,cwd=str(Path(__file__).resolve().parents[2]),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=log,shell=False)
        except Exception:
            log.close();capture.status="failed";capture.error="subprocess_start_failed";db.commit();raise
        _active_ids.add(pcap_id)
    log_event("NETWORK_INGEST_STARTED",severity="info",user_id=user_id,details={"filename":filename,"scenario":scenario,"label":label,"pcap_id":pcap_id})
    def watch():
        try:
            try:code=proc.wait(timeout=config.INGEST_TIMEOUT_SECONDS);timeout=False
            except subprocess.TimeoutExpired:proc.kill();proc.wait();code=1;timeout=True
            with network_base.NetworkSessionLocal() as status_db:
                row=status_db.get(PcapFile,pcap_id)
                if row:
                    if timeout:row.status="failed";row.error="timeout"
                    elif code!=0 and row.status!="failed":row.status="failed";row.error="ingest_failed"
                    done=code==0 and row.status=="done";name=row.filename;error=row.error;status_db.commit()
                else:done=False;name=filename;error="capture_missing"
            log_event("NETWORK_INGEST_DONE" if done else "NETWORK_INGEST_FAILED",severity="info" if done else "warning",user_id=user_id,success=done,details={"filename":name,"pcap_id":pcap_id,**({"error":error} if error else {})})
        except Exception as exc:
            log_event("NETWORK_INGEST_FAILED",severity="warning",user_id=user_id,success=False,details={"filename":filename,"pcap_id":pcap_id,"error":"watcher_error"})
        finally:
            log.close()
            with _lock:_active_ids.discard(pcap_id)
    threading.Thread(target=watch,daemon=True,name=f"pcap-ingest-{pcap_id}").start()
    return pcap_id
