import argparse,sys
from sqlalchemy import create_engine,select
from sqlalchemy.orm import Session
from app.config import MAX_PCAP_MB,get_network_db_file_path
from app.network.storage import NetworkBase,PcapFile
from app.network.ingest import _clean_error,run_ingest
from app.network.pyshark_adapter import iter_packets
from app.network.tshark_locator import find_tshark,tshark_version
from app.network.validation import InvalidInput,read_sidecar,read_sidecar_marker,validate_ingest

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument("filename");p.add_argument("--label",required=True);p.add_argument("--scenario",required=True);p.add_argument("--marker");p.add_argument("--sidecar");p.add_argument("--server-port",type=int,default=8000);p.add_argument("--replace",action="store_true");p.add_argument("--pcap-id",type=int);a=p.parse_args(argv)
    try:path=validate_ingest(a.filename,a.label,a.scenario,a.marker,a.server_port,a.sidecar)
    except (InvalidInput,FileNotFoundError) as exc:print(str(exc),file=sys.stderr);return 1
    if not path.is_file():print("file_not_found",file=sys.stderr);return 1
    if path.stat().st_size>MAX_PCAP_MB*1024*1024:print("pcap_too_large",file=sys.stderr);return 1
    tshark=find_tshark()
    if not tshark:print("tshark_unavailable",file=sys.stderr);return 1
    try:
        marker=a.marker or (read_sidecar_marker(a.sidecar) if a.sidecar else None);sidecar_info=read_sidecar(a.sidecar) if a.sidecar else None
        engine=create_engine(f"sqlite:///{get_network_db_file_path()}",connect_args={"check_same_thread":False});NetworkBase.metadata.create_all(engine)
        with Session(engine) as db:
            row=db.get(PcapFile,a.pcap_id) if a.pcap_id else db.scalar(select(PcapFile).where(PcapFile.filename==a.filename))
            if a.pcap_id and (row is None or row.filename!=a.filename):print("capture_not_found",file=sys.stderr);return 1
            if row and not(a.replace or a.pcap_id):print("already_ingested",file=sys.stderr);return 1
            if row is None:row=PcapFile(filename=a.filename,size_bytes=path.stat().st_size,label=a.label,scenario=a.scenario,marker=marker,server_port=a.server_port,sidecar_name=a.sidecar,sidecar_info=sidecar_info,status="queued");db.add(row);db.commit();db.refresh(row)
            else:row.label=a.label;row.scenario=a.scenario;row.marker=marker;row.server_port=a.server_port;row.sidecar_name=a.sidecar;row.sidecar_info=sidecar_info;row.size_bytes=path.stat().st_size;row.status="queued";db.commit()
            pcap_id=row.id
        result=run_ingest(get_network_db_file_path(),path,{"pcap_id":pcap_id,"server_port":a.server_port,"marker":marker,"tshark_version":tshark_version(tshark)},iter_packets(path,a.server_port,tshark))
        print(f"done pcap_id={pcap_id} packets={result['packet_count']} bytes={result['total_frame_bytes']} truncated={result['truncated']}");engine.dispose();return 0
    except Exception as exc:print(_clean_error(exc),file=sys.stderr);return 1

