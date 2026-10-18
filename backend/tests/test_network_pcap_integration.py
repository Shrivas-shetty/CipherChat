import os
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app.config import get_network_db_file_path
from app.db.network_models import Exposure, HttpTransaction, NetworkBase, Packet, PcapFile
from app.network.ingest import run_ingest
from app.network.pyshark_adapter import iter_packets
from app.network.tshark_locator import find_tshark, tshark_version
from tests.tools.make_pcap import make_pcap

pytestmark = pytest.mark.integration


@pytest.mark.skipif(os.getenv("CC_SKIP_INTEGRATION") == "1", reason="CC_SKIP_INTEGRATION=1")
@pytest.mark.skipif(find_tshark() is None, reason="tshark is not installed or was not found")
def test_real_tshark_synthetic_capture(tmp_path, monkeypatch):
    tshark = find_tshark()
    path = tmp_path / "synthetic.pcap"
    expected = make_pcap(path)
    db_path = tmp_path / "network.db"
    engine = create_engine(f"sqlite:///{db_path}")
    NetworkBase.metadata.create_all(engine)
    with Session(engine) as db:
        cap = PcapFile(filename=path.name, size_bytes=path.stat().st_size, label="integration",
                       scenario="plain_baseline", marker="SECRETWORD123", server_port=8000, status="queued")
        db.add(cap); db.commit(); pid = cap.id
    monkeypatch.setattr("app.network.ingest.MAX_PACKETS_PER_FILE", 300000)
    run_ingest(db_path, path, {"pcap_id": pid, "server_port": 8000, "marker": "SECRETWORD123",
                               "tshark_version": tshark_version(tshark)}, iter_packets(path, 8000, tshark))
    with Session(engine) as db:
        cap = db.get(PcapFile, pid)
        assert cap.packet_count == expected
        assert cap.total_frame_bytes > 0 and cap.syn_count >= 1
        assert cap.http_requests >= 2 and cap.http_responses >= 2
        packets = db.scalars(select(Packet).where(Packet.pcap_id == pid).order_by(Packet.frame_no)).all()
        assert len(packets) == expected and packets[0].frame_no == 1
        assert {packet.direction for packet in packets} >= {"c2s", "s2c"}
        transactions = db.scalars(select(HttpTransaction).where(HttpTransaction.pcap_id == pid)).all()
        assert len(transactions) >= 2
        assert {transaction.endpoint_class for transaction in transactions} >= {"login", "baseline_send"}
        assert any(transaction.status_code == 200 for transaction in transactions)
        exposures = {x.kind: x for x in db.scalars(select(Exposure).where(Exposure.pcap_id == pid))}
        assert exposures["marker"].count == exposures["jwt"].count == exposures["password_field"].count == 1
        assert exposures["marker"].frames
    engine.dispose()
