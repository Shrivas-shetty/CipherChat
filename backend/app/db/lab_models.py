from sqlalchemy import Column, DateTime, Float, Integer, JSON, String

from app.db.lab_base import LabBase
from app.db.models import utc_now


class TextMetric(LabBase):
    __tablename__ = "text_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    message_id = Column(Integer, unique=True, nullable=False, index=True)
    session_id = Column(String(36), nullable=False, index=True)
    sender_id = Column(Integer, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    pt_len_bytes = Column(Integer, nullable=False)
    ct_len_bytes = Column(Integer, nullable=False)
    total_ct_bits = Column(Integer, nullable=False)
    key_trials = Column(Integer, nullable=False)
    confusion_pct = Column(Float, nullable=False)
    key_flip_pcts = Column(JSON, nullable=False)
    pt_trials = Column(Integer, nullable=False)
    diffusion_bits = Column(Float, nullable=False)
    avalanche_pct = Column(Float, nullable=False)
    block_avalanche_pct = Column(Float, nullable=False)
    pt_flip_bit_idx = Column(JSON, nullable=False)
    pt_flip_changed_bits = Column(JSON, nullable=False)
    pt_flip_block_changed_bits = Column(JSON, nullable=False)
    enc_us = Column(Float, nullable=False)
    dec_us = Column(Float, nullable=False)
    timing_iters = Column(Integer, nullable=False)
