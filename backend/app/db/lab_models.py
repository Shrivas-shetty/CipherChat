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


class ImageMetric(LabBase):
    __tablename__ = "image_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    message_id = Column(Integer, unique=True, nullable=False, index=True)
    session_id = Column(String(36), nullable=False, index=True)
    sender_id = Column(Integer, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    n_pixels = Column(Integer, nullable=False)
    pt_len_bytes = Column(Integer, nullable=False)
    ct_len_bytes = Column(Integer, nullable=False)
    npcr_trials = Column(Integer, nullable=False)
    npcr_pct = Column(Float, nullable=False)
    npcr_trial_pcts = Column(JSON, nullable=False)
    npcr_changed_counts = Column(JSON, nullable=False)
    uaci_pct = Column(Float, nullable=False)
    uaci_trial_pcts = Column(JSON, nullable=False)
    flip_byte_idx = Column(JSON, nullable=False)
    entropy_r = Column(Float, nullable=False)
    entropy_g = Column(Float, nullable=False)
    entropy_b = Column(Float, nullable=False)
    entropy_avg = Column(Float, nullable=False)
    corr_pt_r = Column(Float, nullable=True)
    corr_pt_g = Column(Float, nullable=True)
    corr_pt_b = Column(Float, nullable=True)
    corr_pt_avg = Column(Float, nullable=True)
    corr_ct_r = Column(Float, nullable=True)
    corr_ct_g = Column(Float, nullable=True)
    corr_ct_b = Column(Float, nullable=True)
    corr_ct_avg = Column(Float, nullable=True)
    mse_dec = Column(Float, nullable=False)
    psnr_dec = Column(Float, nullable=True)
    mse_enc = Column(Float, nullable=False)
    psnr_enc = Column(Float, nullable=True)
    enc_us = Column(Float, nullable=False)
    dec_us = Column(Float, nullable=False)
    timing_iters = Column(Integer, nullable=False)
