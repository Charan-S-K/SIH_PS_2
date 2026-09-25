"""
SQLAlchemy Model for Stage 13: ML Dataset Generator.
Stores synthetic training and evaluation dataset batches, extracted session features,
ground truth security labels, and transparent labeling rationales.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class MlDatasetBatch(Base):
    """
    Represents a synthetic ML dataset generation batch run.
    """
    __tablename__ = "ml_dataset_batches"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, default="Synthetic Email Security Dataset")
    seed = Column(Integer, nullable=False, default=42)
    sample_count = Column(Integer, nullable=False, default=100)
    secure_samples_count = Column(Integer, nullable=False, default=0)
    weak_crypto_count = Column(Integer, nullable=False, default=0)
    plaintext_leak_count = Column(Integer, nullable=False, default=0)
    downgrade_attack_count = Column(Integer, nullable=False, default=0)
    anomalous_count = Column(Integer, nullable=False, default=0)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    records = relationship("MlDatasetRecord", back_populates="batch", cascade="all, delete-orphan")


class MlDatasetRecord(Base):
    """
    Individual sample record in a synthetic ML dataset.
    """
    __tablename__ = "ml_dataset_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    batch_id = Column(String, ForeignKey("ml_dataset_batches.id", ondelete="CASCADE"), nullable=False)
    sample_index = Column(Integer, nullable=False)
    scenario_name = Column(String, nullable=False)
    protocol = Column(String, nullable=False)  # SMTP, SMTPS, IMAP, IMAPS, POP3, POP3S
    tls_version = Column(String, nullable=True)  # TLS 1.3, TLS 1.2, TLS 1.0, None
    cipher_suite = Column(String, nullable=True)
    auth_mechanism = Column(String, nullable=True)  # PLAIN, LOGIN, XOAUTH2, CRAM-MD5
    
    # Traffic features
    packet_count = Column(Integer, nullable=False, default=0)
    duration_seconds = Column(Float, nullable=False, default=0.0)
    total_bytes = Column(Integer, nullable=False, default=0)
    
    # Ground truth labeling
    ground_truth_label = Column(String, nullable=False)  # SECURE, WEAK_CRYPTO, PLAINTEXT_LEAK, DOWNGRADE_ATTACK, ANOMALOUS
    label_code = Column(Integer, nullable=False)  # 0: SECURE, 1: WEAK_CRYPTO, 2: PLAINTEXT_LEAK, 3: DOWNGRADE_ATTACK, 4: ANOMALOUS
    label_rationale = Column(String, nullable=False)
    
    # Extracted feature dictionary for ML models
    features_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    batch = relationship("MlDatasetBatch", back_populates="records")
