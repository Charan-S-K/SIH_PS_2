"""
Pydantic Schemas for Stage 13: ML Dataset Generator.
Defines requests, record representations, batch summaries, and CSV/JSON export schemas.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MlDatasetGenerateRequest(BaseModel):
    """Request payload to trigger synthetic dataset generation."""
    name: Optional[str] = Field(default="Synthetic Email Security Dataset", description="Custom name for the dataset batch")
    sample_count: int = Field(default=100, ge=10, le=5000, description="Total synthetic samples to generate")
    seed: int = Field(default=42, description="Random seed for reproducible generation")
    include_weak_scenarios: bool = Field(default=True, description="Whether to include weak crypto, plaintext, downgrade, and anomalous scenarios")
    description: Optional[str] = Field(default="Synthetic dataset for training email security risk classifiers", description="Batch description")


class MlDatasetRecordResponse(BaseModel):
    """Schema for individual dataset sample record."""
    id: str
    batch_id: str
    sample_index: int
    scenario_name: str
    protocol: str
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    auth_mechanism: Optional[str] = None
    packet_count: int
    duration_seconds: float
    total_bytes: int
    ground_truth_label: str
    label_code: int
    label_rationale: str
    features_json: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class MlDatasetBatchResponse(BaseModel):
    """Schema for ML Dataset Batch metadata and label distribution."""
    id: str
    name: str
    seed: int
    sample_count: int
    secure_samples_count: int
    weak_crypto_count: int
    plaintext_leak_count: int
    downgrade_attack_count: int
    anomalous_count: int
    description: Optional[str] = None
    created_at: datetime
    records: Optional[List[MlDatasetRecordResponse]] = None

    class Config:
        from_attributes = True


class MlDatasetExportResponse(BaseModel):
    """Schema for dataset export."""
    batch_id: str
    batch_name: str
    total_records: int
    csv_url: Optional[str] = None
    records: List[MlDatasetRecordResponse]
