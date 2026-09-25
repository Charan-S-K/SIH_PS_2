"""
REST API Endpoints for Stage 13: ML Dataset Generator.
Exposes dataset generation, batch listing, sample record inspection, and CSV/JSON export endpoints.
"""

import csv
import io
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.ml_dataset import MlDatasetBatch, MlDatasetRecord
from app.schemas.ml_dataset import (
    MlDatasetGenerateRequest,
    MlDatasetBatchResponse,
    MlDatasetRecordResponse,
    MlDatasetExportResponse
)
from app.services.ml_dataset_generator import MlDatasetGenerator

router = APIRouter(prefix="/ml/dataset", tags=["ML Dataset Generator"])


@router.post(
    "/generate",
    response_model=MlDatasetBatchResponse,
    summary="Generate synthetic email security ML dataset",
    description="Triggers reproducible synthetic dataset generation across secure, weak crypto, cleartext auth, downgrade attack, and anomalous scenarios."
)
def generate_dataset(
    req: MlDatasetGenerateRequest,
    db: Session = Depends(get_db)
) -> MlDatasetBatchResponse:
    """Generate a new reproducible synthetic ML dataset batch."""
    generator = MlDatasetGenerator()
    try:
        batch = generator.generate_dataset_batch(db, req)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dataset generation failed: {str(exc)}"
        )
    return MlDatasetBatchResponse.model_validate(batch)


@router.get(
    "/batches",
    response_model=List[MlDatasetBatchResponse],
    summary="List all generated synthetic dataset batches",
    description="Retrieves aggregate metadata and label distributions for all synthetic dataset batches."
)
def list_batches(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db)
) -> List[MlDatasetBatchResponse]:
    """Fetch list of generated dataset batches."""
    batches = db.query(MlDatasetBatch).order_by(MlDatasetBatch.created_at.desc()).limit(limit).all()
    return [MlDatasetBatchResponse.model_validate(b) for b in batches]


@router.get(
    "/batches/{batch_id}",
    response_model=MlDatasetBatchResponse,
    summary="Get details and sample records for a dataset batch",
    description="Retrieves complete batch metadata and individual synthetic records with extracted features and ground truth labels."
)
def get_batch_details(
    batch_id: str,
    db: Session = Depends(get_db)
) -> MlDatasetBatchResponse:
    """Fetch detailed dataset batch metadata and records."""
    batch = db.query(MlDatasetBatch).filter(MlDatasetBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset batch with ID '{batch_id}' not found"
        )
    return MlDatasetBatchResponse.model_validate(batch)


@router.get(
    "/export/{batch_id}/csv",
    summary="Export dataset batch as CSV",
    description="Returns CSV formatted content containing all sample records, extracted feature vectors, and ground truth labels for a batch."
)
def export_batch_csv(
    batch_id: str,
    db: Session = Depends(get_db)
):
    """Export dataset records as a CSV file."""
    batch = db.query(MlDatasetBatch).filter(MlDatasetBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset batch with ID '{batch_id}' not found"
        )

    records = db.query(MlDatasetRecord).filter(MlDatasetRecord.batch_id == batch_id).order_by(MlDatasetRecord.sample_index).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    header = [
        "sample_index", "scenario_name", "protocol", "tls_version", "cipher_suite",
        "auth_mechanism", "packet_count", "duration_seconds", "total_bytes",
        "protocol_code", "tls_version_code", "cipher_strength_bits", "is_starttls_used",
        "is_auth_encrypted", "cert_validity_code", "avg_packet_size",
        "ground_truth_label", "label_code", "label_rationale"
    ]
    writer.writerow(header)

    for r in records:
        f = r.features_json or {}
        writer.writerow([
            r.sample_index,
            r.scenario_name,
            r.protocol,
            r.tls_version or "None",
            r.cipher_suite or "None",
            r.auth_mechanism or "None",
            r.packet_count,
            r.duration_seconds,
            r.total_bytes,
            f.get("protocol_code", 0),
            f.get("tls_version_code", 0),
            f.get("cipher_strength_bits", 0),
            f.get("is_starttls_used", 0),
            f.get("is_auth_encrypted", 0),
            f.get("cert_validity_code", 0),
            f.get("avg_packet_size", 0.0),
            r.ground_truth_label,
            r.label_code,
            r.label_rationale
        ])

    csv_content = output.getvalue()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ml_dataset_{batch_id[:8]}.csv"}
    )
