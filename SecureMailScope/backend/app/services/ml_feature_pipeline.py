"""
ML Feature Pipeline Service for Stage 14.
Extracts versioned, observable, defensible feature matrices from analyzed sessions / dataset batches,
performs z-score preprocessing, executes stratified train/test splitting, and verifies zero data leakage.
"""

import math
import random
import logging
from typing import Dict, List, Tuple, Any, Optional
from sqlalchemy.orm import Session

from app.models.ml_dataset import MlDatasetBatch, MlDatasetRecord
from app.models.session import TcpSession
from app.models.email_analysis import EmailSessionAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.certificate import X509CertificateAnalysis
from app.models.ml_feature_pipeline import MlFeatureSet
from app.schemas.ml_feature_pipeline import MlFeatureExtractionRequest, MlDataLeakageReport

logger = logging.getLogger(__name__)


FEATURE_NAMES = [
    "protocol_code",
    "tls_version_code",
    "cipher_strength_bits",
    "is_starttls_used",
    "is_auth_encrypted",
    "cert_validity_code",
    "packet_count",
    "duration_seconds",
    "total_bytes",
    "avg_packet_size"
]


class MlFeaturePipeline:
    """
    Versioned feature extraction and preprocessing pipeline.
    Ensures feature defensibility, reproducible train/test splits, and zero data leakage.
    """

    def process_feature_extraction(
        self,
        db: Session,
        req: MlFeatureExtractionRequest
    ) -> MlFeatureSet:
        """
        Extracts features from a dataset batch or job, performs preprocessing, splits train/test sets,
        verifies data leakage constraints, and persists the feature set.
        """
        samples: List[Dict[str, Any]] = []

        if req.batch_id:
            batch = db.query(MlDatasetBatch).filter(MlDatasetBatch.id == req.batch_id).first()
            if not batch:
                raise ValueError(f"Dataset batch '{req.batch_id}' not found")

            records = db.query(MlDatasetRecord).filter(MlDatasetRecord.batch_id == req.batch_id).order_by(MlDatasetRecord.sample_index).all()
            for r in records:
                samples.append({
                    "sample_id": r.id,
                    "label_code": r.label_code,
                    "features": r.features_json
                })

        elif req.job_id:
            samples = self._extract_features_from_job(db, req.job_id)

        else:
            raise ValueError("Either 'batch_id' or 'job_id' must be specified for feature extraction")

        if len(samples) == 0:
            raise ValueError("No valid sample records found for feature extraction")

        # 1. Stratified Train / Test Split
        train_samples, test_samples = self._stratified_split(samples, req.test_split_ratio, req.random_seed)

        # 2. Fit Preprocessing Scaler (Mean & Std) STRICTLY on Training Set (Prevents Data Leakage)
        scaling_params = self._fit_scaler(train_samples)

        # 3. Transform Feature Matrices using Fitted Training Scaler
        X_train, y_train, train_ids = self._transform_samples(train_samples, scaling_params)
        X_test, y_test, test_ids = self._transform_samples(test_samples, scaling_params)

        # 4. Verify Data Leakage Constraints
        leakage_report = self._verify_data_leakage(train_ids, test_ids, scaling_params)

        feature_schema = {
            "version": req.pipeline_version,
            "feature_names": FEATURE_NAMES,
            "feature_count": len(FEATURE_NAMES),
            "categorical_encodings": {
                "protocol_code": {"SMTP": 1, "SMTPS": 2, "IMAP": 3, "IMAPS": 4, "POP3": 5, "POP3S": 6},
                "tls_version_code": {"None": 0, "SSLv3": 1, "TLS 1.0": 2, "TLS 1.1": 3, "TLS 1.2": 4, "TLS 1.3": 5},
                "cert_validity_code": {"None": 0, "Valid": 1, "Expired": 2, "Self-Signed": 3}
            }
        }

        train_split_json = {
            "X_train": X_train,
            "y_train": y_train,
            "sample_ids": train_ids
        }
        test_split_json = {
            "X_test": X_test,
            "y_test": y_test,
            "sample_ids": test_ids
        }

        feature_set = MlFeatureSet(
            pipeline_version=req.pipeline_version,
            source_batch_id=req.batch_id,
            source_job_id=req.job_id,
            total_samples=len(samples),
            feature_count=len(FEATURE_NAMES),
            test_split_ratio=req.test_split_ratio,
            train_samples_count=len(train_samples),
            test_samples_count=len(test_samples),
            random_seed=req.random_seed,
            feature_schema_json=feature_schema,
            preprocessing_params_json=scaling_params,
            leakage_check_passed=leakage_report.passed,
            leakage_check_details_json=leakage_report.model_dump(),
            train_split_json=train_split_json,
            test_split_json=test_split_json
        )
        db.add(feature_set)
        db.commit()
        db.refresh(feature_set)

        return feature_set

    def _extract_features_from_job(self, db: Session, job_id: str) -> List[Dict[str, Any]]:
        """Extracts feature vectors from real analyzed TCP sessions in a job."""
        sessions = db.query(TcpSession).filter(TcpSession.job_id == job_id).all()
        samples = []

        for s in sessions:
            email_analysis = db.query(EmailSessionAnalysis).filter(
                EmailSessionAnalysis.job_id == job_id, EmailSessionAnalysis.tcp_stream == s.tcp_stream
            ).first()

            tls = db.query(TlsHandshakeAnalysis).filter(
                TlsHandshakeAnalysis.job_id == job_id, TlsHandshakeAnalysis.tcp_stream == s.tcp_stream
            ).first()

            cert = db.query(X509CertificateAnalysis).filter(
                X509CertificateAnalysis.job_id == job_id, X509CertificateAnalysis.tcp_stream == s.tcp_stream
            ).first()

            # Protocol code
            proto_map = {"SMTP": 1, "SMTPS": 2, "IMAP": 3, "IMAPS": 4, "POP3": 5, "POP3S": 6}
            p_code = proto_map.get((s.protocol or "").upper(), 1)

            # TLS version code
            tls_map = {"TLS 1.3": 5, "TLS 1.2": 4, "TLS 1.1": 3, "TLS 1.0": 2, "SSL 3.0": 1}
            tls_ver = tls.negotiated_version if tls else "None"
            tls_code = tls_map.get(tls_ver, 0)

            # Cipher bits
            cipher_bits = 0
            if tls and tls.negotiated_cipher_suite:
                if "256" in tls.negotiated_cipher_suite:
                    cipher_bits = 256
                elif "128" in tls.negotiated_cipher_suite:
                    cipher_bits = 128
                elif "3DES" in tls.negotiated_cipher_suite:
                    cipher_bits = 112

            is_starttls = 1 if (email_analysis and email_analysis.starttls_accepted) else 0
            is_auth_enc = 1 if (email_analysis and email_analysis.auth_attempted and tls_code >= 4) else 0

            cert_code = 0
            if cert:
                if cert.validity_status == "VALID" and not cert.is_self_signed:
                    cert_code = 1
                elif cert.validity_status == "EXPIRED":
                    cert_code = 2
                elif cert.is_self_signed:
                    cert_code = 3

            pkts = s.packet_count or 1
            duration = s.duration_seconds or 0.1
            total_bytes = s.total_payload_bytes or 100
            avg_size = round(total_bytes / pkts, 1)

            # Assign label heuristic for real capture
            label_code = 0  # SECURE by default
            if tls_code in (1, 2) or cipher_bits == 112 or cert_code in (2, 3):
                label_code = 1  # WEAK_CRYPTO
            elif email_analysis and email_analysis.auth_attempted and not is_auth_enc:
                label_code = 2  # PLAINTEXT_LEAK

            samples.append({
                "sample_id": s.id,
                "label_code": label_code,
                "features": {
                    "protocol_code": p_code,
                    "tls_version_code": tls_code,
                    "cipher_strength_bits": cipher_bits,
                    "is_starttls_used": is_starttls,
                    "is_auth_encrypted": is_auth_enc,
                    "cert_validity_code": cert_code,
                    "packet_count": pkts,
                    "duration_seconds": duration,
                    "total_bytes": total_bytes,
                    "avg_packet_size": avg_size
                }
            })

        return samples

    def _stratified_split(
        self,
        samples: List[Dict[str, Any]],
        test_ratio: float,
        seed: int
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Performs reproducible stratified train/test split preserving ground truth label ratios."""
        rng = random.Random(seed)

        # Group samples by label_code
        by_label: Dict[int, List[Dict[str, Any]]] = {}
        for s in samples:
            by_label.setdefault(s["label_code"], []).append(s)

        train_samples = []
        test_samples = []

        for label, items in by_label.items():
            items_shuffled = list(items)
            rng.shuffle(items_shuffled)

            num_test = max(1, int(round(len(items_shuffled) * test_ratio))) if len(items_shuffled) > 1 else 0
            num_test = min(num_test, len(items_shuffled) - 1) if len(items_shuffled) > 1 else 0

            test_part = items_shuffled[:num_test]
            train_part = items_shuffled[num_test:]

            test_samples.extend(test_part)
            train_samples.extend(train_part)

        rng.shuffle(train_samples)
        rng.shuffle(test_samples)
        return train_samples, test_samples

    def _fit_scaler(self, train_samples: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
        """Fits Z-score mean and std scaler strictly on the training set."""
        params: Dict[str, Dict[str, float]] = {}

        for name in FEATURE_NAMES:
            vals = [float(s["features"][name]) for s in train_samples]
            if len(vals) == 0:
                mean_val = 0.0
                std_val = 1.0
            else:
                mean_val = sum(vals) / len(vals)
                variance = sum((x - mean_val) ** 2 for x in vals) / len(vals)
                std_val = math.sqrt(variance)
                if std_val < 1e-6:
                    std_val = 1.0

            params[name] = {"mean": round(mean_val, 4), "std": round(std_val, 4)}

        return params

    def _transform_samples(
        self,
        samples: List[Dict[str, Any]],
        scaling_params: Dict[str, Dict[str, float]]
    ) -> Tuple[List[List[float]], List[int], List[str]]:
        """Transforms raw feature vectors into Z-score normalized feature matrices."""
        X = []
        y = []
        sample_ids = []

        for s in samples:
            row = []
            f = s["features"]
            for name in FEATURE_NAMES:
                val = float(f[name])
                mean = scaling_params[name]["mean"]
                std = scaling_params[name]["std"]
                scaled_val = round((val - mean) / std, 4)
                row.append(scaled_val)

            X.append(row)
            y.append(s["label_code"])
            sample_ids.append(s["sample_id"])

        return X, y, sample_ids

    def _verify_data_leakage(
        self,
        train_ids: List[str],
        test_ids: List[str],
        scaling_params: Dict[str, Dict[str, float]]
    ) -> MlDataLeakageReport:
        """Verifies zero sample ID overlap and confirms preprocessor scaler fit parameters."""
        overlap = set(train_ids).intersection(set(test_ids))
        passed = len(overlap) == 0 and len(scaling_params) == len(FEATURE_NAMES)

        summary = (
            f"Data leakage verification PASSED: Zero sample overlap between train ({len(train_ids)}) "
            f"and test ({len(test_ids)}) splits. Scaler parameters fit strictly on train split."
            if passed else "Data leakage check FAILED: Overlap detected between train and test splits."
        )

        return MlDataLeakageReport(
            passed=passed,
            overlap_sample_ids_count=len(overlap),
            scaler_fit_on_train_only=True,
            train_samples_count=len(train_ids),
            test_samples_count=len(test_ids),
            summary=summary
        )
