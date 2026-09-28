"""
Synthetic Anomaly Injection & Evaluation Engine for Stage 17.
Injects controlled synthetic anomaly profiles into feature sets and evaluates
Isolation Forest detector performance (precision, recall, F1, FPR, confusion matrix).
"""

import os
import random
import logging
from enum import Enum
from typing import Dict, List, Tuple, Any, Optional
from sqlalchemy.orm import Session
import numpy as np

from app.models.ml_feature_pipeline import MlFeatureSet
from app.models.tls_anomaly import TlsAnomalyDetectorModel
from app.models.synthetic_anomaly import SyntheticAnomalyBatch, SyntheticAnomalyEvaluation
from app.schemas.synthetic_anomaly import (
    SyntheticAnomalyProfile,
    SyntheticAnomalyInjectRequest,
    SyntheticAnomalyEvaluateRequest,
    SyntheticAnomalyEvaluationResponse
)
from app.services.tls_anomaly_detector import TlsAnomalyDetectorService, DISCLAIMER_TEXT

logger = logging.getLogger(__name__)


class SyntheticAnomalyInjectorService:
    """
    Service for injecting controlled synthetic anomalies into baseline feature sets
    and evaluating anomaly detection performance against ground truth labels.
    """

    def inject_anomalies(
        self,
        db: Session,
        req: SyntheticAnomalyInjectRequest
    ) -> SyntheticAnomalyBatch:
        """
        Injects controlled synthetic anomaly profiles into a baseline feature matrix.
        """
        fset = db.query(MlFeatureSet).filter(MlFeatureSet.id == req.feature_set_id).first()
        if not fset:
            raise ValueError(f"Baseline feature set '{req.feature_set_id}' not found")

        train_data = fset.train_split_json or {}
        samples = train_data.get("X_train", [])
        if not samples:
            raise ValueError("Baseline feature set contains empty sample matrix")

        # Make deep copy of samples
        X_orig = [dict(s) for s in samples] if isinstance(samples[0], dict) else list(samples)
        total_count = len(X_orig)
        inject_count = max(1, int(total_count * req.injection_rate))

        rng = random.Random(req.seed)
        injected_indices = set(rng.sample(range(total_count), inject_count))

        X_injected = []
        y_ground_truth = []

        for i, sample in enumerate(X_orig):
            # If sample is dict convert/copy, or handle numeric list
            if isinstance(sample, dict):
                sample_dict = dict(sample)
            else:
                sample_dict = {"feature_" + str(idx): val for idx, val in enumerate(sample)}

            if i in injected_indices:
                # Mutate sample according to chosen profile
                mutated = self._mutate_sample(sample_dict, req.anomaly_profile, rng)
                X_injected.append(mutated)
                y_ground_truth.append(1)  # 1 = Synthetic Anomaly
            else:
                X_injected.append(sample_dict)
                y_ground_truth.append(0)  # 0 = Normal Baseline

        profile_str = req.anomaly_profile.value if isinstance(req.anomaly_profile, Enum) else str(req.anomaly_profile)
        batch_name = req.name or f"Synthetic Injection - {profile_str} ({int(req.injection_rate*100)}%)"

        batch_db = SyntheticAnomalyBatch(
            name=batch_name,
            baseline_feature_set_id=fset.id,
            anomaly_profile=profile_str,
            injection_rate=req.injection_rate,
            total_samples_count=total_count,
            injected_samples_count=inject_count,
            injected_data_json={
                "X_injected": X_injected,
                "y_ground_truth": y_ground_truth,
                "injected_indices": list(injected_indices)
            },
            metadata_json={"seed": req.seed}
        )
        db.add(batch_db)
        db.commit()
        db.refresh(batch_db)

        return batch_db

    def evaluate_injection(
        self,
        db: Session,
        req: SyntheticAnomalyEvaluateRequest
    ) -> SyntheticAnomalyEvaluationResponse:
        """
        Evaluates active or specified Isolation Forest anomaly detector against injected ground truth labels.
        """
        batch_db = db.query(SyntheticAnomalyBatch).filter(SyntheticAnomalyBatch.id == req.injection_batch_id).first()
        if not batch_db:
            raise ValueError(f"Synthetic anomaly batch '{req.injection_batch_id}' not found")

        detector_service = TlsAnomalyDetectorService()
        
        # Load detector model
        if req.detector_version:
            model_db = db.query(TlsAnomalyDetectorModel).filter(TlsAnomalyDetectorModel.version == req.detector_version).first()
        else:
            model_db = db.query(TlsAnomalyDetectorModel).filter(TlsAnomalyDetectorModel.is_active == True).first()

        if not model_db:
            raise ValueError("No active TLS anomaly detector model found for evaluation")

        data_payload = batch_db.injected_data_json or {}
        X_injected = data_payload.get("X_injected", [])
        y_ground_truth = data_payload.get("y_ground_truth", [])

        if not X_injected or not y_ground_truth:
            raise ValueError("Injection batch contains invalid or missing injected samples")

        tp = fp = tn = fn = 0

        for sample, gt in zip(X_injected, y_ground_truth):
            from app.schemas.tls_anomaly import TlsAnomalyPredictRequest
            pred_resp = detector_service.predict(
                db,
                TlsAnomalyPredictRequest(
                    model_version=model_db.version,
                    features_json=sample
                )
            )

            is_anom = pred_resp.is_anomalous

            if gt == 1 and is_anom:
                tp += 1
            elif gt == 0 and is_anom:
                fp += 1
            elif gt == 0 and not is_anom:
                tn += 1
            elif gt == 1 and not is_anom:
                fn += 1

        total = len(y_ground_truth)
        total_anom = sum(y_ground_truth)

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

        eval_db = SyntheticAnomalyEvaluation(
            injection_batch_id=batch_db.id,
            detector_version=model_db.version,
            total_samples=total,
            total_injected_anomalies=total_anom,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fpr,
            disclaimer_text=DISCLAIMER_TEXT,
            evaluation_metadata_json={
                "anomaly_profile": batch_db.anomaly_profile,
                "injection_rate": batch_db.injection_rate
            }
        )
        db.add(eval_db)
        db.commit()
        db.refresh(eval_db)

        return SyntheticAnomalyEvaluationResponse.model_validate(eval_db)

    def _mutate_sample(
        self,
        sample: Dict[str, Any],
        profile: SyntheticAnomalyProfile,
        rng: random.Random
    ) -> Dict[str, Any]:
        """Mutates feature dictionary according to specific anomaly profile."""
        mutated = dict(sample)
        prof_str = profile.value if isinstance(profile, Enum) else str(profile)

        if prof_str == SyntheticAnomalyProfile.EXPIRED_CERT_SURGE.value:
            mutated["cert_validity_days"] = -99.0
            mutated["cert_validity_code"] = 2.0
        elif prof_str == SyntheticAnomalyProfile.DEPRECATED_TLS_SPIKE.value:
            mutated["tls_version_code"] = 0x0300  # SSL 3.0 / TLS 1.0 legacy
            mutated["cipher_suite_code"] = 0x0005  # RC4-SHA
        elif prof_str == SyntheticAnomalyProfile.UNENCRYPTED_AUTH_BURST.value:
            mutated["is_starttls_used"] = 0.0
            mutated["is_auth_encrypted"] = 0.0
            mutated["cipher_suite_code"] = 0x0000
        elif prof_str == SyntheticAnomalyProfile.KEY_STRENGTH_DEGRADATION.value:
            mutated["key_exchange_bits"] = 512.0
            mutated["cipher_strength_bits"] = 512.0
        elif prof_str == SyntheticAnomalyProfile.MALFORMED_PACKET_STORM.value:
            mutated["packet_count"] = 8000.0
            mutated["duration_ms"] = 90000.0
            mutated["total_bytes"] = 8000000.0
        elif prof_str == SyntheticAnomalyProfile.COMBINED_MUTATION_SURGE.value:
            mutated["cert_validity_days"] = -30.0
            mutated["tls_version_code"] = 0x0300
            mutated["key_exchange_bits"] = 512.0
            mutated["packet_count"] = 5000.0
        else:
            # Fallback mutation
            mutated["packet_count"] = 9999.0

        return mutated
