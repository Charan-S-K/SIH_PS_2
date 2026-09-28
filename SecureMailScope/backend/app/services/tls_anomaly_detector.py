"""
TLS Anomaly Detector Service for Stage 16.
Implements lightweight unsupervised Isolation Forest model training, score calibration,
raw anomaly score evaluation, and explicit non-malice disclaimers.
"""

import os
import time
import joblib
import logging
from typing import Dict, List, Tuple, Any, Optional
from sqlalchemy.orm import Session

import numpy as np
from sklearn.ensemble import IsolationForest

from app.models.ml_feature_pipeline import MlFeatureSet
from app.models.tls_anomaly import TlsAnomalyDetectorModel, TlsAnomalyResult
from app.schemas.tls_anomaly import (
    TlsAnomalyTrainRequest,
    TlsAnomalyPredictRequest,
    TlsAnomalyResponse
)
from app.services.ml_feature_pipeline import FEATURE_NAMES

logger = logging.getLogger(__name__)

ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "artifacts")

DISCLAIMER_TEXT = "Anomalous behavior indicator only; does not constitute definitive proof of a malicious cyber attack."


class TlsAnomalyDetectorService:
    """
    Service for unsupervised Isolation Forest anomaly detection, score calibration, and inference.
    """

    def __init__(self):
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    def train_detector(self, db: Session, req: TlsAnomalyTrainRequest) -> TlsAnomalyDetectorModel:
        """
        Fits Isolation Forest model on baseline normal feature set and calibrates decision threshold.
        """
        feature_set = db.query(MlFeatureSet).filter(MlFeatureSet.id == req.feature_set_id).first()
        if not feature_set:
            raise ValueError(f"Feature set '{req.feature_set_id}' not found")

        train_data = feature_set.train_split_json or {}
        X_train = np.array(train_data.get("X_train", []))

        if len(X_train) == 0:
            raise ValueError("Feature set contains empty training matrix")

        version_str = req.version or f"iforest-v1.0.{int(time.time())}"

        # Initialize and fit Isolation Forest
        iforest = IsolationForest(
            n_estimators=req.n_estimators,
            contamination=req.contamination,
            random_state=req.random_state
        )
        iforest.fit(X_train)

        # Calculate decision scores for threshold calibration
        scores = iforest.score_samples(X_train)
        calibrated_threshold = float(np.percentile(scores, req.contamination * 100))

        # Save model binary artifact to disk
        artifact_filename = f"model_iforest_{version_str}.joblib"
        artifact_path = os.path.join(ARTIFACTS_DIR, artifact_filename)
        joblib.dump(iforest, artifact_path)

        # Deactivate previous active models
        db.query(TlsAnomalyDetectorModel).filter(TlsAnomalyDetectorModel.is_active == True).update({"is_active": False})

        model_db = TlsAnomalyDetectorModel(
            name=req.name or "TLS Isolation Forest Anomaly Detector",
            version=version_str,
            algorithm="IsolationForest",
            contamination=req.contamination,
            calibrated_threshold=round(calibrated_threshold, 4),
            n_estimators=req.n_estimators,
            random_state=req.random_state,
            feature_set_id=feature_set.id,
            baseline_samples_count=len(X_train),
            is_active=True,
            model_artifact_path=artifact_path
        )
        db.add(model_db)
        db.commit()
        db.refresh(model_db)

        return model_db

    def predict(self, db: Session, req: TlsAnomalyPredictRequest) -> TlsAnomalyResponse:
        """
        Evaluates raw anomaly score for input features against calibrated decision threshold.
        Appends explicit non-malice disclaimer label.
        """
        start_t = time.time()

        if req.model_version:
            model_db = db.query(TlsAnomalyDetectorModel).filter(TlsAnomalyDetectorModel.version == req.model_version).first()
        else:
            model_db = db.query(TlsAnomalyDetectorModel).filter(TlsAnomalyDetectorModel.is_active == True).order_by(TlsAnomalyDetectorModel.created_at.desc()).first()

        if not model_db:
            raise ValueError("No active TLS anomaly detector model found")

        if not model_db.model_artifact_path or not os.path.exists(model_db.model_artifact_path):
            raise ValueError(f"Model artifact file for version '{model_db.version}' not found")

        iforest: IsolationForest = joblib.load(model_db.model_artifact_path)

        # Fetch scaling parameters
        scaling_params = {}
        if model_db.feature_set_id:
            fset = db.query(MlFeatureSet).filter(MlFeatureSet.id == model_db.feature_set_id).first()
            if fset:
                scaling_params = fset.preprocessing_params_json or {}

        # Scale input feature vector
        raw_features = req.features_json
        scaled_row = []
        for name in FEATURE_NAMES:
            raw_val = float(raw_features.get(name, 0.0))
            if name in scaling_params:
                mean = scaling_params[name]["mean"]
                std = scaling_params[name]["std"]
                val = (raw_val - mean) / std
            else:
                val = raw_val
            scaled_row.append(val)

        X_in = np.array([scaled_row])

        # Compute raw anomaly score
        raw_score = float(iforest.score_samples(X_in)[0])
        is_anomalous = bool(raw_score < model_db.calibrated_threshold)
        label = "ANOMALOUS_BEHAVIOR" if is_anomalous else "NORMAL_BEHAVIOR"

        inf_time = round((time.time() - start_t) * 1000, 2)

        res_db = TlsAnomalyResult(
            model_id=model_db.id,
            model_version=model_db.version,
            job_id=req.job_id,
            tcp_stream=req.tcp_stream,
            raw_anomaly_score=round(raw_score, 4),
            calibrated_threshold=model_db.calibrated_threshold,
            is_anomalous=is_anomalous,
            anomaly_label=label,
            disclaimer_text=DISCLAIMER_TEXT,
            features_json=raw_features,
            execution_time_ms=inf_time
        )
        db.add(res_db)
        db.commit()
        db.refresh(res_db)

        return TlsAnomalyResponse(
            id=res_db.id,
            model_id=res_db.model_id,
            model_version=res_db.model_version,
            job_id=res_db.job_id,
            tcp_stream=res_db.tcp_stream,
            raw_anomaly_score=res_db.raw_anomaly_score,
            calibrated_threshold=res_db.calibrated_threshold,
            is_anomalous=res_db.is_anomalous,
            anomaly_label=res_db.anomaly_label,
            disclaimer_text=res_db.disclaimer_text,
            features_json=res_db.features_json,
            execution_time_ms=res_db.execution_time_ms,
            created_at=res_db.created_at
        )
