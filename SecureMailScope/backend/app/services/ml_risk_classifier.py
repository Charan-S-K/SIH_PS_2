"""
ML Risk Classifier Service for Stage 15.
Trains and evaluates explainable Random Forest models on versioned feature sets,
computes precision, recall, F1, and confusion matrix metrics, persists serialized model artifacts,
and executes probabilistic inference without overriding deterministic security facts.
"""

import os
import time
import joblib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Optional
from sqlalchemy.orm import Session

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from app.models.ml_feature_pipeline import MlFeatureSet
from app.models.ml_model import MlTrainedModel, MlPredictionResult
from app.schemas.ml_model import (
    MlTrainModelRequest,
    MlEvaluationMetrics,
    MlPredictRequest,
    MlPredictionResponse
)
from app.services.ml_feature_pipeline import FEATURE_NAMES

logger = logging.getLogger(__name__)

ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "artifacts")

LABEL_NAMES_BY_CODE = {
    0: "SECURE",
    1: "WEAK_CRYPTO",
    2: "PLAINTEXT_LEAK",
    3: "DOWNGRADE_ATTACK",
    4: "ANOMALOUS"
}


class MlRiskClassifierService:
    """
    Service for training, persistence, evaluation, and inference of Random Forest ML Risk Classifiers.
    """

    def __init__(self):
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    def train_model(self, db: Session, req: MlTrainModelRequest) -> MlTrainedModel:
        """
        Trains a Random Forest classifier on specified feature set and records evaluation metrics.
        """
        feature_set = db.query(MlFeatureSet).filter(MlFeatureSet.id == req.feature_set_id).first()
        if not feature_set:
            raise ValueError(f"Feature set '{req.feature_set_id}' not found")

        train_data = feature_set.train_split_json or {}
        test_data = feature_set.test_split_json or {}

        X_train = np.array(train_data.get("X_train", []))
        y_train = np.array(train_data.get("y_train", []))
        X_test = np.array(test_data.get("X_test", []))
        y_test = np.array(test_data.get("y_test", []))

        if len(X_train) == 0 or len(X_test) == 0:
            raise ValueError("Feature set contains empty training or testing matrices")

        # Create model version name
        version_str = req.version or f"rf-v1.0.{int(time.time())}"

        # Initialize and fit Random Forest Classifier
        rf = RandomForestClassifier(
            n_estimators=req.n_estimators,
            max_depth=req.max_depth,
            random_state=req.random_state
        )
        rf.fit(X_train, y_train)

        # Evaluate model on test split
        y_pred = rf.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
        rec = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

        # Confusion matrix (5x5 for codes 0 to 4)
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1, 2, 3, 4]).tolist()
        class_rep = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        # Feature importances mapping
        importances = {}
        for name, imp in zip(FEATURE_NAMES, rf.feature_importances_):
            importances[name] = round(float(imp), 4)

        # Save model binary artifact to disk
        artifact_filename = f"model_{version_str}.joblib"
        artifact_path = os.path.join(ARTIFACTS_DIR, artifact_filename)
        joblib.dump(rf, artifact_path)

        # Deactivate previous active models
        db.query(MlTrainedModel).filter(MlTrainedModel.is_active == True).update({"is_active": False})

        hyperparams = {
            "n_estimators": req.n_estimators,
            "max_depth": req.max_depth,
            "random_state": req.random_state
        }

        model_db = MlTrainedModel(
            name=req.name or "Random Forest Email Security Classifier",
            version=version_str,
            algorithm="RandomForestClassifier",
            hyperparameters_json=hyperparams,
            feature_set_id=feature_set.id,
            accuracy=round(acc, 4),
            precision_macro=round(prec, 4),
            recall_macro=round(rec, 4),
            f1_macro=round(f1, 4),
            confusion_matrix_json=cm,
            class_report_json=class_rep,
            feature_importances_json=importances,
            is_active=True,
            model_artifact_path=artifact_path
        )
        db.add(model_db)
        db.commit()
        db.refresh(model_db)

        return model_db

    def predict(self, db: Session, req: MlPredictRequest) -> MlPredictionResponse:
        """
        Executes inference prediction on an input feature vector using the active/specified model version.
        Guarantees non-override of deterministic rule engine findings.
        """
        start_t = time.time()

        if req.model_version:
            model_db = db.query(MlTrainedModel).filter(MlTrainedModel.version == req.model_version).first()
        else:
            model_db = db.query(MlTrainedModel).filter(MlTrainedModel.is_active == True).order_by(MlTrainedModel.created_at.desc()).first()

        if not model_db:
            raise ValueError("No trained ML model found for prediction")

        if not model_db.model_artifact_path or not os.path.exists(model_db.model_artifact_path):
            raise ValueError(f"Model artifact file for version '{model_db.version}' not found")

        rf: RandomForestClassifier = joblib.load(model_db.model_artifact_path)

        # Fetch scaling parameters from associated feature set
        scaling_params = {}
        if model_db.feature_set_id:
            fset = db.query(MlFeatureSet).filter(MlFeatureSet.id == model_db.feature_set_id).first()
            if fset:
                scaling_params = fset.preprocessing_params_json or {}

        # Scale raw feature vector
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

        # Inference
        pred_class_code = int(rf.predict(X_in)[0])
        probabilities = rf.predict_proba(X_in)[0]

        prob_dict = {}
        classes = rf.classes_
        for c_code, prob in zip(classes, probabilities):
            label = LABEL_NAMES_BY_CODE.get(int(c_code), f"CLASS_{c_code}")
            prob_dict[label] = round(float(prob), 4)

        pred_label = LABEL_NAMES_BY_CODE.get(pred_class_code, "UNKNOWN")
        inf_time = round((time.time() - start_t) * 1000, 2)

        pred_db = MlPredictionResult(
            model_id=model_db.id,
            model_version=model_db.version,
            job_id=req.job_id,
            tcp_stream=req.tcp_stream,
            predicted_class_code=pred_class_code,
            predicted_label=pred_label,
            confidence_probabilities_json=prob_dict,
            is_deterministic_fact_overridden=False,  # GUARANTEED FALSE
            inference_time_ms=inf_time
        )
        db.add(pred_db)
        db.commit()
        db.refresh(pred_db)

        return MlPredictionResponse(
            id=pred_db.id,
            model_id=pred_db.model_id,
            model_version=pred_db.model_version,
            job_id=pred_db.job_id,
            tcp_stream=pred_db.tcp_stream,
            predicted_class_code=pred_db.predicted_class_code,
            predicted_label=pred_db.predicted_label,
            confidence_probabilities=pred_db.confidence_probabilities_json,
            is_deterministic_fact_overridden=False,
            inference_time_ms=pred_db.inference_time_ms,
            created_at=pred_db.created_at
        )
