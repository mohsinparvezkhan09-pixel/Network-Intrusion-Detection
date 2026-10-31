"""
Inference and Prediction Engine for Network Intrusion Detection System.
Provides single-record and batch flow inference, anomaly detection, confidence scores,
and contributing feature analysis.
"""

import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import logging
from typing import Dict, List, Any, Optional, Union
import joblib
import numpy as np
import pandas as pd

from backend.ml.preprocessing import (
    CANONICAL_FEATURES,
    normalize_dataframe_columns,
    validate_features
)

logger = logging.getLogger(__name__)

# Severity mapping based on attack nature and threat impact (rule-based SOC standard)
SEVERITY_MAPPING: Dict[str, str] = {
    "BENIGN": "Informational",
    "DOS": "High",
    "DDOS": "Critical",
    "PORTSCAN": "Medium",
    "BRUTEFORCE": "High",
    "BOTNET": "Critical"
}


class ModelEngine:
    """
    Singleton / Cached model loader for real-time and batch predictions.
    """
    _instance: Optional["ModelEngine"] = None
    _bundle: Optional[Dict[str, Any]] = None
    _model_path: Optional[str] = None

    def __init__(self, artifacts_dir: Optional[str] = None):
        if artifacts_dir is None:
            artifacts_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "artifacts",
                "models"
            )
        self.artifacts_dir = artifacts_dir
        self.active_model_path = os.path.join(artifacts_dir, "active_model.joblib")
        self.load_active_model()

    @classmethod
    def get_instance(cls, artifacts_dir: Optional[str] = None) -> "ModelEngine":
        if cls._instance is None:
            cls._instance = ModelEngine(artifacts_dir)
        return cls._instance

    def load_active_model(self, force_reload: bool = False) -> bool:
        if not os.path.exists(self.active_model_path):
            logger.warning(f"No active model found at {self.active_model_path}")
            self._bundle = None
            return False

        try:
            if self._bundle is None or force_reload:
                logger.info(f"Loading active model from {self.active_model_path}")
                self._bundle = joblib.load(self.active_model_path)
            return True
        except Exception as e:
            logger.error(f"Failed to load active model: {e}")
            self._bundle = None
            return False

    @property
    def is_loaded(self) -> bool:
        return self._bundle is not None

    @property
    def model_metadata(self) -> Optional[Dict[str, Any]]:
        if not self.is_loaded:
            return None
        return {
            "version": self._bundle.get("version"),
            "model_type": self._bundle.get("model_type"),
            "created_at": self._bundle.get("created_at"),
            "dataset_name": self._bundle.get("dataset_name"),
            "training_samples": self._bundle.get("training_samples"),
            "test_samples": self._bundle.get("test_samples"),
            "classes": self._bundle.get("classes"),
            "features": self._bundle.get("features"),
            "metrics": self._bundle.get("metrics"),
            "feature_importances": self._bundle.get("feature_importances", {})
        }

    def predict_dataframe(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Runs batch prediction across a DataFrame of network flows.
        """
        if not self.is_loaded:
            raise RuntimeError("No active model is loaded. Please train or load a model first.")

        cleaned_df, _ = normalize_dataframe_columns(df)
        validation = validate_features(cleaned_df, require_target=False)
        if not validation["is_valid"]:
            missing = ", ".join(validation["missing_features"])
            raise ValueError(f"Input data is missing required features: {missing}")

        X = cleaned_df[CANONICAL_FEATURES].copy()
        
        # Supervised prediction
        supervised_pipe = self._bundle["supervised_pipeline"]
        y_preds = supervised_pipe.predict(X)
        
        y_probas = None
        if hasattr(supervised_pipe, "predict_proba"):
            y_probas = supervised_pipe.predict_proba(X)

        # Unsupervised Anomaly Detection (Isolation Forest)
        anomaly_pipe = self._bundle.get("anomaly_pipeline")
        iso_preds = None
        iso_scores = None
        if anomaly_pipe is not None:
            # -1 for anomaly, 1 for inlier
            iso_preds = anomaly_pipe.predict(X)
            # decision_function: lower score means more anomalous
            iso_scores = anomaly_pipe.decision_function(X)

        idx_to_class = self._bundle["idx_to_class"]
        classes = self._bundle["classes"]
        medians = self._bundle.get("feature_medians", {})
        stds = self._bundle.get("feature_stds", {})
        importances = self._bundle.get("feature_importances", {})

        results = []
        for idx in range(len(X)):
            pred_idx = int(y_preds[idx])
            pred_class = idx_to_class.get(pred_idx, str(pred_idx))
            
            # Probability distribution
            class_probs = {}
            confidence = 1.0
            if y_probas is not None:
                probs_row = y_probas[idx]
                for c_idx, c_name in enumerate(classes):
                    class_probs[c_name] = round(float(probs_row[c_idx]), 4)
                confidence = round(float(probs_row[pred_idx]), 4)

            # Anomaly details
            # Isolation forest: score < 0 is flagged as anomaly
            is_anomaly = False
            raw_anomaly_score = 0.0
            if iso_preds is not None and iso_scores is not None:
                is_anomaly = bool(iso_preds[idx] == -1)
                raw_anomaly_score = round(float(iso_scores[idx]), 4)

            # Determine severity
            severity = SEVERITY_MAPPING.get(pred_class.upper(), "Medium")
            # If benign but flagged as unsupervised anomaly, elevate to Low/Medium review
            if pred_class.upper() == "BENIGN" and is_anomaly:
                severity = "Low"

            # Compute top contributing features (based on z-score deviation and importance)
            row_dict = X.iloc[idx].to_dict()
            contributions = []
            for feat_name, val in row_dict.items():
                try:
                    num_val = float(val)
                    m = medians.get(feat_name, 0.0)
                    s = stds.get(feat_name, 1.0)
                    z_score = abs(num_val - m) / (s if s != 0 else 1.0)
                    weight = importances.get(feat_name, 0.01)
                    score = z_score * (weight + 0.05)
                    contributions.append({
                        "feature": feat_name,
                        "value": round(num_val, 2),
                        "baseline_median": round(float(m), 2),
                        "deviation_score": round(float(score), 3)
                    })
                except Exception:
                    continue

            contributions.sort(key=lambda x: x["deviation_score"], reverse=True)
            top_features = contributions[:4]

            results.append({
                "record_index": idx,
                "predicted_class": pred_class,
                "confidence": confidence,
                "class_probabilities": class_probs,
                "is_anomaly": is_anomaly,
                "anomaly_score": raw_anomaly_score,
                "severity": severity,
                "model_version": self._bundle.get("version", "unknown"),
                "top_contributing_features": top_features,
                "summary": {
                    "destination_port": int(row_dict.get("Destination Port", 0)),
                    "flow_duration": int(row_dict.get("Flow Duration", 0)),
                    "total_packets": int(row_dict.get("Total Fwd Packets", 0) + row_dict.get("Total Backward Packets", 0)),
                    "flow_bytes_per_sec": float(row_dict.get("Flow Bytes/s", 0.0))
                }
            })

        return results

    def predict_single(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predicts classification and anomaly status for a single network flow record.
        """
        df = pd.DataFrame([record])
        results = self.predict_dataframe(df)
        return results[0]
