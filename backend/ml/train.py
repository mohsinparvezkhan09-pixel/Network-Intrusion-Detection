"""
Model Training Service for Supervised Classification & Unsupervised Anomaly Detection.
Trains Random Forest or XGBoost models alongside an Isolation Forest anomaly detector.
Persists complete versioned pipelines and evaluation metadata.
"""

import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.pipeline import Pipeline

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

from backend.ml.preprocessing import (
    CANONICAL_FEATURES,
    TARGET_COLUMN,
    normalize_dataframe_columns,
    validate_features,
    build_preprocessor_pipeline
)
from backend.ml.evaluate import evaluate_classifier

logger = logging.getLogger(__name__)


def train_models(
    df: pd.DataFrame,
    model_type: str = "random_forest",
    dataset_name: str = "sample_traffic.csv",
    artifacts_dir: Optional[str] = None,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Trains both supervised classifier and unsupervised Isolation Forest on dataset.
    Validates features, executes stratified split, calculates genuine metrics,
    and saves model bundle atomically.
    """
    if artifacts_dir is None:
        artifacts_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "artifacts",
            "models"
        )
    os.makedirs(artifacts_dir, exist_ok=True)

    # 1. Clean & Validate
    cleaned_df, _ = normalize_dataframe_columns(df)
    validation = validate_features(cleaned_df, require_target=True)
    if not validation["is_valid"]:
        missing = ", ".join(validation["missing_features"])
        raise ValueError(f"Dataset is missing required canonical features: {missing}")

    # 2. Extract Features & Target
    X = cleaned_df[CANONICAL_FEATURES].copy()
    y_raw = cleaned_df[TARGET_COLUMN].astype(str).str.strip()

    # Determine unique classes dynamically from actual dataset
    classes = sorted(list(y_raw.unique()))
    class_to_idx = {cls_name: i for i, cls_name in enumerate(classes)}
    idx_to_class = {i: cls_name for i, cls_name in enumerate(classes)}
    y = np.array([class_to_idx[val] for val in y_raw])

    # 3. Stratified Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.25,
        random_state=random_state,
        stratify=y if len(classes) > 1 else None
    )

    # 4. Supervised Pipeline
    preprocessor = build_preprocessor_pipeline(CANONICAL_FEATURES)
    
    if model_type.lower() == "xgboost" and XGBOOST_AVAILABLE:
        classifier = xgb.XGBClassifier(
            n_estimators=120,
            max_depth=6,
            learning_rate=0.1,
            random_state=random_state,
            eval_metric="mlogloss",
            tree_method="hist"
        )
        selected_model_name = "XGBoost Classifier"
    else:
        classifier = RandomForestClassifier(
            n_estimators=120,
            max_depth=16,
            min_samples_split=4,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1
        )
        selected_model_name = "Random Forest Classifier"

    supervised_pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", classifier)
    ])

    logger.info(f"Training {selected_model_name} on {len(X_train)} samples...")
    supervised_pipeline.fit(X_train, y_train)

    # 5. Evaluate Supervised Pipeline on Unseen Test Split
    y_pred = supervised_pipeline.predict(X_test)
    y_proba = None
    if hasattr(supervised_pipeline, "predict_proba"):
        y_proba = supervised_pipeline.predict_proba(X_test)

    eval_results = evaluate_classifier(
        y_true=y_test,
        y_pred=y_pred,
        y_proba=y_proba,
        class_names=classes
    )

    # 6. Unsupervised Anomaly Detector (Isolation Forest)
    # Fit Isolation Forest on preprocessed features
    # Contamination set to 0.05 representing typical anomalous network behavior assumption
    contamination = 0.05
    iso_forest = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    
    anomaly_pipeline = Pipeline([
        ("preprocessor", build_preprocessor_pipeline(CANONICAL_FEATURES)),
        ("detector", iso_forest)
    ])
    logger.info("Training Isolation Forest Anomaly Detector...")
    anomaly_pipeline.fit(X_train)

    # 7. Model Versioning & Bundle Creation
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    version_id = f"nids_model_{timestamp_str}"
    
    # Calculate feature baselines (median & std for anomaly explaining)
    feature_medians = X[CANONICAL_FEATURES].median().to_dict()
    feature_stds = X[CANONICAL_FEATURES].std().replace(0, 1.0).to_dict()

    # Extract feature importances if available
    feature_importances: Dict[str, float] = {}
    if hasattr(classifier, "feature_importances_"):
        for fname, imp in zip(CANONICAL_FEATURES, classifier.feature_importances_):
            feature_importances[fname] = round(float(imp), 4)

    bundle = {
        "version": version_id,
        "model_type": selected_model_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_name": dataset_name,
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "classes": classes,
        "class_to_idx": class_to_idx,
        "idx_to_class": idx_to_class,
        "features": CANONICAL_FEATURES,
        "supervised_pipeline": supervised_pipeline,
        "anomaly_pipeline": anomaly_pipeline,
        "anomaly_contamination": contamination,
        "feature_medians": feature_medians,
        "feature_stds": feature_stds,
        "feature_importances": feature_importances,
        "metrics": eval_results,
        "environment": {
            "python_version": sys.version.split()[0],
            "scikit_learn_version": joblib.__version__
        }
    }

    # Save to timestamped file first, then update active symlink/file atomically
    bundle_path = os.path.join(artifacts_dir, f"{version_id}.joblib")
    joblib.dump(bundle, bundle_path, compress=3)

    # Active model link
    active_path = os.path.join(artifacts_dir, "active_model.joblib")
    joblib.dump(bundle, active_path, compress=3)

    # Save metadata summary as JSON for quick inspection without unpickling
    meta_path = os.path.join(artifacts_dir, f"{version_id}_meta.json")
    active_meta_path = os.path.join(artifacts_dir, "active_model_meta.json")
    
    metadata_clean = {
        "version": version_id,
        "model_type": selected_model_name,
        "created_at": bundle["created_at"],
        "dataset_name": dataset_name,
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "classes": classes,
        "features": CANONICAL_FEATURES,
        "anomaly_contamination": contamination,
        "feature_importances": feature_importances,
        "metrics": eval_results
    }
    
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata_clean, f, indent=2)
    with open(active_meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata_clean, f, indent=2)

    logger.info(f"Model {version_id} successfully trained and saved. Accuracy: {eval_results['accuracy']}")
    return metadata_clean


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "data",
        "sample_traffic.csv"
    )
    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found.")
        sys.exit(1)

    df_sample = pd.read_csv(data_path)
    res = train_models(df_sample, model_type="random_forest", dataset_name="sample_traffic.csv")
    print(f"Training Complete! Active Model Version: {res['version']}")
    print(f"Test Accuracy: {res['metrics']['accuracy'] * 100:.2f}%")
    print(f"Classes: {res['classes']}")
