"""
Model Management, Metrics, and Training API Endpoints.
"""

import os
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
import pandas as pd

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.schemas.common import ModelStatusResponse, ModelTrainRequest
from backend.ml.predict import ModelEngine
from backend.ml.train import train_models

router = APIRouter(prefix="/models", tags=["Models"])


@router.get("/status", response_model=ModelStatusResponse)
def get_model_status():
    """
    Returns metadata and status for the currently active ML model pipeline.
    """
    engine = ModelEngine.get_instance()
    if not engine.is_loaded or not engine.model_metadata:
        return ModelStatusResponse(
            is_loaded=False,
            version=None,
            model_type=None,
            dataset_name=None,
            created_at=None,
            training_samples=None,
            test_samples=None,
            classes=None,
            features=None,
            anomaly_contamination=None,
            metrics=None
        )

    meta = engine.model_metadata
    return ModelStatusResponse(
        is_loaded=True,
        version=meta.get("version"),
        model_type=meta.get("model_type"),
        dataset_name=meta.get("dataset_name"),
        created_at=meta.get("created_at"),
        training_samples=meta.get("training_samples"),
        test_samples=meta.get("test_samples"),
        classes=meta.get("classes"),
        features=meta.get("features"),
        anomaly_contamination=0.05,
        metrics=meta.get("metrics")
    )


@router.get("/metrics")
def get_model_metrics():
    """
    Returns actual, un-fabricated evaluation metrics of the active model,
    including confusion matrix, ROC-AUC, FPR, FNR, and per-class reports.
    """
    engine = ModelEngine.get_instance()
    if not engine.is_loaded or not engine.model_metadata:
        raise HTTPException(status_code=404, detail="No active model loaded.")

    return engine.model_metadata.get("metrics", {})


@router.post("/train")
def train_model_endpoint(
    request: ModelTrainRequest
):
    """
    Trains a new supervised model + Isolation Forest anomaly detector.
    Does not replace active model until validation passes.
    """
    dataset_file = request.dataset_name or "sample_traffic.csv"
    data_path = os.path.join(settings.DATA_DIR, dataset_file)

    if not os.path.exists(data_path):
        raise HTTPException(
            status_code=404,
            detail=f"Training dataset '{dataset_file}' not found in data directory."
        )

    try:
        df = pd.read_csv(data_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read training dataset: {str(e)}")

    try:
        new_meta = train_models(
            df=df,
            model_type=request.model_type,
            dataset_name=dataset_file,
            artifacts_dir=settings.MODELS_DIR
        )
        # Reload engine with new active model
        engine = ModelEngine.get_instance()
        engine.load_active_model(force_reload=True)

        return {
            "message": "Model training completed successfully.",
            "version": new_meta["version"],
            "model_type": new_meta["model_type"],
            "accuracy": new_meta["metrics"]["accuracy"],
            "classes": new_meta["classes"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

