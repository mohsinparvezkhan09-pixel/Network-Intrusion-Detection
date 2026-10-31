"""
Prediction API Endpoints (Single & Batch Flow Inference, History).
"""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
import pandas as pd

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.entities import PredictionRecord, AlertRecord, DatasetRecord, JobRecord
from backend.app.schemas.common import (
    SinglePredictionRequest,
    PredictionOut,
    BatchPredictionRequest,
    BatchPredictionResponse,
    PredictionHistoryItem
)
from backend.ml.predict import ModelEngine

router = APIRouter(prefix="/predictions", tags=["Predictions"])


@router.post("/single", response_model=PredictionOut)
def predict_single(
    request: SinglePredictionRequest,
    db: Session = Depends(get_db)
):
    """
    Evaluates a single network flow record against the active trained model.
    """
    engine = ModelEngine.get_instance()
    if not engine.is_loaded:
        raise HTTPException(
            status_code=503,
            detail="No ML model is loaded. Please train or initialize a model first."
        )

    try:
        result = engine.predict_single(request.features)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Inference error: {str(e)}")

    # Record in database
    flow_rec = PredictionRecord(
        destination_port=result["summary"]["destination_port"],
        flow_duration=result["summary"]["flow_duration"],
        total_packets=result["summary"]["total_packets"],
        flow_bytes_s=result["summary"]["flow_bytes_per_sec"],
        predicted_class=result["predicted_class"],
        confidence=result["confidence"],
        is_anomaly=result["is_anomaly"],
        anomaly_score=result["anomaly_score"],
        severity=result["severity"],
        model_version=result["model_version"],
        features_json=json.dumps(request.features)
    )
    db.add(flow_rec)

    # If malicious or anomaly, generate an alert
    if result["predicted_class"].upper() != "BENIGN" or result["is_anomaly"]:
        alert = AlertRecord(
            predicted_class=result["predicted_class"],
            severity=result["severity"],
            status="New",
            summary_json=json.dumps(result["summary"]),
            model_version=result["model_version"],
            contributing_features_json=json.dumps(result["top_contributing_features"])
        )
        db.add(alert)

    db.commit()
    return PredictionOut(**result)


@router.post("/batch", response_model=BatchPredictionResponse)
def predict_batch(
    request: BatchPredictionRequest,
    db: Session = Depends(get_db)
):
    """
    Analyzes multiple network flow records either passed directly or from an uploaded dataset.
    """
    engine = ModelEngine.get_instance()
    if not engine.is_loaded:
        raise HTTPException(
            status_code=503,
            detail="No ML model is loaded. Please train or initialize a model first."
        )

    # 1. Obtain DataFrame
    if request.dataset_id is not None:
        dataset = db.query(DatasetRecord).filter(DatasetRecord.id == request.dataset_id).first()
        if not dataset:
            raise HTTPException(status_code=404, detail="Dataset not found.")
        try:
            df = pd.read_csv(dataset.file_path, nrows=request.row_limit or 5000)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read dataset file: {str(e)}")
    elif request.records is not None and len(request.records) > 0:
        df = pd.DataFrame(request.records[:request.row_limit or 5000])
    else:
        raise HTTPException(status_code=400, detail="Must provide either dataset_id or records.")

    if len(df) == 0:
        raise HTTPException(status_code=400, detail="Provided dataset or records list is empty.")

    job_id = f"job_{uuid.uuid4().hex[:10]}"
    job = JobRecord(
        id=job_id,
        job_type="batch_prediction",
        status="running",
        total_items=len(df),
        processed_items=0
    )
    db.add(job)
    db.commit()

    try:
        predictions = engine.predict_dataframe(df)
    except Exception as e:
        job.status = "failed"
        job.result_summary_json = json.dumps({"error": str(e)})
        db.commit()
        raise HTTPException(status_code=400, detail=f"Batch inference error: {str(e)}")

    # Tally metrics and persist records
    normal_count = 0
    suspicious_count = 0
    attack_counts: Dict[str, int] = {}
    alerts_generated = 0

    prediction_records = []
    alert_records = []

    for pred in predictions:
        p_class = pred["predicted_class"]
        attack_counts[p_class] = attack_counts.get(p_class, 0) + 1
        
        is_attack = p_class.upper() != "BENIGN"
        if not is_attack and not pred["is_anomaly"]:
            normal_count += 1
        else:
            suspicious_count += 1

        prediction_records.append(PredictionRecord(
            destination_port=pred["summary"]["destination_port"],
            flow_duration=pred["summary"]["flow_duration"],
            total_packets=pred["summary"]["total_packets"],
            flow_bytes_s=pred["summary"]["flow_bytes_per_sec"],
            predicted_class=pred["predicted_class"],
            confidence=pred["confidence"],
            is_anomaly=pred["is_anomaly"],
            anomaly_score=pred["anomaly_score"],
            severity=pred["severity"],
            model_version=pred["model_version"],
            features_json=None  # avoid bloating DB in large batches
        ))

        if request.create_alerts and (is_attack or pred["is_anomaly"]):
            alerts_generated += 1
            alert_records.append(AlertRecord(
                predicted_class=pred["predicted_class"],
                severity=pred["severity"],
                status="New",
                summary_json=json.dumps(pred["summary"]),
                model_version=pred["model_version"],
                contributing_features_json=json.dumps(pred["top_contributing_features"])
            ))

    db.bulk_save_objects(prediction_records)
    if alert_records:
        db.bulk_save_objects(alert_records)

    job.status = "completed"
    job.progress = 1.0
    job.processed_items = len(df)
    job.finished_at = datetime.now(timezone.utc)
    job.result_summary_json = json.dumps({
        "total_analyzed": len(df),
        "normal": normal_count,
        "suspicious": suspicious_count,
        "alerts_generated": alerts_generated
    })
    db.commit()

    # Limit returned results to first 500 for responsive frontend rendering
    return BatchPredictionResponse(
        job_id=job_id,
        total_analyzed=len(df),
        normal_count=normal_count,
        suspicious_count=suspicious_count,
        attack_counts=attack_counts,
        alerts_generated=alerts_generated,
        results=[PredictionOut(**p) for p in predictions[:500]]
    )


@router.get("/history", response_model=List[PredictionHistoryItem])
def get_prediction_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    predicted_class: Optional[str] = None,
    severity: Optional[str] = None,
    is_anomaly: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """
    Returns paginated prediction history with filtering options.
    """
    query = db.query(PredictionRecord)
    if predicted_class:
        query = query.filter(PredictionRecord.predicted_class == predicted_class)
    if severity:
        query = query.filter(PredictionRecord.severity == severity)
    if is_anomaly is not None:
        query = query.filter(PredictionRecord.is_anomaly == is_anomaly)

    records = query.order_by(desc(PredictionRecord.timestamp)).offset(skip).limit(limit).all()
    return records

