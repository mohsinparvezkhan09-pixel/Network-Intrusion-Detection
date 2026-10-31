"""
Pydantic Schemas for Request/Response Validation.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


# Health Schema
class HealthResponse(BaseModel):
    status: str
    version: str
    active_model: Optional[str]
    model_loaded: bool
    database_connected: bool
    timestamp: str


# Dataset Schemas
class DatasetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    filename: str
    row_count: int
    file_size_bytes: int
    has_labels: bool
    description: Optional[str]
    created_at: datetime


class DatasetUploadResponse(BaseModel):
    dataset_id: int
    filename: str
    total_rows: int
    total_columns: int
    is_valid_schema: bool
    missing_features: List[str]
    has_target: bool
    preview: List[Dict[str, Any]]


# Prediction Schemas
class SinglePredictionRequest(BaseModel):
    features: Dict[str, Any]


class ContributingFeature(BaseModel):
    feature: str
    value: float
    baseline_median: float
    deviation_score: float


class PredictionOut(BaseModel):
    record_index: Optional[int] = 0
    predicted_class: str
    confidence: float
    class_probabilities: Dict[str, float]
    is_anomaly: bool
    anomaly_score: float
    severity: str
    model_version: str
    top_contributing_features: List[ContributingFeature]
    summary: Dict[str, Any]


class BatchPredictionRequest(BaseModel):
    dataset_id: Optional[int] = None
    records: Optional[List[Dict[str, Any]]] = None
    create_alerts: bool = True
    row_limit: Optional[int] = 5000


class BatchPredictionResponse(BaseModel):
    job_id: str
    total_analyzed: int
    normal_count: int
    suspicious_count: int
    attack_counts: Dict[str, int]
    alerts_generated: int
    results: List[PredictionOut]


class PredictionHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    destination_port: int
    flow_duration: int
    total_packets: int
    flow_bytes_s: float
    predicted_class: str
    confidence: float
    is_anomaly: bool
    severity: str
    model_version: str


# Alert Schemas
class AlertUpdatePatch(BaseModel):
    status: str = Field(..., description="New status: New, Under Review, Resolved, or False Positive")
    analyst_notes: Optional[str] = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    predicted_class: str
    severity: str
    status: str
    summary: Dict[str, Any]
    model_version: str
    analyst_notes: Optional[str] = None
    review_timestamp: Optional[datetime] = None
    contributing_features: List[Dict[str, Any]] = []


# Model Schemas
class ModelTrainRequest(BaseModel):
    model_type: str = "random_forest"  # "random_forest" or "xgboost"
    dataset_name: Optional[str] = "sample_traffic.csv"


class ModelStatusResponse(BaseModel):
    is_loaded: bool
    version: Optional[str]
    model_type: Optional[str]
    dataset_name: Optional[str]
    created_at: Optional[str]
    training_samples: Optional[int]
    test_samples: Optional[int]
    classes: Optional[List[str]]
    features: Optional[List[str]]
    anomaly_contamination: Optional[float]
    metrics: Optional[Dict[str, Any]]


# Dashboard Schemas
class DashboardStatsResponse(BaseModel):
    total_analyzed_records: int
    normal_records: int
    suspicious_records: int
    total_alerts: int
    unreviewed_alerts: int
    critical_alerts: int
    attack_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    model_version: str
    model_health: str


class TrendPoint(BaseModel):
    time_label: str
    benign_count: int
    attack_count: int
    alert_count: int


class DashboardTrendsResponse(BaseModel):
    trends: List[TrendPoint]
