"""
SQLAlchemy ORM Entities for Network Intrusion Detection System.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text
)
from backend.app.database import Base


class DatasetRecord(Base):
    __tablename__ = "datasets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    row_count = Column(Integer, default=0)
    file_size_bytes = Column(Integer, default=0)
    has_labels = Column(Boolean, default=False)
    description = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PredictionRecord(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    destination_port = Column(Integer, index=True)
    flow_duration = Column(Integer)
    total_packets = Column(Integer)
    flow_bytes_s = Column(Float)
    predicted_class = Column(String(64), index=True)
    confidence = Column(Float)
    is_anomaly = Column(Boolean, default=False, index=True)
    anomaly_score = Column(Float)
    severity = Column(String(32), index=True)
    model_version = Column(String(128))
    features_json = Column(Text, nullable=True)


class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    predicted_class = Column(String(64), index=True)
    severity = Column(String(32), index=True)  # Informational, Low, Medium, High, Critical
    status = Column(String(32), default="New", index=True)  # New, Under Review, Resolved, False Positive
    summary_json = Column(Text, nullable=False)
    model_version = Column(String(128))
    analyst_notes = Column(Text, nullable=True)
    review_timestamp = Column(DateTime, nullable=True)
    contributing_features_json = Column(Text, nullable=True)


class JobRecord(Base):
    __tablename__ = "jobs"

    id = Column(String(64), primary_key=True)
    job_type = Column(String(64), index=True)  # "training", "batch_prediction"
    status = Column(String(32), default="pending", index=True)  # pending, running, completed, failed
    progress = Column(Float, default=0.0)
    total_items = Column(Integer, default=0)
    processed_items = Column(Integer, default=0)
    result_summary_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime, nullable=True)

