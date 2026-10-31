"""
Initial Database Seeder for Network Intrusion Detection System.
Registers sample dataset and executes baseline flow predictions to populate SOC dashboard.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
from backend.app.database import init_db, SessionLocal
from backend.app.models.entities import DatasetRecord
from backend.ml.predict import ModelEngine
from backend.app.api.predictions import predict_batch
from backend.app.schemas.common import BatchPredictionRequest

def seed():
    print("[*] Initializing database tables...")
    init_db()
    db = SessionLocal()

    # Register sample dataset if not present
    sample_csv = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "sample_traffic.csv"
    )
    if not os.path.exists(sample_csv):
        print(f"[-] Sample dataset not found at {sample_csv}")
        return

    existing = db.query(DatasetRecord).filter(DatasetRecord.filename == "sample_traffic.csv").first()
    if not existing:
        df = pd.read_csv(sample_csv)
        rec = DatasetRecord(
            name="CIC-IDS2017 Sample Flow Traffic",
            filename="sample_traffic.csv",
            file_path=sample_csv,
            row_count=len(df),
            file_size_bytes=os.path.getsize(sample_csv),
            has_labels=True,
            description="Synthetic network traffic flows matching standard CIC-IDS2017 feature attributes"
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        print(f"[+] Registered dataset ID {rec.id}: {rec.name} ({len(df)} rows)")
        dataset_id = rec.id
    else:
        dataset_id = existing.id

    # Run initial batch predictions on 400 flows to populate dashboard stats and alerts
    print("[*] Loading ModelEngine and populating initial flow analysis telemetry...")
    engine = ModelEngine.get_instance()
    if not engine.is_loaded:
        print("[-] Active model not found. Run train.py first.")
        return

    req = BatchPredictionRequest(
        dataset_id=dataset_id,
        row_limit=500,
        create_alerts=True
    )
    res = predict_batch(req, db=db)
    print(f"[+] Initial flow analysis completed: {res.total_analyzed} flows analyzed ({res.normal_count} normal, {res.suspicious_count} suspicious, {res.alerts_generated} alerts created)")
    db.close()

if __name__ == "__main__":
    seed()

