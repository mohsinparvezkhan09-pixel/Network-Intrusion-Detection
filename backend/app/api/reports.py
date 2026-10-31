"""
Reporting and Export API Endpoints.
"""

import io
import csv
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.entities import AlertRecord, PredictionRecord

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/export")
def export_report(
    report_type: str = Query("alerts", pattern="^(alerts|predictions)$"),
    format: str = Query("csv", pattern="^(csv|json)$"),
    db: Session = Depends(get_db)
):
    """
    Exports alerts or prediction history as downloadable CSV or JSON.
    """
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    if report_type == "alerts":
        alerts = db.query(AlertRecord).order_by(desc(AlertRecord.timestamp)).limit(5000).all()
        
        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Alert ID", "Timestamp", "Attack Class", "Severity", "Status", "Model Version", "Analyst Notes"])
            for a in alerts:
                writer.writerow([
                    a.id,
                    a.timestamp.isoformat() if a.timestamp else "",
                    a.predicted_class,
                    a.severity,
                    a.status,
                    a.model_version or "",
                    a.analyst_notes or ""
                ])
            csv_data = output.getvalue()
            return Response(
                content=csv_data,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=nids_alerts_report_{timestamp_str}.csv"}
            )
        else:
            data = [{
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "predicted_class": a.predicted_class,
                "severity": a.severity,
                "status": a.status,
                "model_version": a.model_version,
                "analyst_notes": a.analyst_notes
            } for a in alerts]
            return {"report": "alerts", "exported_at": timestamp_str, "records": data}

    else:
        predictions = db.query(PredictionRecord).order_by(desc(PredictionRecord.timestamp)).limit(5000).all()
        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Timestamp", "Dest Port", "Duration", "Packets", "Bytes/s", "Class", "Confidence", "Anomaly", "Severity"])
            for p in predictions:
                writer.writerow([
                    p.id,
                    p.timestamp.isoformat() if p.timestamp else "",
                    p.destination_port,
                    p.flow_duration,
                    p.total_packets,
                    p.flow_bytes_s,
                    p.predicted_class,
                    p.confidence,
                    p.is_anomaly,
                    p.severity
                ])
            csv_data = output.getvalue()
            return Response(
                content=csv_data,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=nids_predictions_report_{timestamp_str}.csv"}
            )
        else:
            data = [{
                "id": p.id,
                "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                "destination_port": p.destination_port,
                "flow_duration": p.flow_duration,
                "total_packets": p.total_packets,
                "flow_bytes_s": p.flow_bytes_s,
                "predicted_class": p.predicted_class,
                "confidence": p.confidence,
                "is_anomaly": p.is_anomaly,
                "severity": p.severity
            } for p in predictions]
            return {"report": "predictions", "exported_at": timestamp_str, "records": data}
