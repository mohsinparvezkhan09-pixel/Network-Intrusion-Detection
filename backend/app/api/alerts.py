"""
Alert Management API Endpoints (Triage, Analyst Review, Status Updates).
"""

import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Path
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.entities import AlertRecord
from backend.app.schemas.common import AlertOut, AlertUpdatePatch

router = APIRouter(prefix="/alerts", tags=["Alerts"])

VALID_STATUSES = {"New", "Under Review", "Resolved", "False Positive"}


def format_alert_response(alert: AlertRecord) -> AlertOut:
    summary = {}
    try:
        summary = json.loads(alert.summary_json) if alert.summary_json else {}
    except Exception:
        summary = {"raw": alert.summary_json}

    contributing = []
    try:
        contributing = json.loads(alert.contributing_features_json) if alert.contributing_features_json else []
    except Exception:
        contributing = []

    return AlertOut(
        id=alert.id,
        timestamp=alert.timestamp,
        predicted_class=alert.predicted_class,
        severity=alert.severity,
        status=alert.status,
        summary=summary,
        model_version=alert.model_version or "unknown",
        analyst_notes=alert.analyst_notes,
        review_timestamp=alert.review_timestamp,
        contributing_features=contributing
    )


@router.get("", response_model=List[AlertOut])
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    predicted_class: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Retrieves filtered and paginated security alerts.
    """
    query = db.query(AlertRecord)
    if severity:
        query = query.filter(AlertRecord.severity == severity)
    if status:
        query = query.filter(AlertRecord.status == status)
    if predicted_class:
        query = query.filter(AlertRecord.predicted_class == predicted_class)

    alerts = query.order_by(desc(AlertRecord.timestamp)).offset(skip).limit(limit).all()
    return [format_alert_response(a) for a in alerts]


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert_detail(
    alert_id: int = Path(..., ge=1),
    db: Session = Depends(get_db)
):
    """
    Returns complete investigation details for a specific alert.
    """
    alert = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return format_alert_response(alert)


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert_status(
    payload: AlertUpdatePatch,
    alert_id: int = Path(..., ge=1),
    db: Session = Depends(get_db)
):
    """
    Updates an alert's review status (New, Under Review, Resolved, False Positive) and analyst notes.
    """
    if payload.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}"
        )

    alert = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.status = payload.status
    if payload.analyst_notes is not None:
        alert.analyst_notes = payload.analyst_notes
    alert.review_timestamp = datetime.now(timezone.utc)

    db.commit()
    db.refresh(alert)
    return format_alert_response(alert)

