"""
Health and Status API Endpoint.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.app.database import get_db
from backend.app.schemas.common import HealthResponse
from backend.ml.predict import ModelEngine

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)):
    """
    Checks operational health of API, database connectivity, and ML model status.
    """
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    engine = ModelEngine.get_instance()
    model_version = engine.model_metadata.get("version") if engine.is_loaded else None

    return HealthResponse(
        status="healthy" if db_ok and engine.is_loaded else "degraded",
        version="1.0.0",
        active_model=model_version,
        model_loaded=engine.is_loaded,
        database_connected=db_ok,
        timestamp=datetime.now(timezone.utc).isoformat()
    )

