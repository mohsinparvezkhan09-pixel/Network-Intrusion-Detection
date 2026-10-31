"""
Dataset Upload, Validation, and Management API Endpoints.
"""

import os
import shutil
from typing import List
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query
from sqlalchemy.orm import Session
import pandas as pd

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.entities import DatasetRecord
from backend.app.schemas.common import DatasetOut, DatasetUploadResponse
from backend.ml.preprocessing import normalize_dataframe_columns, validate_features

router = APIRouter(prefix="/datasets", tags=["Datasets"])


@router.post("/upload", response_model=DatasetUploadResponse)
async def upload_dataset(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Safely uploads a CSV network-flow dataset, inspects its schema,
    checks for missing canonical features, and stores metadata.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")

    # Prevent path traversal
    safe_filename = os.path.basename(file.filename)
    dest_path = os.path.join(settings.DATA_DIR, f"upload_{safe_filename}")

    # Enforce file size limit
    total_bytes = 0
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    with open(dest_path, "wb") as buffer:
        while chunk := await file.read(1024 * 1024):
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                buffer.close()
                if os.path.exists(dest_path):
                    os.remove(dest_path)
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB."
                )
            buffer.write(chunk)

    # Read and inspect with pandas
    try:
        # Read limited rows first or complete file
        df = pd.read_csv(dest_path, nrows=50000)
    except Exception as e:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV file: {str(e)}")

    cleaned_df, _ = normalize_dataframe_columns(df)
    validation = validate_features(cleaned_df, require_target=False)

    # Register in database
    record = DatasetRecord(
        name=safe_filename,
        filename=os.path.basename(dest_path),
        file_path=dest_path,
        row_count=len(df),
        file_size_bytes=total_bytes,
        has_labels=validation["has_target"],
        description=f"Uploaded CSV with {len(df)} rows and {len(df.columns)} columns"
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Prepare preview rows (sanitizing nan/inf)
    preview_df = df.head(10).fillna(0).replace([float('inf'), float('-inf')], 0)
    preview = preview_df.to_dict(orient="records")

    return DatasetUploadResponse(
        dataset_id=record.id,
        filename=safe_filename,
        total_rows=len(df),
        total_columns=len(df.columns),
        is_valid_schema=validation["is_valid"],
        missing_features=validation["missing_features"],
        has_target=validation["has_target"],
        preview=preview
    )


@router.get("", response_model=List[DatasetOut])
def list_datasets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Returns list of all registered datasets.
    """
    datasets = db.query(DatasetRecord).order_by(DatasetRecord.created_at.desc()).offset(skip).limit(limit).all()
    return datasets

