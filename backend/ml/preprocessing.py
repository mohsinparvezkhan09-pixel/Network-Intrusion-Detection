"""
Data Preprocessing and Validation for Network Intrusion Detection System.
Handles feature normalization, missing values, infinite values, and pipeline transformations.
"""

import logging
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

logger = logging.getLogger(__name__)

# Canonical feature schema based on standard network flow captures (e.g. CIC-IDS2017)
CANONICAL_FEATURES: List[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward"
]

TARGET_COLUMN = "Label"


def clean_column_name(col: str) -> str:
    """Strip whitespace and normalize column names."""
    return col.strip()


def normalize_dataframe_columns(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, str]]:
    """
    Normalizes dataframe column names while preserving original-to-canonical mapping.
    Matches case-insensitively and handles spaces/underscores.
    """
    column_mapping: Dict[str, str] = {}
    renamed: Dict[str, str] = {}
    
    canonical_lookup = {clean_column_name(c).lower().replace("_", " "): c for c in CANONICAL_FEATURES}
    canonical_lookup[TARGET_COLUMN.lower()] = TARGET_COLUMN

    for col in df.columns:
        norm_key = clean_column_name(str(col)).lower().replace("_", " ")
        if norm_key in canonical_lookup:
            matched_canonical = canonical_lookup[norm_key]
            renamed[col] = matched_canonical
            column_mapping[str(col)] = matched_canonical
        else:
            renamed[col] = clean_column_name(str(col))
            column_mapping[str(col)] = clean_column_name(str(col))

    df_cleaned = df.rename(columns=renamed)
    return df_cleaned, column_mapping


def validate_features(df: pd.DataFrame, require_target: bool = False) -> Dict[str, Any]:
    """
    Validates presence of canonical features and records data health.
    Does not silently fill missing columns.
    """
    cleaned_df, _ = normalize_dataframe_columns(df)
    missing_features = [f for f in CANONICAL_FEATURES if f not in cleaned_df.columns]
    
    missing_target = False
    if require_target and TARGET_COLUMN not in cleaned_df.columns:
        missing_target = True

    is_valid = len(missing_features) == 0 and (not require_target or not missing_target)
    
    # Calculate statistics on NaN and Infinite values
    num_nans = int(cleaned_df.isna().sum().sum())
    # Count infs in numeric columns
    numeric_cols = cleaned_df.select_dtypes(include=[np.number]).columns
    num_infs = int(np.isinf(cleaned_df[numeric_cols].values).sum()) if len(numeric_cols) > 0 else 0

    return {
        "is_valid": is_valid,
        "total_rows": len(cleaned_df),
        "total_columns": len(cleaned_df.columns),
        "available_features": [c for c in cleaned_df.columns if c in CANONICAL_FEATURES],
        "missing_features": missing_features,
        "has_target": TARGET_COLUMN in cleaned_df.columns,
        "missing_target": missing_target,
        "nan_count": num_nans,
        "inf_count": num_infs
    }


class SafeInfAndNanCleaner(BaseEstimator, TransformerMixin):
    """
    Custom transformer to replace positive/negative infinity with large bounded values
    or NaN for downstream median imputation, preventing overflows or model corruption.
    """
    def __init__(self, clip_max: float = 1e9, clip_min: float = -1e9):
        self.clip_max = clip_max
        self.clip_min = clip_min

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        X_copy = np.array(X, dtype=np.float64, copy=True)
        # Replace infs with nan so SimpleImputer can replace with median
        X_copy[np.isinf(X_copy)] = np.nan
        # Clip extreme values
        X_copy = np.clip(X_copy, self.clip_min, self.clip_max)
        return X_copy


def build_preprocessor_pipeline(features: Optional[List[str]] = None) -> Pipeline:
    """
    Constructs a robust sklearn preprocessing pipeline with:
    1. Safe Inf replacement and value bounding
    2. Median imputation for missing/corrupted values
    3. Robust scaling to handle network flow outliers gracefully
    """
    pipe = Pipeline([
        ("cleaner", SafeInfAndNanCleaner()),
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", RobustScaler(with_centering=True, with_scaling=True, unit_variance=True))
    ])
    return pipe

