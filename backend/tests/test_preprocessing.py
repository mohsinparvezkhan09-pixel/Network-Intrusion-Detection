"""
Unit Tests for Data Preprocessing and Validation Pipeline.
"""

import numpy as np
import pandas as pd
import pytest

from backend.ml.preprocessing import (
    CANONICAL_FEATURES,
    clean_column_name,
    normalize_dataframe_columns,
    validate_features,
    SafeInfAndNanCleaner,
    build_preprocessor_pipeline
)


def test_clean_column_name():
    assert clean_column_name("  Destination Port  ") == "Destination Port"
    assert clean_column_name("Flow Duration\n") == "Flow Duration"


def test_normalize_dataframe_columns():
    df = pd.DataFrame({
        " destination_port ": [80, 443],
        "FLOW_DURATION": [1000, 2000],
        "label": ["BENIGN", "DoS"]
    })
    cleaned_df, mapping = normalize_dataframe_columns(df)
    assert "Destination Port" in cleaned_df.columns
    assert "Flow Duration" in cleaned_df.columns
    assert "Label" in cleaned_df.columns


def test_validate_features_missing_features():
    df = pd.DataFrame({
        "Destination Port": [80],
        "Flow Duration": [1000]
    })
    val = validate_features(df, require_target=True)
    assert val["is_valid"] is False
    assert len(val["missing_features"]) > 0
    assert val["missing_target"] is True


def test_safe_inf_and_nan_cleaner():
    transformer = SafeInfAndNanCleaner(clip_max=1000, clip_min=-1000)
    arr = np.array([
        [10.0, np.inf],
        [-np.inf, 5000.0],
        [np.nan, 20.0]
    ])
    transformed = transformer.transform(arr)
    # Inf should be replaced by NaN for imputer
    assert np.isnan(transformed[0, 1])
    assert np.isnan(transformed[1, 0])
    # Extreme values should be clipped
    assert transformed[1, 1] == 1000.0


def test_full_preprocessor_pipeline():
    pipeline = build_preprocessor_pipeline()
    X = np.array([
        [80.0, 5000.0, np.inf],
        [443.0, np.nan, 120.0],
        [8080.0, 15000.0, 300.0]
    ])
    pipeline.fit(X)
    X_trans = pipeline.transform(X)
    assert X_trans.shape == (3, 3)
    assert not np.isnan(X_trans).any()
    assert not np.isinf(X_trans).any()

