"""
Unit Tests for Machine Learning Pipeline Training and Inference.
"""

import os
import pandas as pd
import pytest

from backend.ml.predict import ModelEngine
from backend.ml.train import train_models


def test_model_loading_and_metadata():
    engine = ModelEngine.get_instance()
    assert engine.is_loaded is True
    meta = engine.model_metadata
    assert meta is not None
    assert "version" in meta
    assert "classes" in meta
    assert len(meta["classes"]) >= 2
    assert "BENIGN" in meta["classes"]
    assert "metrics" in meta
    assert meta["metrics"]["accuracy"] > 0.85


def test_single_prediction_engine():
    engine = ModelEngine.get_instance()
    sample_flow = {
        "Destination Port": 80,
        "Flow Duration": 500000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 12,
        "Total Length of Fwd Packets": 3500.0,
        "Total Length of Bwd Packets": 10200.0,
        "Fwd Packet Length Max": 1460.0,
        "Fwd Packet Length Min": 40.0,
        "Fwd Packet Length Mean": 350.0,
        "Bwd Packet Length Max": 1460.0,
        "Bwd Packet Length Min": 40.0,
        "Bwd Packet Length Mean": 850.0,
        "Flow Bytes/s": 27400.0,
        "Flow Packets/s": 44.0,
        "Flow IAT Mean": 23800.0,
        "Flow IAT Std": 12000.0,
        "Flow IAT Max": 60000.0,
        "Flow IAT Min": 100.0,
        "Fwd IAT Mean": 50000.0,
        "Bwd IAT Mean": 41000.0,
        "Fwd PSH Flags": 0,
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
        "ACK Flag Count": 1,
        "URG Flag Count": 0,
        "Down/Up Ratio": 1.2,
        "Average Packet Size": 622.0,
        "Init_Win_bytes_forward": 29200,
        "Init_Win_bytes_backward": 29200,
        "act_data_pkt_fwd": 7,
        "min_seg_size_forward": 32
    }
    pred = engine.predict_single(sample_flow)
    assert "predicted_class" in pred
    assert "confidence" in pred
    assert "is_anomaly" in pred
    assert "severity" in pred
    assert "top_contributing_features" in pred
    assert len(pred["top_contributing_features"]) > 0


def test_batch_prediction():
    engine = ModelEngine.get_instance()
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "data",
        "sample_traffic.csv"
    )
    df = pd.read_csv(data_path).head(15)
    results = engine.predict_dataframe(df)
    assert len(results) == 15
    for r in results:
        assert "predicted_class" in r
        assert "confidence" in r
        assert r["confidence"] >= 0.0 and r["confidence"] <= 1.0

