"""
Pytest configuration and test client fixture for Network Intrusion Detection System.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.main import app
from backend.app.database import init_db
from backend.ml.predict import ModelEngine


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Ensure database and model are initialized before testing."""
    init_db()
    engine = ModelEngine.get_instance()
    if not engine.is_loaded:
        from backend.ml.train import train_models
        import pandas as pd
        data_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "data",
            "sample_traffic.csv"
        )
        if os.path.exists(data_path):
            df = pd.read_csv(data_path)
            train_models(df, model_type="random_forest", dataset_name="sample_traffic.csv")
            engine.load_active_model(force_reload=True)


@pytest.fixture
def client():
    """Returns FastAPI TestClient instance."""
    with TestClient(app) as c:
        yield c

