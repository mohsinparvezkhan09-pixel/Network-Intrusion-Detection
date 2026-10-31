"""
Integration Tests for FastAPI Endpoints.
"""

import pytest


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["healthy", "degraded"]
    assert data["model_loaded"] is True
    assert data["database_connected"] is True


def test_dashboard_stats(client):
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_analyzed_records" in data
    assert "attack_distribution" in data
    assert "severity_distribution" in data
    assert "model_health" in data


def test_dashboard_trends(client):
    res = client.get("/api/dashboard/trends")
    assert res.status_code == 200
    data = res.json()
    assert "trends" in data
    assert len(data["trends"]) > 0


def test_model_status_and_metrics(client):
    res_status = client.get("/api/models/status")
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert data_status["is_loaded"] is True
    assert "classes" in data_status

    res_metrics = client.get("/api/models/metrics")
    assert res_metrics.status_code == 200
    data_metrics = res_metrics.json()
    assert "accuracy" in data_metrics
    assert "confusion_matrix" in data_metrics


def test_single_prediction_api(client):
    payload = {
        "features": {
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
    }
    res = client.post("/api/predictions/single", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "predicted_class" in data
    assert "confidence" in data
    assert "severity" in data


def test_alerts_management(client):
    # Fetch alerts
    res = client.get("/api/alerts?limit=10")
    assert res.status_code == 200
    alerts = res.json()
    assert isinstance(alerts, list)

    # If there is an alert, test PATCH review status
    if len(alerts) > 0:
        alert_id = alerts[0]["id"]
        patch_payload = {
            "status": "Under Review",
            "analyst_notes": "Triage verified high packet surge."
        }
        res_patch = client.patch(f"/api/alerts/{alert_id}", json=patch_payload)
        assert res_patch.status_code == 200
        updated = res_patch.json()
        assert updated["status"] == "Under Review"
        assert updated["analyst_notes"] == "Triage verified high packet surge."


def test_reports_export(client):
    res_csv = client.get("/api/reports/export?report_type=alerts&format=csv")
    assert res_csv.status_code == 200
    assert res_csv.headers["content-type"].startswith("text/csv")

    res_json = client.get("/api/reports/export?report_type=predictions&format=json")
    assert res_json.status_code == 200
    data = res_json.json()
    assert data["report"] == "predictions"

