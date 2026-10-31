# Aegis NIDS: AI-Powered Network Intrusion Detection System

An enterprise-grade, defensive cybersecurity application for detecting malicious network activity through supervised machine learning (Random Forest / XGBoost) and unsupervised anomaly detection (Isolation Forest) across network flow records.

Built following modern Security Operations Center (SOC) standards with reliable offline CSV flow ingestion, verifiable evaluation metrics, rule-based threat severity mapping, and interactive feature deviation explainability.

---

## 1. System Architecture

```
                                  +-----------------------------+
                                  |     React 19 + Vite SOC     |
                                  |  Tailwind CSS & Recharts    |
                                  |     (Port: 5173)            |
                                  +--------------+--------------+
                                                 | REST / JSON
                                                 v
                                  +-----------------------------+
                                  |     FastAPI Backend API     |
                                  |   Pydantic V2 Validation    |
                                  |     (Port: 8000)            |
                                  +--------------+--------------+
                                                 |
                     +---------------------------+---------------------------+
                     |                                                       |
                     v                                                       v
      +-----------------------------+                         +-----------------------------+
      |      ML Model Engine        |                         |     SQLite Database         |
      | - Preprocessing Pipeline    |                         | - Dataset Metadata          |
      | - Random Forest Classifier  |                         | - Flow Predictions History  |
      | - Isolation Forest Detector |                         | - Security Alerts & Notes   |
      | - Atomic Model Versioning   |                         | - Background Job Records    |
      +-----------------------------+                         +-----------------------------+
```

### Supported Threat Categories
* **BENIGN**: Normal web, DNS, streaming, and database communications.
* **DoS (Denial-of-Service)**: Slowloris and connection starvation patterns.
* **DDoS (Distributed DoS)**: High-rate SYN floods and packet amplification bursts.
* **PortScan**: Rapid TCP/UDP port reconnaissance and probing.
* **BruteForce**: Repeated unauthorized authentication sweeps against SSH, FTP, or RDP.
* **Botnet**: Periodic low-jitter C2 (Command & Control) heartbeat beacons.
* **Unsupervised Anomalies**: Identified separately via Isolation Forest with configurable contamination (5%).

---

## 2. Technology Stack

* **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, Recharts, Lucide React, React Router.
* **Backend**: Python 3.10+, FastAPI, Uvicorn, Pydantic V2, SQLAlchemy, SQLite.
* **Machine Learning**: Scikit-learn, XGBoost, Pandas, NumPy, Joblib.
* **Testing**: Pytest (backend), Vitest & React Testing Library (frontend).

---

## 3. Project Directory Structure

```
Network Intrusion Detection/
  backend/
    app/
      main.py               # FastAPI application & lifespan startup
      config.py             # App settings & CORS configuration
      database.py           # SQLite SQLAlchemy engine & session factory
      api/
        health.py           # /api/health endpoint
        dashboard.py        # /api/dashboard/stats & /api/dashboard/trends
        datasets.py         # /api/datasets/upload & list
        predictions.py      # /api/predictions/single & batch inference
        alerts.py           # /api/alerts list, triage, and PATCH update
        models.py           # /api/models status, metrics, and training
        reports.py          # /api/reports/export (CSV & JSON)
      models/
        entities.py         # SQLAlchemy ORM database models
      schemas/
        common.py           # Pydantic v2 request & response schemas
    ml/
      preprocessing.py      # Canonical schema validation & inf/nan transformers
      train.py              # Supervised & Isolation Forest pipeline training
      predict.py            # Singleton model inference engine & explainability
      evaluate.py           # Genuine confusion matrix, F1, FPR, FNR, ROC-AUC
    tests/
      conftest.py           # Test fixtures & test client
      test_api.py           # Integration API tests
      test_models.py        # ML engine & inference tests
      test_preprocessing.py # Preprocessing & validation tests
    requirements.txt        # Backend dependencies
    .env.example            # Environment variables template
  frontend/
    src/
      components/           # Sidebar, Header, SeverityBadge, StatusBadge
      layouts/              # DashboardLayout with SOC header & sidebar
      pages/
        OverviewPage.tsx        # KPI metrics, trend chart, attack donut, alerts
        TrafficAnalysisPage.tsx # CSV upload, validation, batch execution & export
        AlertsPage.tsx          # Incident triage, analyst notes, and status updates
        ModelCenterPage.tsx     # Metrics, confusion matrix, per-class stats, retrain
        PredictionExplorerPage.tsx # Interactive test vectors & feature deviation
        ReportsPage.tsx         # Download CSV/JSON incident & prediction reports
        SettingsHelpPage.tsx    # System health, canonical schema, safe-use policy
      services/api.ts       # Typed API client
      types/index.ts        # TypeScript interfaces
    package.json            # Frontend dependencies & scripts
  data/
    sample_traffic.csv      # Synthetic flow dataset (4,500 records, 6 classes)
  artifacts/
    models/                 # Versioned model joblib bundles & metadata JSONs
    reports/                # Generated reports
  scripts/
    setup.ps1               # Automated Windows PowerShell environment setup
    train_model.ps1         # ML training automation script
    run_backend.ps1         # Launches FastAPI backend on port 8000
    run_frontend.ps1        # Launches Vite dev server on port 5173
    generate_sample_data.py # Reproducible realistic flow generator
    seed_database.py        # Seeds initial flow history and security alerts
  README.md
```

---

## 4. Quick Start (Windows PowerShell)

### Prerequisites
* Python 3.10 or higher
* Node.js 18+ and npm

### Automated Setup
Open Windows PowerShell in the project directory and run:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
```

### Manual Setup
1. **Install Backend Dependencies**:
   ```powershell
   python -m pip install -r backend/requirements.txt
   ```

2. **Generate Sample Traffic Dataset & Seed Database**:
   ```powershell
   python scripts/generate_sample_data.py
   python backend/ml/train.py
   python scripts/seed_database.py
   ```

3. **Install Frontend Dependencies**:
   ```powershell
   cd frontend
   npm install
   cd ..
   ```

---

## 5. Starting the Application

Launch the backend and frontend in two separate PowerShell windows:

### Terminal 1: Backend API
```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_backend.ps1
# Or directly:
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
* Backend API: `http://127.0.0.1:8000`
* Interactive Swagger Docs: `http://127.0.0.1:8000/docs`
* ReDoc: `http://127.0.0.1:8000/redoc`

### Terminal 2: Frontend SOC Dashboard
```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_frontend.ps1
# Or directly:
cd frontend
npm run dev
```
* Dashboard URL: `http://localhost:5173`

---

## 6. Running Automated Tests

### Backend Test Suite (Pytest)
```powershell
python -m pytest backend/tests -v
```
Runs 15 automated tests covering:
* Feature normalization and missing canonical feature detection
* Positive/negative infinity and NaN sanitization
* Model training, loading, and versioning
* Single-flow and batch inference
* FastAPI endpoints: `/health`, `/dashboard/stats`, `/dashboard/trends`, `/models`, `/predictions`, `/alerts`, `/reports`

### Frontend Test Suite (Vitest)
```powershell
cd frontend
npm test
```
Tests component rendering for `SeverityBadge`, `StatusBadge`, `Sidebar` navigation, and `Header`.

### Frontend Production Build
```powershell
cd frontend
npm run build
```

---

## 7. API Usage Examples (Windows PowerShell)

> **Note on Windows PowerShell**: In PowerShell, `curl` is an alias for `Invoke-WebRequest`. Use `curl.exe` or `Invoke-RestMethod` to execute API calls.

### Health Check
```powershell
curl.exe -X GET "http://127.0.0.1:8000/api/health"
# Or using native PowerShell:
Invoke-RestMethod "http://127.0.0.1:8000/api/health"
```

### Single Flow Inference
```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/predictions/single" `
  -H "Content-Type: application/json" `
  -d '{\"features\": {\"Destination Port\": 80, \"Flow Duration\": 120000, \"Total Fwd Packets\": 850, \"Total Backward Packets\": 0, \"Total Length of Fwd Packets\": 34000.0, \"Total Length of Bwd Packets\": 0.0, \"Fwd Packet Length Max\": 40.0, \"Fwd Packet Length Min\": 40.0, \"Fwd Packet Length Mean\": 40.0, \"Bwd Packet Length Max\": 0.0, \"Bwd Packet Length Min\": 0.0, \"Bwd Packet Length Mean\": 0.0, \"Flow Bytes/s\": 283333.0, \"Flow Packets/s\": 7083.0, \"Flow IAT Mean\": 141.0, \"Flow IAT Std\": 20.0, \"Flow IAT Max\": 250.0, \"Flow IAT Min\": 10.0, \"Fwd IAT Mean\": 141.0, \"Bwd IAT Mean\": 0.0, \"Fwd PSH Flags\": 0, \"SYN Flag Count\": 1, \"RST Flag Count\": 0, \"ACK Flag Count\": 0, \"URG Flag Count\": 0, \"Down/Up Ratio\": 0.0, \"Average Packet Size\": 40.0, \"Init_Win_bytes_forward\": 2048, \"Init_Win_bytes_backward\": -1, \"act_data_pkt_fwd\": 0, \"min_seg_size_forward\": 20}}'
```

### List Alerts
```powershell
curl.exe -X GET "http://127.0.0.1:8000/api/alerts?limit=10&severity=Critical"
# Or native PowerShell:
Invoke-RestMethod "http://127.0.0.1:8000/api/alerts?limit=10&severity=Critical"
```

### Triage / Update Alert Status
```powershell
curl.exe -X PATCH "http://127.0.0.1:8000/api/alerts/1" `
  -H "Content-Type: application/json" `
  -d '{\"status\": \"Under Review\", \"analyst_notes\": \"Triage verified packet flood from IP 192.168.1.105\"}'
```

---

## 8. Troubleshooting & Common Questions

1. **Missing Features Error on CSV Upload**:
   Ensure your CSV contains canonical network flow headers (e.g. `Destination Port`, `Flow Duration`, `Total Fwd Packets`, etc.). Headers with whitespace variations or snake_case are automatically mapped. Missing required features will trigger clear validation errors without arbitrary default imputation.

2. **Port 8000 or 5173 Already in Use**:
   * Change backend port: `python -m uvicorn backend.app.main:app --port 8001`
   * Change frontend port in `frontend/vite.config.ts`.

3. **Active Model Not Found**:
   Run `python backend/ml/train.py` or trigger retraining directly from the **Model Center** in the UI.

---

## 9. Model Limitations & Safe-Use Guidance

* **Pattern Recognition vs Mitigation**: Aegis NIDS performs passive detection and alerting; it does not block packets or modify firewall rules automatically unless explicitly connected to a separate prevention mechanism.
* **Anomaly Detection Interpretation**: Unsupervised Isolation Forest flags statistical deviations and does not identify a specific attack signature on its own.
* **Authorized Monitoring**: Only analyze datasets and network flow captures that you are explicitly authorized to monitor.

#   N e t w o r k - I n t r u s i o n - D e t e c t i o n  
 #   N e t w o r k - I n t r u s i o n - D e t e c t i o n  
 #   N e t w o r k - I n t r u s i o n - D e t e c t i o n  
 #   N e t w o r k - I n t r u s i o n - D e t e c t i o n  
 #   N e t w o r k - I n t r u s i o n - D e t e c t i o n  
 #   N e t w o r k - I n t r u s i o n - D e t e c t i o n  
 