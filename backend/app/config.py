"""
Application Configuration Settings for Network Intrusion Detection System.
"""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True)

    PROJECT_NAME: str = "AI-Powered Network Intrusion Detection System"
    API_V1_STR: str = "/api"
    
    # Base directories
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DATA_DIR: str = os.path.join(BASE_DIR, "data")
    ARTIFACTS_DIR: str = os.path.join(BASE_DIR, "artifacts")
    MODELS_DIR: str = os.path.join(ARTIFACTS_DIR, "models")
    REPORTS_DIR: str = os.path.join(ARTIFACTS_DIR, "reports")
    
    # SQLite Database
    SQLITE_DB_PATH: str = os.path.join(BASE_DIR, "nids_database.db")
    SQLALCHEMY_DATABASE_URI: str = f"sqlite:///{SQLITE_DB_PATH}"
    
    # Upload limits
    MAX_UPLOAD_SIZE_MB: int = 50
    MAX_BATCH_ROWS: int = 20000
    
    # CORS
    CORS_ORIGINS: list = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]

settings = Settings()
