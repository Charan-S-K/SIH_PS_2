"""
Application configuration management via Pydantic Settings.
Loads configuration from environment variables or .env file.
"""

import json
from functools import lru_cache
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SecureMailScope backend configuration settings."""

    # Project metadata
    PROJECT_NAME: str = Field(
        default="SecureMailScope",
        description="Application name"
    )
    PROJECT_DESCRIPTION: str = Field(
        default="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
        description="Application description"
    )
    VERSION: str = Field(default="0.1.0", description="Semantic version")
    API_V1_STR: str = Field(default="/api/v1", description="API v1 prefix")
    
    # Environment & Debug
    ENVIRONMENT: str = Field(default="development", description="Environment: development, staging, production, testing")
    DEBUG: bool = Field(default=False, description="Debug mode")

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+psycopg2://postgres:postgres@localhost:5432/securemailscope",
        description="Database connection URL"
    )
    DATABASE_CONNECT_TIMEOUT_SECONDS: int = Field(
        default=5,
        description="Database connection timeout in seconds"
    )

    # CORS settings: accepts JSON list string or comma-separated string
    CORS_ORIGINS: Union[List[str], str] = Field(
        default=[
            "http://localhost:5173",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:3000",
        ],
        description="Allowed CORS origin URLs"
    )

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def normalize_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            stripped = v.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    pass
            return [i.strip() for i in stripped.split(",") if i.strip()]
        elif isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        return []

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
