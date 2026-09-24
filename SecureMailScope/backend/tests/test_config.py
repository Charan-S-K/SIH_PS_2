"""Tests for application settings and environment handling."""

import os
from unittest import mock
from app.config import Settings, get_settings


def test_default_settings():
    """Verify default configuration values."""
    settings = Settings()
    assert settings.PROJECT_NAME == "SecureMailScope"
    assert settings.VERSION == "0.1.0"
    assert settings.API_V1_STR == "/api/v1"
    assert settings.ENVIRONMENT == "development"
    assert settings.DEBUG is False
    assert len(settings.CORS_ORIGINS) >= 2


def test_cors_origins_parsing():
    """Verify that comma-separated string CORS origins are parsed into a list."""
    with mock.patch.dict(os.environ, {"CORS_ORIGINS": "http://example.com,http://test.org"}):
        settings = Settings()
        assert "http://example.com" in settings.CORS_ORIGINS
        assert "http://test.org" in settings.CORS_ORIGINS
        assert len(settings.CORS_ORIGINS) == 2


def test_environment_override():
    """Verify environment variables take precedence over defaults."""
    with mock.patch.dict(os.environ, {
        "ENVIRONMENT": "staging",
        "DEBUG": "true",
        "DATABASE_URL": "sqlite:///./test.db"
    }):
        settings = Settings()
        assert settings.ENVIRONMENT == "staging"
        assert settings.DEBUG is True
        assert settings.DATABASE_URL == "sqlite:///./test.db"

def test_cors_origins_json_string():
    """Verify that JSON-formatted string CORS origins are parsed into a list."""
    with mock.patch.dict(os.environ, {"CORS_ORIGINS": '["http://localhost:8080", "http://test.local"]'}):
        settings = Settings()
        assert "http://localhost:8080" in settings.CORS_ORIGINS
        assert "http://test.local" in settings.CORS_ORIGINS
        assert len(settings.CORS_ORIGINS) == 2


def test_cors_origins_empty_or_invalid():
    """Verify fallback when empty or invalid string is passed."""
    with mock.patch.dict(os.environ, {"CORS_ORIGINS": ""}):
        settings = Settings()
        assert settings.CORS_ORIGINS == []
