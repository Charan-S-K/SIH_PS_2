"""
Base declarative model and reusable mixins.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime


def utc_now() -> datetime:
    """Return current UTC datetime with timezone awareness."""
    return datetime.now(timezone.utc)


class TimestampMixin:
    """Provides created_at and updated_at audit columns."""
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
