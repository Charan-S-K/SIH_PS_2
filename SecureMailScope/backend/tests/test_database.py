"""Tests for database connectivity and base models."""

from unittest import mock
from sqlalchemy import Column, Integer, String
from app.database import Base, check_database_connection
from app.models.base import TimestampMixin, utc_now


class SampleModel(Base, TimestampMixin):
    """Temporary test model verifying Base and TimestampMixin."""
    __tablename__ = "test_sample"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)


def test_timestamp_mixin(db_session):
    """Verify TimestampMixin sets timestamps on persisted objects."""
    item = SampleModel(name="test_item")
    db_session.add(item)
    db_session.commit()
    db_session.refresh(item)
    
    assert item.id is not None
    assert item.name == "test_item"
    assert item.created_at is not None
    assert item.updated_at is not None


def test_check_database_connection_failure():
    """Verify check_database_connection safely catches errors and returns False."""
    with mock.patch("app.database.engine.connect", side_effect=Exception("Timeout connecting")):
        is_ok, err = check_database_connection()
        assert is_ok is False
        assert "Timeout connecting" in err

def test_get_db_generator():
    """Test get_db dependency yields active session and closes it."""
    from app.database import get_db
    gen = get_db()
    session = next(gen)
    assert session is not None
    try:
        next(gen)
    except StopIteration:
        pass  # Expected when generator finishes
