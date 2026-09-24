"""
Database session management and connection verification.
Provides SQLAlchemy engine, session maker, base declarative model, and health probe.
"""

import logging
from typing import Generator, Tuple, Optional
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# Engine configuration: supports postgresql and sqlite (used for fast offline testing)
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
elif settings.DATABASE_URL.startswith("postgresql"):
    connect_args["connect_timeout"] = settings.DATABASE_CONNECT_TIMEOUT_SECONDS

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    pool_recycle=300,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a SQLAlchemy database session.
    Closes the session after request completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database_connection(timeout_seconds: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """
    Safely probes the database connection without raising unhandled exceptions.
    Returns:
        (True, None) if reachable.
        (False, error_message) if connection fails.
    """
    timeout = timeout_seconds or settings.DATABASE_CONNECT_TIMEOUT_SECONDS
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:
        error_msg = f"Database probe failed: {exc.__class__.__name__}: {str(exc)}"
        logger.warning(error_msg)
        return False, error_msg
