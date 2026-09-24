"""
SecureMailScope FastAPI Main Application.
Provides API routing, CORS handling, middleware, and lifecycle events.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.api.v1 import api_v1_router
from app.database import engine, Base, check_database_connection
import app.models  # Ensure models are imported for metadata registration

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s"
)
logger = logging.getLogger("securemailscope")

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle management."""
    logger.info("Initializing %s v%s in %s mode...", settings.PROJECT_NAME, settings.VERSION, settings.ENVIRONMENT)
    
    # Check initial database connectivity and create tables if connected
    db_ok, db_err = check_database_connection()
    if db_ok:
        logger.info("Initial database connectivity verified.")
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables initialized successfully.")
        except Exception as exc:
            logger.warning("Failed to initialize database tables: %s", exc)
    else:
        logger.warning("Initial database connection failed: %s (Will retry upon requests)", db_err)
    
    yield
    
    logger.info("Shutting down %s...", settings.PROJECT_NAME)


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Mount API v1 router
app.include_router(api_v1_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
def root_endpoint():
    """Root entry point for SecureMailScope API."""
    return {
        "project": settings.PROJECT_NAME,
        "description": settings.PROJECT_DESCRIPTION,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "documentation": "/docs",
        "health": f"{settings.API_V1_STR}/health",
        "readiness": f"{settings.API_V1_STR}/health/ready",
        "info": f"{settings.API_V1_STR}/health/info",
        "pcap_upload": f"{settings.API_V1_STR}/pcap/upload",
        "jobs": f"{settings.API_V1_STR}/jobs"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global fallback exception handler to return safe, structured JSON errors."""
    logger.error("Unhandled server exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred during request processing.",
            "path": request.url.path
        }
    )
