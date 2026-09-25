"""API v1 router registry."""
from fastapi import APIRouter
from app.api.v1.health import router as health_router
from app.api.v1.pcap import router as pcap_router
from app.api.v1.jobs import router as jobs_router
from app.api.v1.rules import router as rules_router
from app.api.v1.ml import router as ml_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router, prefix="/health", tags=["Health & Status"])
api_v1_router.include_router(pcap_router, prefix="/pcap", tags=["PCAP Capture Files"])
api_v1_router.include_router(jobs_router, prefix="/jobs", tags=["Analysis Jobs"])
api_v1_router.include_router(rules_router, prefix="/rules", tags=["Cryptographic Rules"])
api_v1_router.include_router(ml_router)
