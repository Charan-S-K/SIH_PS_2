"""
Cryptographic Rules Engine definition endpoints.
Provides metadata on configured security rules, severities, and descriptions.
"""

from typing import List
from fastapi import APIRouter

from app.schemas.rule_engine import CryptoRuleDefinition
from app.services.crypto_rules_engine import CryptographicRulesEngine

router = APIRouter()


@router.get(
    "",
    response_model=List[CryptoRuleDefinition],
    summary="List all configured Cryptographic Security Rules",
    description="Retrieves definitions for all loaded security rules including category, default severity, description, and remediation advice."
)
def list_rules() -> List[CryptoRuleDefinition]:
    """Return all active rule definitions."""
    engine = CryptographicRulesEngine()
    return engine.list_rules()
