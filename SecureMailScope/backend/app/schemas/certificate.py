from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class SanItem(BaseModel):
    """Subject Alternative Name entry."""
    type: str = Field(..., description="SAN type: DNS, IP, EMAIL, URI, OTHER")
    value: str = Field(..., description="SAN value")


class X509CertificateResponse(BaseModel):
    """Forensic X.509 Certificate model response."""
    id: int
    job_id: str
    tcp_stream: int
    tcp_session_id: Optional[str] = None
    tls_handshake_id: Optional[str] = None
    frame_number: Optional[int] = None

    chain_index: int = 0
    chain_length: int = 1
    chain_status: str = "UNKNOWN"

    # Subject details
    subject_dn: str
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    subject_ou: Optional[str] = None
    subject_country: Optional[str] = None
    subject_state: Optional[str] = None
    subject_locality: Optional[str] = None

    # Issuer details
    issuer_dn: str
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    issuer_ou: Optional[str] = None
    issuer_country: Optional[str] = None
    issuer_state: Optional[str] = None
    issuer_locality: Optional[str] = None

    # Serial Number & Identification
    serial_number: str

    # Temporal Validity
    not_before: datetime
    not_after: datetime
    validity_days: int
    validity_status: str
    days_until_expiration: Optional[int] = None

    # Subject Alternative Names
    sans: List[Dict[str, str]] = []

    # Cryptographic Parameters
    public_key_algorithm: str
    key_size_bits: Optional[int] = None
    public_key_curve: Optional[str] = None
    signature_algorithm: str
    signature_digest: Optional[str] = None

    # CA & Self-Signed
    is_self_signed: bool = False
    is_ca: bool = False
    path_length_constraint: Optional[int] = None

    # Usages & Fingerprints
    key_usage: List[str] = []
    extended_key_usage: List[str] = []
    fingerprint_sha256: str
    fingerprint_sha1: str

    # Forensic & Parsing State
    raw_der_base64: Optional[str] = None
    parsing_status: str = "PARSED"
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class X509CertificateListResponse(BaseModel):
    """Aggregate response for job X.509 certificate analyses."""
    job_id: str
    total_certificates: int
    valid_certificates: int
    expired_certificates: int
    not_yet_valid_certificates: int
    self_signed_certificates: int
    weak_keys_count: int
    weak_signatures_count: int
    certificates: List[X509CertificateResponse]
