from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class X509CertificateAnalysis(Base, TimestampMixin):
    """
    X.509 Certificate Forensic Analysis Model.
    
    Stores parsed and validated cryptographic parameters from X.509 certificates
    observed in TLS handshakes (direct TLS or upgraded via STARTTLS).
    Strictly evidence-first: extracts observable properties (validity, subject/issuer,
    SANs, key algorithm/size, signature algorithm, self-signed status, chain hierarchy).
    Never invents certificate data.
    """
    __tablename__ = "x509_certificate_analyses"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    job_id = Column(
        String(36),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tcp_stream = Column(Integer, nullable=False, index=True)
    tcp_session_id = Column(
        String(36),
        ForeignKey("tcp_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    tls_handshake_id = Column(
        String(36),
        ForeignKey("tls_handshake_analyses.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Frame / Evidence Location
    frame_number = Column(Integer, nullable=True, comment="Packet frame where Certificate message appeared")
    
    # Chain Position & Structure
    chain_index = Column(Integer, default=0, nullable=False, comment="0 = Leaf / End-Entity, 1 = Intermediate, etc.")
    chain_length = Column(Integer, default=1, nullable=False, comment="Total certificates in observed chain")
    chain_status = Column(
        String(50),
        default="UNKNOWN",
        nullable=False,
        comment="COMPLETE_CHAIN, INCOMPLETE_CHAIN, SELF_SIGNED_LEAF, SINGLE_CERTIFICATE, UNKNOWN"
    )

    # Subject Distinguished Name & Components
    subject_dn = Column(Text, nullable=False, comment="Full RFC 4514 Subject DN string")
    subject_cn = Column(String(255), nullable=True, comment="Common Name (CN)")
    subject_org = Column(String(255), nullable=True, comment="Organization (O)")
    subject_ou = Column(String(255), nullable=True, comment="Organizational Unit (OU)")
    subject_country = Column(String(10), nullable=True, comment="Country (C)")
    subject_state = Column(String(255), nullable=True, comment="State/Province (ST)")
    subject_locality = Column(String(255), nullable=True, comment="Locality/City (L)")

    # Issuer Distinguished Name & Components
    issuer_dn = Column(Text, nullable=False, comment="Full RFC 4514 Issuer DN string")
    issuer_cn = Column(String(255), nullable=True, comment="Common Name (CN)")
    issuer_org = Column(String(255), nullable=True, comment="Organization (O)")
    issuer_ou = Column(String(255), nullable=True, comment="Organizational Unit (OU)")
    issuer_country = Column(String(10), nullable=True, comment="Country (C)")
    issuer_state = Column(String(255), nullable=True, comment="State/Province (ST)")
    issuer_locality = Column(String(255), nullable=True, comment="Locality/City (L)")

    # Serial Number & Identification
    serial_number = Column(String(128), nullable=False, comment="Hex formatted serial number")

    # Temporal Validity
    not_before = Column(DateTime(timezone=True), nullable=False, comment="Certificate validity start (UTC)")
    not_after = Column(DateTime(timezone=True), nullable=False, comment="Certificate validity expiration (UTC)")
    validity_days = Column(Integer, nullable=False, comment="Total validity duration in days")
    validity_status = Column(
        String(50),
        nullable=False,
        default="VALID",
        comment="VALID, EXPIRED, NOT_YET_VALID"
    )
    days_until_expiration = Column(
        Integer,
        nullable=True,
        comment="Days until expiration from analysis time (negative if expired)"
    )

    # Subject Alternative Names (SAN)
    sans = Column(
        JSON,
        default=list,
        nullable=False,
        comment="List of SAN objects: [{'type': 'DNS'|'IP'|'EMAIL'|'URI', 'value': str}]"
    )

    # Cryptographic Public Key Parameters
    public_key_algorithm = Column(
        String(50),
        nullable=False,
        default="UNKNOWN",
        comment="RSA, EC, ED25519, ED448, DSA, UNKNOWN"
    )
    key_size_bits = Column(Integer, nullable=True, comment="Key size in bits (e.g. 2048, 4096, 256)")
    public_key_curve = Column(String(100), nullable=True, comment="EC Curve name if applicable (e.g. secp256r1)")

    # Signature Algorithm & Cryptographic Hash
    signature_algorithm = Column(
        String(100),
        nullable=False,
        default="UNKNOWN",
        comment="e.g. sha256WithRSAEncryption, ecdsa-with-SHA256, sha1WithRSAEncryption"
    )
    signature_digest = Column(
        String(50),
        nullable=True,
        comment="Digest algorithm: SHA-256, SHA-384, SHA-512, SHA-1, MD5"
    )

    # Self-Signed & CA Verification
    is_self_signed = Column(Boolean, default=False, nullable=False, comment="True if Subject == Issuer and signature verified")
    is_ca = Column(Boolean, default=False, nullable=False, comment="True if BasicConstraints extension has cA=True")
    path_length_constraint = Column(Integer, nullable=True, comment="BasicConstraints pathlen")

    # Key Usages
    key_usage = Column(
        JSON,
        default=list,
        nullable=False,
        comment="List of KeyUsage flags (e.g. digitalSignature, keyEncipherment, keyCertSign)"
    )
    extended_key_usage = Column(
        JSON,
        default=list,
        nullable=False,
        comment="List of ExtendedKeyUsage OID names (e.g. serverAuth, clientAuth, emailProtection)"
    )

    # Cryptographic Fingerprints
    fingerprint_sha256 = Column(String(64), nullable=False, comment="SHA-256 fingerprint in lowercase hex")
    fingerprint_sha1 = Column(String(40), nullable=False, comment="SHA-1 fingerprint in lowercase hex")

    # Forensic Raw Data
    raw_der_base64 = Column(Text, nullable=True, comment="Base64-encoded raw DER certificate payload")
    parsing_status = Column(
        String(50),
        default="PARSED",
        nullable=False,
        comment="PARSED, CORRUPTED, INCOMPLETE, UNSUPPORTED"
    )
    error_message = Column(Text, nullable=True, comment="Error details if parsing was partial or corrupted")

    # Relationships
    job = relationship("AnalysisJob", back_populates="certificates", foreign_keys=[job_id])
    session = relationship("TcpSession", back_populates="certificates", foreign_keys=[tcp_session_id])
    tls_handshake = relationship("TlsHandshakeAnalysis", back_populates="certificates", foreign_keys=[tls_handshake_id])

    __table_args__ = (
        Index("ix_x509_cert_job_stream", "job_id", "tcp_stream"),
        Index("ix_x509_cert_validity_status", "validity_status"),
        Index("ix_x509_cert_self_signed", "is_self_signed"),
    )
