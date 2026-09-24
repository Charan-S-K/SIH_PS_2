"""
X.509 Certificate Forensic Analysis Engine.

Extracts, parses, and forensic-analyzes X.509 certificates observed during TLS handshakes.
Analyzes Subject, Issuer, Serial Number, Temporal Validity, SANs, Public Key Algorithm & Size,
Signature Algorithm & Digest, Self-Signed Status, and Certificate Chain Completeness.
Strictly evidence-first: uses Python cryptography, handles incomplete evidence explicitly,
and never invents certificate facts.
"""

import base64
import datetime
from typing import List, Dict, Any, Optional, Tuple
from datetime import timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, padding
from sqlalchemy.orm import Session

from app.models.certificate import X509CertificateAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.job import AnalysisJob


class X509Analyzer:
    """Forensic X.509 Certificate Analyzer."""

    @staticmethod
    def _extract_name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
        """Safely extract the first value for an X.509 Name attribute OID."""
        try:
            attrs = name.get_attributes_for_oid(oid)
            if attrs:
                val = attrs[0].value
                if isinstance(val, bytes):
                    return val.decode("utf-8", errors="replace")
                return str(val)
        except Exception:
            pass
        return None

    @staticmethod
    def parse_certificate_der(
        der_bytes: bytes,
        evaluation_time: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """
        Parse raw X.509 Certificate DER bytes into structured forensic properties.
        Zero-crash: catches corrupted/malformed DER and returns error status.
        """
        if not der_bytes:
            return {
                "parsing_status": "CORRUPTED",
                "error_message": "Empty certificate payload",
                "subject_dn": "UNKNOWN",
                "issuer_dn": "UNKNOWN",
                "serial_number": "UNKNOWN",
                "not_before": datetime.datetime.now(timezone.utc),
                "not_after": datetime.datetime.now(timezone.utc),
                "validity_days": 0,
                "validity_status": "UNKNOWN",
                "days_until_expiration": None,
                "sans": [],
                "public_key_algorithm": "UNKNOWN",
                "key_size_bits": None,
                "public_key_curve": None,
                "signature_algorithm": "UNKNOWN",
                "signature_digest": None,
                "is_self_signed": False,
                "is_ca": False,
                "path_length_constraint": None,
                "key_usage": [],
                "extended_key_usage": [],
                "fingerprint_sha256": "",
                "fingerprint_sha1": "",
                "raw_der_base64": "",
            }

        raw_b64 = base64.b64encode(der_bytes).decode("ascii")

        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as e:
            return {
                "parsing_status": "CORRUPTED",
                "error_message": f"Failed to parse X.509 DER: {str(e)}",
                "subject_dn": "CORRUPTED",
                "issuer_dn": "CORRUPTED",
                "serial_number": "CORRUPTED",
                "not_before": datetime.datetime.now(timezone.utc),
                "not_after": datetime.datetime.now(timezone.utc),
                "validity_days": 0,
                "validity_status": "CORRUPTED",
                "days_until_expiration": None,
                "sans": [],
                "public_key_algorithm": "UNKNOWN",
                "key_size_bits": None,
                "public_key_curve": None,
                "signature_algorithm": "UNKNOWN",
                "signature_digest": None,
                "is_self_signed": False,
                "is_ca": False,
                "path_length_constraint": None,
                "key_usage": [],
                "extended_key_usage": [],
                "fingerprint_sha256": "",
                "fingerprint_sha1": "",
                "raw_der_base64": raw_b64,
            }

        # 1. Subject Components
        subject = cert.subject
        try:
            subject_dn = subject.rfc4514_string()
        except Exception:
            subject_dn = str(subject)

        subject_cn = X509Analyzer._extract_name_attribute(subject, NameOID.COMMON_NAME)
        subject_org = X509Analyzer._extract_name_attribute(subject, NameOID.ORGANIZATION_NAME)
        subject_ou = X509Analyzer._extract_name_attribute(subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
        subject_country = X509Analyzer._extract_name_attribute(subject, NameOID.COUNTRY_NAME)
        subject_state = X509Analyzer._extract_name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME)
        subject_locality = X509Analyzer._extract_name_attribute(subject, NameOID.LOCALITY_NAME)

        # 2. Issuer Components
        issuer = cert.issuer
        try:
            issuer_dn = issuer.rfc4514_string()
        except Exception:
            issuer_dn = str(issuer)

        issuer_cn = X509Analyzer._extract_name_attribute(issuer, NameOID.COMMON_NAME)
        issuer_org = X509Analyzer._extract_name_attribute(issuer, NameOID.ORGANIZATION_NAME)
        issuer_ou = X509Analyzer._extract_name_attribute(issuer, NameOID.ORGANIZATIONAL_UNIT_NAME)
        issuer_country = X509Analyzer._extract_name_attribute(issuer, NameOID.COUNTRY_NAME)
        issuer_state = X509Analyzer._extract_name_attribute(issuer, NameOID.STATE_OR_PROVINCE_NAME)
        issuer_locality = X509Analyzer._extract_name_attribute(issuer, NameOID.LOCALITY_NAME)

        # 3. Serial Number (Formatted Hex)
        try:
            serial_int = cert.serial_number
            serial_hex = format(serial_int, "X")
            if len(serial_hex) % 2 != 0:
                serial_hex = "0" + serial_hex
            serial_formatted = ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))
        except Exception:
            serial_formatted = "UNKNOWN"

        # 4. Temporal Validity
        try:
            not_before = cert.not_valid_before_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        validity_days = max(0, (not_after - not_before).days)
        eval_dt = evaluation_time or datetime.datetime.now(timezone.utc)

        if eval_dt < not_before:
            validity_status = "NOT_YET_VALID"
            days_until_expiration = (not_after - eval_dt).days
        elif eval_dt > not_after:
            validity_status = "EXPIRED"
            days_until_expiration = (not_after - eval_dt).days  # negative
        else:
            validity_status = "VALID"
            days_until_expiration = max(0, (not_after - eval_dt).days)

        # 5. Subject Alternative Names (SANs)
        sans: List[Dict[str, str]] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append({"type": "DNS", "value": name.value})
                elif isinstance(name, x509.IPAddress):
                    sans.append({"type": "IP", "value": str(name.value)})
                elif isinstance(name, x509.RFC822Name):
                    sans.append({"type": "EMAIL", "value": name.value})
                elif isinstance(name, x509.UniformResourceIdentifier):
                    sans.append({"type": "URI", "value": name.value})
                else:
                    sans.append({"type": "OTHER", "value": str(name.value)})
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        # 6. Public Key Analysis
        pub_key = cert.public_key()
        pub_key_algo = "UNKNOWN"
        key_size_bits = None
        pub_key_curve = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_algo = "RSA"
            key_size_bits = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_algo = "EC"
            key_size_bits = pub_key.key_size
            try:
                pub_key_curve = pub_key.curve.name
            except Exception:
                pub_key_curve = None
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key_algo = "ED25519"
            key_size_bits = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            pub_key_algo = "ED448"
            key_size_bits = 448
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_algo = "DSA"
            key_size_bits = pub_key.key_size

        # 7. Signature Algorithm & Digest
        try:
            sig_algo_name = cert.signature_algorithm_oid._name
        except Exception:
            sig_algo_name = cert.signature_algorithm_oid.dotted_string

        sig_digest = None
        try:
            if cert.signature_hash_algorithm:
                sig_digest = cert.signature_hash_algorithm.name.upper()
                if sig_digest == "SHA256":
                    sig_digest = "SHA-256"
                elif sig_digest == "SHA384":
                    sig_digest = "SHA-384"
                elif sig_digest == "SHA512":
                    sig_digest = "SHA-512"
                elif sig_digest == "SHA1":
                    sig_digest = "SHA-1"
        except Exception:
            pass

        if not sig_digest:
            algo_lower = sig_algo_name.lower()
            if "sha256" in algo_lower or "sha-256" in algo_lower:
                sig_digest = "SHA-256"
            elif "sha384" in algo_lower or "sha-384" in algo_lower:
                sig_digest = "SHA-384"
            elif "sha512" in algo_lower or "sha-512" in algo_lower:
                sig_digest = "SHA-512"
            elif "sha1" in algo_lower or "sha-1" in algo_lower:
                sig_digest = "SHA-1"
            elif "md5" in algo_lower:
                sig_digest = "MD5"

        # 8. Self-Signed Verification
        is_self_signed = False
        if subject == issuer:
            try:
                if isinstance(pub_key, rsa.RSAPublicKey) and cert.signature_hash_algorithm:
                    pub_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                    is_self_signed = True
                elif isinstance(pub_key, ec.EllipticCurvePublicKey) and cert.signature_hash_algorithm:
                    pub_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(cert.signature_hash_algorithm),
                    )
                    is_self_signed = True
                elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                    pub_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                    )
                    is_self_signed = True
                else:
                    # Fallback for identical DNs if algorithm cannot be self-verified
                    is_self_signed = True
            except Exception:
                is_self_signed = False

        # 9. Basic Constraints & Key Usages
        is_ca = False
        path_length_constraint = None
        try:
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bool(bc_ext.value.ca)
            path_length_constraint = bc_ext.value.path_length
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        key_usages: List[str] = []
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            val = ku_ext.value
            attrs = [
                ("digital_signature", "digitalSignature"),
                ("content_commitment", "contentCommitment"),
                ("key_encipherment", "keyEncipherment"),
                ("data_encipherment", "dataEncipherment"),
                ("key_agreement", "keyAgreement"),
                ("key_cert_sign", "keyCertSign"),
                ("crl_sign", "cRLSign"),
                ("encipher_only", "encipherOnly"),
                ("decipher_only", "decipherOnly"),
            ]
            for attr_name, label in attrs:
                try:
                    if getattr(val, attr_name):
                        key_usages.append(label)
                except ValueError:
                    pass
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        extended_key_usages: List[str] = []
        try:
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            for oid in eku_ext.value:
                try:
                    extended_key_usages.append(oid._name)
                except Exception:
                    extended_key_usages.append(oid.dotted_string)
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        # 10. Cryptographic Fingerprints
        try:
            fp_sha256 = cert.fingerprint(hashes.SHA256()).hex().lower()
        except Exception:
            fp_sha256 = ""

        try:
            fp_sha1 = cert.fingerprint(hashes.SHA1()).hex().lower()
        except Exception:
            fp_sha1 = ""

        return {
            "parsing_status": "PARSED",
            "error_message": None,
            "subject_dn": subject_dn,
            "subject_cn": subject_cn,
            "subject_org": subject_org,
            "subject_ou": subject_ou,
            "subject_country": subject_country,
            "subject_state": subject_state,
            "subject_locality": subject_locality,
            "issuer_dn": issuer_dn,
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
            "issuer_ou": issuer_ou,
            "issuer_country": issuer_country,
            "issuer_state": issuer_state,
            "issuer_locality": issuer_locality,
            "serial_number": serial_formatted,
            "not_before": not_before,
            "not_after": not_after,
            "validity_days": validity_days,
            "validity_status": validity_status,
            "days_until_expiration": days_until_expiration,
            "sans": sans,
            "public_key_algorithm": pub_key_algo,
            "key_size_bits": key_size_bits,
            "public_key_curve": pub_key_curve,
            "signature_algorithm": sig_algo_name,
            "signature_digest": sig_digest,
            "is_self_signed": is_self_signed,
            "is_ca": is_ca,
            "path_length_constraint": path_length_constraint,
            "key_usage": key_usages,
            "extended_key_usage": extended_key_usages,
            "fingerprint_sha256": fp_sha256,
            "fingerprint_sha1": fp_sha1,
            "raw_der_base64": raw_b64,
        }

    @staticmethod
    def analyze_certificate_chain(
        parsed_certs: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze certificate chain hierarchy, order, and completeness.
        Index 0 is leaf / end-entity; subsequent items are intermediates or root.
        """
        chain_len = len(parsed_certs)
        if chain_len == 0:
            return []

        # Determine chain status
        if chain_len == 1:
            leaf = parsed_certs[0]
            if leaf.get("is_self_signed"):
                chain_status = "SELF_SIGNED_LEAF"
            else:
                chain_status = "INCOMPLETE_CHAIN"
        else:
            # Check sequential linkage: cert[i].issuer == cert[i+1].subject
            linked = True
            for i in range(chain_len - 1):
                cur_issuer = parsed_certs[i].get("issuer_dn")
                next_subject = parsed_certs[i + 1].get("subject_dn")
                if cur_issuer != next_subject:
                    linked = False
                    break

            last_cert = parsed_certs[-1]
            if linked:
                if last_cert.get("is_self_signed") and last_cert.get("is_ca"):
                    chain_status = "COMPLETE_CHAIN"
                else:
                    chain_status = "INCOMPLETE_CHAIN"
            else:
                chain_status = "BROKEN_CHAIN"

        results = []
        for idx, cert_info in enumerate(parsed_certs):
            item = dict(cert_info)
            item["chain_index"] = idx
            item["chain_length"] = chain_len
            item["chain_status"] = chain_status
            results.append(item)

        return results

    @classmethod
    def analyze_job_certificates(
        cls,
        db: Session,
        job_id: str,
        evaluation_time: Optional[datetime.datetime] = None,
    ) -> List[X509CertificateAnalysis]:
        """
        Perform complete X.509 certificate forensic analysis for all TLS handshakes in an AnalysisJob.
        Idempotent: removes any previous certificate analyses for the job before insertion.
        """
        # 1. Clean existing records for this job
        db.query(X509CertificateAnalysis).filter(X509CertificateAnalysis.job_id == job_id).delete()
        db.commit()

        # 2. Fetch all TLS handshakes for this job
        tls_handshakes = (
            db.query(TlsHandshakeAnalysis)
            .filter(TlsHandshakeAnalysis.job_id == job_id)
            .order_by(TlsHandshakeAnalysis.tcp_stream)
            .all()
        )

        created_records: List[X509CertificateAnalysis] = []

        for hs in tls_handshakes:
            raw_certs_b64 = hs.raw_certificates_bytes or []
            if not raw_certs_b64:
                continue

            parsed_list: List[Dict[str, Any]] = []
            for cert_b64 in raw_certs_b64:
                try:
                    der_bytes = base64.b64decode(cert_b64)
                    parsed = cls.parse_certificate_der(der_bytes, evaluation_time=evaluation_time)
                    parsed_list.append(parsed)
                except Exception as e:
                    parsed_list.append({
                        "parsing_status": "CORRUPTED",
                        "error_message": f"Base64 decoding failed: {str(e)}",
                        "subject_dn": "CORRUPTED",
                        "issuer_dn": "CORRUPTED",
                        "serial_number": "CORRUPTED",
                        "not_before": datetime.datetime.now(timezone.utc),
                        "not_after": datetime.datetime.now(timezone.utc),
                        "validity_days": 0,
                        "validity_status": "CORRUPTED",
                        "days_until_expiration": None,
                        "sans": [],
                        "public_key_algorithm": "UNKNOWN",
                        "key_size_bits": None,
                        "public_key_curve": None,
                        "signature_algorithm": "UNKNOWN",
                        "signature_digest": None,
                        "is_self_signed": False,
                        "is_ca": False,
                        "path_length_constraint": None,
                        "key_usage": [],
                        "extended_key_usage": [],
                        "fingerprint_sha256": "",
                        "fingerprint_sha1": "",
                        "raw_der_base64": cert_b64,
                    })

            # Chain analysis
            analyzed_chain = cls.analyze_certificate_chain(parsed_list)

            for cert_dict in analyzed_chain:
                record = X509CertificateAnalysis(
                    job_id=job_id,
                    tcp_stream=hs.tcp_stream,
                    tcp_session_id=hs.tcp_session_id,
                    tls_handshake_id=hs.id,
                    frame_number=hs.certificate_frame,
                    chain_index=cert_dict.get("chain_index", 0),
                    chain_length=cert_dict.get("chain_length", 1),
                    chain_status=cert_dict.get("chain_status", "UNKNOWN"),
                    subject_dn=cert_dict["subject_dn"],
                    subject_cn=cert_dict.get("subject_cn"),
                    subject_org=cert_dict.get("subject_org"),
                    subject_ou=cert_dict.get("subject_ou"),
                    subject_country=cert_dict.get("subject_country"),
                    subject_state=cert_dict.get("subject_state"),
                    subject_locality=cert_dict.get("subject_locality"),
                    issuer_dn=cert_dict["issuer_dn"],
                    issuer_cn=cert_dict.get("issuer_cn"),
                    issuer_org=cert_dict.get("issuer_org"),
                    issuer_ou=cert_dict.get("issuer_ou"),
                    issuer_country=cert_dict.get("issuer_country"),
                    issuer_state=cert_dict.get("issuer_state"),
                    issuer_locality=cert_dict.get("issuer_locality"),
                    serial_number=cert_dict["serial_number"],
                    not_before=cert_dict["not_before"],
                    not_after=cert_dict["not_after"],
                    validity_days=cert_dict["validity_days"],
                    validity_status=cert_dict["validity_status"],
                    days_until_expiration=cert_dict.get("days_until_expiration"),
                    sans=cert_dict.get("sans", []),
                    public_key_algorithm=cert_dict["public_key_algorithm"],
                    key_size_bits=cert_dict.get("key_size_bits"),
                    public_key_curve=cert_dict.get("public_key_curve"),
                    signature_algorithm=cert_dict["signature_algorithm"],
                    signature_digest=cert_dict.get("signature_digest"),
                    is_self_signed=cert_dict.get("is_self_signed", False),
                    is_ca=cert_dict.get("is_ca", False),
                    path_length_constraint=cert_dict.get("path_length_constraint"),
                    key_usage=cert_dict.get("key_usage", []),
                    extended_key_usage=cert_dict.get("extended_key_usage", []),
                    fingerprint_sha256=cert_dict["fingerprint_sha256"],
                    fingerprint_sha1=cert_dict["fingerprint_sha1"],
                    raw_der_base64=cert_dict.get("raw_der_base64"),
                    parsing_status=cert_dict.get("parsing_status", "PARSED"),
                    error_message=cert_dict.get("error_message"),
                )
                db.add(record)
                created_records.append(record)

        db.commit()
        for r in created_records:
            db.refresh(r)

        return created_records
