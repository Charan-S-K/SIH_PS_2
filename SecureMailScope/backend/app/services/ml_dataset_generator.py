"""
ML Dataset Generator Service for Stage 13.
Generates reproducible synthetic datasets of secure and weak email/TLS communication scenarios,
extracts standardized feature vectors, assigns ground truth security labels, and documents labeling rationale.
"""

import random
import logging
from typing import Dict, List, Tuple, Any
from sqlalchemy.orm import Session

from app.models.ml_dataset import MlDatasetBatch, MlDatasetRecord
from app.schemas.ml_dataset import MlDatasetGenerateRequest

logger = logging.getLogger(__name__)


LABEL_MAP = {
    "SECURE": (0, "No cryptographic or protocol flaws detected. End-to-end encryption with modern TLS parameters."),
    "WEAK_CRYPTO": (1, "Cryptographic weakness present: deprecated TLS version, weak cipher, or invalid/expired certificate."),
    "PLAINTEXT_LEAK": (2, "Cleartext authentication or sensitive credentials transmitted over unencrypted TCP stream."),
    "DOWNGRADE_ATTACK": (3, "Opportunistic TLS downgrade or STARTTLS stripping injection detected."),
    "ANOMALOUS": (4, "Traffic exhibits anomalous packet rate, payload variance, or protocol framing anomalies.")
}


class MlDatasetGenerator:
    """
    Service for generating reproducible synthetic training/testing datasets for email security ML models.
    """

    def generate_dataset_batch(self, db: Session, req: MlDatasetGenerateRequest) -> MlDatasetBatch:
        """
        Generates a complete reproducible synthetic dataset batch and persists records to the database.
        """
        # Set seed for reproducible random generation
        rng = random.Random(req.seed)

        batch = MlDatasetBatch(
            name=req.name or "Synthetic Email Security Dataset",
            seed=req.seed,
            sample_count=req.sample_count,
            description=req.description
        )
        db.add(batch)
        db.commit()
        db.refresh(batch)

        counts = {
            "SECURE": 0,
            "WEAK_CRYPTO": 0,
            "PLAINTEXT_LEAK": 0,
            "DOWNGRADE_ATTACK": 0,
            "ANOMALOUS": 0
        }

        records: List[MlDatasetRecord] = []

        scenarios = [
            "SECURE_SMTPS_TLS13",
            "SECURE_STARTTLS_TLS12",
            "WEAK_TLS10_DEPRECATED",
            "WEAK_3DES_CIPHER",
            "PLAINTEXT_SMTP_AUTH",
            "STARTTLS_STRIPPED_DOWNGRADE",
            "EXPIRED_SELF_SIGNED_CERT",
            "ANOMALOUS_BURST_TRAFFIC"
        ]

        if not req.include_weak_scenarios:
            scenarios = ["SECURE_SMTPS_TLS13", "SECURE_STARTTLS_TLS12"]

        for i in range(req.sample_count):
            scenario = rng.choice(scenarios)
            record_data = self._generate_sample_by_scenario(scenario, i + 1, rng)

            ground_truth = record_data["ground_truth_label"]
            counts[ground_truth] = counts.get(ground_truth, 0) + 1

            record_db = MlDatasetRecord(
                batch_id=batch.id,
                sample_index=i + 1,
                scenario_name=scenario,
                protocol=record_data["protocol"],
                tls_version=record_data["tls_version"],
                cipher_suite=record_data["cipher_suite"],
                auth_mechanism=record_data["auth_mechanism"],
                packet_count=record_data["packet_count"],
                duration_seconds=record_data["duration_seconds"],
                total_bytes=record_data["total_bytes"],
                ground_truth_label=ground_truth,
                label_code=LABEL_MAP[ground_truth][0],
                label_rationale=record_data["label_rationale"],
                features_json=record_data["features_json"]
            )
            records.append(record_db)

        db.add_all(records)

        # Update batch summary counts
        batch.secure_samples_count = counts["SECURE"]
        batch.weak_crypto_count = counts["WEAK_CRYPTO"]
        batch.plaintext_leak_count = counts["PLAINTEXT_LEAK"]
        batch.downgrade_attack_count = counts["DOWNGRADE_ATTACK"]
        batch.anomalous_count = counts["ANOMALOUS"]

        db.commit()
        db.refresh(batch)
        return batch

    def _generate_sample_by_scenario(
        self,
        scenario: str,
        index: int,
        rng: random.Random
    ) -> Dict[str, Any]:
        """
        Generates individual synthetic sample parameters and extracted feature vector based on scenario template.
        """
        if scenario == "SECURE_SMTPS_TLS13":
            protocol = "SMTPS"
            tls_version = "TLS 1.3"
            cipher = "TLS_AES_256_GCM_SHA384"
            auth = "XOAUTH2"
            pkts = rng.randint(15, 35)
            duration = round(rng.uniform(0.5, 2.5), 2)
            bytes_trans = rng.randint(2500, 6000)
            ground_truth = "SECURE"
            rationale = "Modern SMTPS with TLS 1.3, AES-256-GCM cipher, and XOAUTH2 token authentication."

            features = {
                "protocol_code": 2,  # SMTPS
                "tls_version_code": 5,  # TLS 1.3
                "cipher_strength_bits": 256,
                "is_starttls_used": 0,
                "is_auth_encrypted": 1,
                "cert_validity_code": 1,  # Valid
                "packet_count": pkts,
                "duration_seconds": duration,
                "total_bytes": bytes_trans,
                "avg_packet_size": round(bytes_trans / pkts, 1)
            }

        elif scenario == "SECURE_STARTTLS_TLS12":
            protocol = "SMTP"
            tls_version = "TLS 1.2"
            cipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            auth = "CRAM-MD5"
            pkts = rng.randint(20, 45)
            duration = round(rng.uniform(1.0, 3.5), 2)
            bytes_trans = rng.randint(3000, 7500)
            ground_truth = "SECURE"
            rationale = "Successful STARTTLS upgrade on port 587 to TLS 1.2 with ECDHE PFS."

            features = {
                "protocol_code": 1,  # SMTP
                "tls_version_code": 4,  # TLS 1.2
                "cipher_strength_bits": 128,
                "is_starttls_used": 1,
                "is_auth_encrypted": 1,
                "cert_validity_code": 1,
                "packet_count": pkts,
                "duration_seconds": duration,
                "total_bytes": bytes_trans,
                "avg_packet_size": round(bytes_trans / pkts, 1)
            }

        elif scenario == "WEAK_TLS10_DEPRECATED":
            protocol = "SMTPS"
            tls_version = "TLS 1.0"
            cipher = "TLS_RSA_WITH_AES_128_CBC_SHA"
            auth = "LOGIN"
            pkts = rng.randint(12, 30)
            duration = round(rng.uniform(0.8, 2.8), 2)
            bytes_trans = rng.randint(2000, 5000)
            ground_truth = "WEAK_CRYPTO"
            rationale = "Deprecated TLS 1.0 protocol negotiated; vulnerable to BEAST and POODLE attacks."

            features = {
                "protocol_code": 2,
                "tls_version_code": 2,  # TLS 1.0
                "cipher_strength_bits": 128,
                "is_starttls_used": 0,
                "is_auth_encrypted": 1,
                "cert_validity_code": 1,
                "packet_count": pkts,
                "duration_seconds": duration,
                "total_bytes": bytes_trans,
                "avg_packet_size": round(bytes_trans / pkts, 1)
            }

        elif scenario == "WEAK_3DES_CIPHER":
            protocol = "IMAPS"
            tls_version = "TLS 1.2"
            cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            auth = "PLAIN"
            pkts = rng.randint(18, 40)
            duration = round(rng.uniform(1.2, 4.0), 2)
            bytes_trans = rng.randint(3500, 8000)
            ground_truth = "WEAK_CRYPTO"
            rationale = "Legacy 3DES CBC cipher suite enabled (64-bit block size vulnerable to Sweet32)."

            features = {
                "protocol_code": 4,  # IMAPS
                "tls_version_code": 4,
                "cipher_strength_bits": 112,  # 3DES effective 112 bits
                "is_starttls_used": 0,
                "is_auth_encrypted": 1,
                "cert_validity_code": 1,
                "packet_count": pkts,
                "duration_seconds": duration,
                "total_bytes": bytes_trans,
                "avg_packet_size": round(bytes_trans / pkts, 1)
            }

        elif scenario == "PLAINTEXT_SMTP_AUTH":
            protocol = "SMTP"
            tls_version = None
            cipher = None
            auth = "PLAIN"
            pkts = rng.randint(8, 20)
            duration = round(rng.uniform(0.3, 1.5), 2)
            bytes_trans = rng.randint(800, 2500)
            ground_truth = "PLAINTEXT_LEAK"
            rationale = "Cleartext AUTH PLAIN executed over unencrypted TCP port 25."

            features = {
                "protocol_code": 1,  # SMTP
                "tls_version_code": 0,  # None
                "cipher_strength_bits": 0,
                "is_starttls_used": 0,
                "is_auth_encrypted": 0,
                "cert_validity_code": 0,
                "packet_count": pkts,
                "duration_seconds": duration,
                "total_bytes": bytes_trans,
                "avg_packet_size": round(bytes_trans / pkts, 1)
            }

        elif scenario == "STARTTLS_STRIPPED_DOWNGRADE":
            protocol = "SMTP"
            tls_version = None
            cipher = None
            auth = "PLAIN"
            pkts = rng.randint(10, 25)
            duration = round(rng.uniform(0.5, 2.0), 2)
            bytes_trans = rng.randint(1200, 3000)
            ground_truth = "DOWNGRADE_ATTACK"
            rationale = "STARTTLS command advertised but server response modified by MitM actor."

            features = {
                "protocol_code": 1,
                "tls_version_code": 0,
                "cipher_strength_bits": 0,
                "is_starttls_used": 1,  # Requested but stripped
                "is_auth_encrypted": 0,
                "cert_validity_code": 0,
                "packet_count": pkts,
                "duration_seconds": duration,
                "total_bytes": bytes_trans,
                "avg_packet_size": round(bytes_trans / pkts, 1)
            }

        elif scenario == "EXPIRED_SELF_SIGNED_CERT":
            protocol = "POP3S"
            tls_version = "TLS 1.2"
            cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            auth = "LOGIN"
            pkts = rng.randint(14, 30)
            duration = round(rng.uniform(0.6, 2.2), 2)
            bytes_trans = rng.randint(2200, 5200)
            ground_truth = "WEAK_CRYPTO"
            rationale = "POP3S server presented an expired, self-signed X.509 certificate."

            features = {
                "protocol_code": 6,  # POP3S
                "tls_version_code": 4,
                "cipher_strength_bits": 256,
                "is_starttls_used": 0,
                "is_auth_encrypted": 1,
                "cert_validity_code": 3,  # Self-signed/expired
                "packet_count": pkts,
                "duration_seconds": duration,
                "total_bytes": bytes_trans,
                "avg_packet_size": round(bytes_trans / pkts, 1)
            }

        else:  # ANOMALOUS_BURST_TRAFFIC
            protocol = "SMTP"
            tls_version = "TLS 1.2"
            cipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            auth = "UNKNOWN"
            pkts = rng.randint(150, 400)  # High anomalous packet count
            duration = round(rng.uniform(0.1, 0.4), 2)  # High burst rate
            bytes_trans = rng.randint(15000, 50000)
            ground_truth = "ANOMALOUS"
            rationale = "Anomalous traffic pattern: extreme packet burst rate (>300 pkts/0.3s) with malformed protocol framing."

            features = {
                "protocol_code": 1,
                "tls_version_code": 4,
                "cipher_strength_bits": 128,
                "is_starttls_used": 0,
                "is_auth_encrypted": 1,
                "cert_validity_code": 1,
                "packet_count": pkts,
                "duration_seconds": duration,
                "total_bytes": bytes_trans,
                "avg_packet_size": round(bytes_trans / pkts, 1)
            }

        return {
            "protocol": protocol,
            "tls_version": tls_version,
            "cipher_suite": cipher,
            "auth_mechanism": auth,
            "packet_count": pkts,
            "duration_seconds": duration,
            "total_bytes": bytes_trans,
            "ground_truth_label": ground_truth,
            "label_rationale": rationale,
            "features_json": features
        }
