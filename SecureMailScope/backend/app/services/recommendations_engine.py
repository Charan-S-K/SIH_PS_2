"""
Recommendations Engine Service for Stage 19.
Generates deterministic, evidence-backed remediation recommendations directly tied to security rules,
findings, affected components, exact configuration snippets, and compliance frameworks.
"""

import logging
from typing import Dict, List, Tuple, Any, Optional
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.finding import UnifiedFinding
from app.models.rule_result import CryptoRuleResult
from app.models.recommendation import RemediationRecommendation
from app.schemas.recommendation import (
    RecommendationResponse,
    JobRecommendationsSummaryResponse
)

logger = logging.getLogger(__name__)


# Deterministic Rule Remediation Catalog
RECOMMENDATION_CATALOG = {
    "RULE-SSLV3-DEPRECATED": {
        "title": "Enforce TLS 1.2+ & Disable SSLv3/TLS 1.0/1.1 Protocols",
        "severity": "CRITICAL",
        "affected_component": "Postfix SMTP Server & Dovecot IMAP/POP3 Server",
        "recommended_action": (
            "# Postfix Configuration (/etc/postfix/main.cf)\n"
            "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n"
            "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n"
            "smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n\n"
            "# Dovecot Configuration (/etc/dovecot/conf.d/10-ssl.conf)\n"
            "ssl_min_protocol = TLSv1.2"
        ),
        "rationale": "SSL 3.0 and TLS 1.0/1.1 are vulnerable to POODLE, BEAST, and CRIME attacks and are formally deprecated per IETF RFC 8996.",
        "implementation_effort": "LOW",
        "compliance_frameworks": ["NIST SP 800-52 Rev 2", "PCI-DSS 4.0 Req 4.2", "CIS Postfix Benchmark 1.1"]
    },
    "RULE-PLAINTEXT-AUTH": {
        "title": "Mandate TLS Encryption Prior to User Authentication",
        "severity": "CRITICAL",
        "affected_component": "SMTP/IMAP Authentication Gateway",
        "recommended_action": (
            "# Postfix Configuration (/etc/postfix/main.cf)\n"
            "smtpd_tls_auth_only = yes\n"
            "smtpd_sasl_auth_enable = yes\n\n"
            "# Dovecot Configuration (/etc/dovecot/conf.d/10-auth.conf)\n"
            "disable_plaintext_auth = yes"
        ),
        "rationale": "Cleartext authentication over unencrypted streams allows passive network eavesdroppers to intercept credentials.",
        "implementation_effort": "LOW",
        "compliance_frameworks": ["NIST SP 800-52 Rev 2", "HIPAA Security Rule §164.312(e)(1)"]
    },
    "RULE-CERT-EXPIRED": {
        "title": "Renew & Deploy Valid X.509 TLS Server Certificate",
        "severity": "HIGH",
        "affected_component": "X.509 PKI Certificate Store",
        "recommended_action": (
            "# Request Let's Encrypt / Automated ACME Renewal\n"
            "certbot renew --post-hook 'systemctl reload postfix dovecot'\n\n"
            "# Verify Certificate Expiry\n"
            "openssl x509 -enddate -noout -in /etc/ssl/certs/mailserver.crt"
        ),
        "rationale": "Expired X.509 certificates break chain of trust verification, triggering browser/client warnings and risking MitM interception.",
        "implementation_effort": "MEDIUM",
        "compliance_frameworks": ["CA/Browser Forum Baseline Requirements", "PCI-DSS 4.0 Req 4.2.1"]
    },
    "RULE-RSA-WEAK-KEY": {
        "title": "Upgrade RSA Key Length to 2048-bit Minimum (3072-bit Recommended)",
        "severity": "HIGH",
        "affected_component": "OpenSSL Cryptographic Key Pair",
        "recommended_action": (
            "# Generate 3072-bit RSA Private Key\n"
            "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /etc/ssl/private/mail.key\n\n"
            "# Update Certificate Signing Request\n"
            "openssl req -new -key /etc/ssl/private/mail.key -out /etc/ssl/certs/mail.csr"
        ),
        "rationale": "RSA keys shorter than 2048 bits provide less than 112 bits of security margin and are vulnerable to factorization attacks.",
        "implementation_effort": "MEDIUM",
        "compliance_frameworks": ["NIST SP 800-57 Part 1 Rev 5", "CNSA Suite 1.0"]
    },
    "RULE-WEAK-CIPHER": {
        "title": "Disable Weak & Legacy Cipher Suites (RC4, 3DES, EXPORT)",
        "severity": "HIGH",
        "affected_component": "TLS Cipher Suite Selection Engine",
        "recommended_action": (
            "# Postfix Recommended Cipher Suite String\n"
            "smtpd_tls_ciphers = high\n"
            "smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, 3DES\n\n"
            "# Dovecot Cipher String\n"
            "ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"
        ),
        "rationale": "Weak ciphers such as RC4, 3DES (Sweet32), or EXPORT ciphers can be decrypted by adversary eavesdroppers.",
        "implementation_effort": "LOW",
        "compliance_frameworks": ["NIST SP 800-52 Rev 2", "PCI-DSS 4.0 Req 4.2"]
    }
}

DEFAULT_FALLBACK_RECOMMENDATION = {
    "title": "Enforce Mail Server Cryptographic Posture Best Practices",
    "severity": "MEDIUM",
    "affected_component": "Mail Transfer Agent (MTA) & Cryptographic Stack",
    "recommended_action": (
        "Review MTA TLS configuration directives.\n"
        "Ensure TLS 1.2+ mandatory enforcement and disable weak ciphers."
    ),
    "rationale": "General security hardening recommended based on passive network traffic analysis.",
    "implementation_effort": "MEDIUM",
    "compliance_frameworks": ["CIS Mail Server Benchmark"]
}


class RecommendationsEngineService:
    """
    Service for generating deterministic, evidence-backed remediation recommendations.
    """

    def generate_job_recommendations(
        self,
        db: Session,
        job_id: str
    ) -> JobRecommendationsSummaryResponse:
        """
        Generates deterministic remediation recommendations for all findings in a job.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Analysis job '{job_id}' not found")

        # Delete previous recommendations for job
        db.query(RemediationRecommendation).filter(RemediationRecommendation.job_id == job_id).delete()
        db.commit()

        findings = db.query(UnifiedFinding).filter(UnifiedFinding.job_id == job_id).all()
        crypto_rules = db.query(CryptoRuleResult).filter(CryptoRuleResult.job_id == job_id).all()

        rule_ids = set()
        for f in findings:
            if f.rule_id:
                rule_ids.add((f.rule_id, f.id, f.severity, f.title))
        for r in crypto_rules:
            if r.rule_id:
                rule_ids.add((r.rule_id, None, r.severity, r.rule_name))

        persisted = []
        crit_c = high_c = med_c = low_c = 0

        if rule_ids:
            for rule_id, finding_id, sev, title in rule_ids:
                cat = RECOMMENDATION_CATALOG.get(rule_id, DEFAULT_FALLBACK_RECOMMENDATION)
                
                s_level = (sev or cat["severity"]).upper()
                if s_level == "CRITICAL":
                    crit_c += 1
                elif s_level == "HIGH":
                    high_c += 1
                elif s_level == "MEDIUM":
                    med_c += 1
                else:
                    low_c += 1

                rec_db = RemediationRecommendation(
                    job_id=job_id,
                    finding_id=finding_id,
                    rule_id=rule_id,
                    title=cat["title"],
                    severity=s_level,
                    affected_component=cat["affected_component"],
                    recommended_action=cat["recommended_action"],
                    rationale=cat["rationale"],
                    implementation_effort=cat["implementation_effort"],
                    compliance_frameworks=cat["compliance_frameworks"],
                    triggering_evidence_json={"rule_id": rule_id, "triggering_title": title}
                )
                db.add(rec_db)
                persisted.append(rec_db)
        else:
            # Fallback baseline recommendation
            med_c += 1
            rec_db = RemediationRecommendation(
                job_id=job_id,
                rule_id="RULE-BASELINE-POSTURE",
                title=DEFAULT_FALLBACK_RECOMMENDATION["title"],
                severity="MEDIUM",
                affected_component=DEFAULT_FALLBACK_RECOMMENDATION["affected_component"],
                recommended_action=DEFAULT_FALLBACK_RECOMMENDATION["recommended_action"],
                rationale=DEFAULT_FALLBACK_RECOMMENDATION["rationale"],
                implementation_effort=DEFAULT_FALLBACK_RECOMMENDATION["implementation_effort"],
                compliance_frameworks=DEFAULT_FALLBACK_RECOMMENDATION["compliance_frameworks"]
            )
            db.add(rec_db)
            persisted.append(rec_db)

        db.commit()

        resp_list = [RecommendationResponse.model_validate(r) for r in persisted]

        return JobRecommendationsSummaryResponse(
            job_id=job_id,
            total_recommendations=len(persisted),
            critical_count=crit_c,
            high_count=high_c,
            medium_count=med_c,
            low_count=low_c,
            recommendations=resp_list
        )
