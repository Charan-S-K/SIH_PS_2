"""
Test PCAP Suite Evaluation & Verification Service .
Runs expected-vs-actual validation comparing processing results against curated test PCAP scenarios.
"""

import logging
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session

from app.fixtures.test_pcap_suite import CURATED_PCAP_SUITE, PcapSuiteScenario
from app.models.job import AnalysisJob
from app.models.finding import UnifiedFinding
from app.models.security_posture import SecurityPostureScore
from app.models.protocol import ProtocolIdentification
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.tls_anomaly import TlsAnomalyResult

logger = logging.getLogger(__name__)


class PcapSuiteRunnerService:
    """
    Service for executing and evaluating regression PCAP test suites against defined ground truth.
    """

    @staticmethod
    def list_scenarios() -> List[PcapSuiteScenario]:
        """Returns all curated test PCAP suite scenarios."""
        return list(CURATED_PCAP_SUITE.values())

    @staticmethod
    def get_scenario(scenario_id: str) -> Optional[PcapSuiteScenario]:
        """Retrieves scenario definition by ID."""
        return CURATED_PCAP_SUITE.get(scenario_id)

    @staticmethod
    def evaluate_job_against_scenario(
        db: Session,
        job_id: str,
        scenario_id: str
    ) -> Dict[str, Any]:
        """
        Evaluates an analyzed job against a target PCAP scenario's expected outcomes.
        Returns match score (0-100%), pass status, and detailed evaluation matrix.
        """
        scenario = PcapSuiteRunnerService.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario '{scenario_id}' not found in curated PCAP suite")

        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"AnalysisJob {job_id} not found")

        exp = scenario.expected_outcome
        discrepancies: List[str] = []
        checks_passed = 0
        total_checks = 5

        # 1. Protocol Detection Check
        actual_protos = db.query(ProtocolIdentification.protocol).filter(
            ProtocolIdentification.job_id == job_id
        ).distinct().all()
        actual_proto_list = [p[0].upper() for p in actual_protos] if actual_protos else ["UNKNOWN"]

        proto_matched = any(p in actual_proto_list for p in exp.expected_mail_protocols) or (
            "UNKNOWN" in exp.expected_mail_protocols and len(actual_proto_list) == 0
        )
        if proto_matched:
            checks_passed += 1
        else:
            discrepancies.append(
                f"Protocol mismatch: Expected {exp.expected_mail_protocols}, observed {actual_proto_list}"
            )

        # 2. TLS Version Check
        actual_tls = db.query(TlsHandshakeAnalysis.negotiated_version).filter(
            TlsHandshakeAnalysis.job_id == job_id
        ).distinct().all()
        actual_tls_list = [t[0] for t in actual_tls] if actual_tls else ["NONE"]

        tls_matched = any(t in actual_tls_list for t in exp.expected_tls_versions) or (
            "UNKNOWN" in exp.expected_tls_versions and ("NONE" in actual_tls_list or len(actual_tls_list) == 0)
        )
        if tls_matched:
            checks_passed += 1
        else:
            discrepancies.append(
                f"TLS Version mismatch: Expected {exp.expected_tls_versions}, observed {actual_tls_list}"
            )

        # 3. Security Findings & Rules Engine Check
        actual_findings = db.query(UnifiedFinding).filter(
            UnifiedFinding.job_id == job_id
        ).all()
        actual_rule_ids = [f.rule_id for f in actual_findings if f.rule_id]

        rule_matched = all(r in actual_rule_ids for r in exp.expected_rule_ids)
        if rule_matched:
            checks_passed += 1
        else:
            discrepancies.append(
                f"Rule findings mismatch: Expected rules {exp.expected_rule_ids}, triggered {actual_rule_ids}"
            )

        # 4. Security Posture Score Range Check
        posture_rec = db.query(SecurityPostureScore).filter(
            SecurityPostureScore.job_id == job_id
        ).first()
        actual_posture_score = posture_rec.overall_score if posture_rec else 100.0

        in_range = exp.expected_posture_range[0] <= actual_posture_score <= exp.expected_posture_range[1]
        if in_range:
            checks_passed += 1
        else:
            discrepancies.append(
                f"Posture score out of range: Expected [{exp.expected_posture_range[0]}-{exp.expected_posture_range[1]}], observed {actual_posture_score}"
            )

        # 5. Anomaly Detection Check
        anomaly_rec = db.query(TlsAnomalyResult).filter(
            TlsAnomalyResult.job_id == job_id,
            TlsAnomalyResult.is_anomalous == True
        ).first()
        actual_is_anomaly = anomaly_rec is not None

        if actual_is_anomaly == exp.is_anomaly_expected or not exp.is_anomaly_expected:
            checks_passed += 1
        else:
            discrepancies.append(
                f"Anomaly check mismatch: Expected {exp.is_anomaly_expected}, observed {actual_is_anomaly}"
            )

        match_score_percent = round((checks_passed / total_checks) * 100.0, 1)
        passed = match_score_percent >= 80.0

        return {
            "job_id": job_id,
            "scenario_id": scenario_id,
            "scenario_name": scenario.name,
            "category": scenario.category,
            "match_score_percent": match_score_percent,
            "passed": passed,
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "discrepancies": discrepancies,
            "observed_summary": {
                "detected_protocols": actual_proto_list,
                "tls_versions": actual_tls_list,
                "rule_ids_triggered": actual_rule_ids,
                "posture_score": actual_posture_score,
                "is_anomalous": actual_is_anomaly
            }
        }
