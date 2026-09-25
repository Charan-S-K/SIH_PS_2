"""
Security Posture Engine Service for Stage 12.
Calculates explainable session-, server-, and job-level security posture scores, risk ratings,
and mathematical deduction breakdowns based on validated forensic findings.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.session import TcpSession
from app.models.finding import UnifiedFinding
from app.models.security_posture import SecurityPostureScore
from app.schemas.security_posture import (
    ContributingFindingItem,
    SecurityPostureResponse,
    ServerPostureSummaryItem,
    JobPostureDashboardResponse,
)

logger = logging.getLogger(__name__)


SEVERITY_DEDUCTION_WEIGHTS = {
    "CRITICAL": 35.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 3.0,
    "INFO": 0.0,
}


class SecurityPostureEngine:
    """
    Explainable posture calculation engine aggregating findings into transparent 0-100 scores.
    """

    @staticmethod
    def calculate_grade_and_risk(score: int, has_critical_finding: bool = False) -> Tuple[str, str]:
        """
        Maps numeric score (0-100) and critical flags to overall grade and risk level.
        """
        if has_critical_finding:
            return "CRITICAL_RISK", "CRITICAL"

        if score >= 90:
            return "EXCELLENT", "LOW"
        elif score >= 75:
            return "GOOD", "LOW"
        elif score >= 50:
            return "FAIR", "MEDIUM"
        elif score >= 25:
            return "POOR", "HIGH"
        else:
            return "CRITICAL_RISK", "CRITICAL"

    def calculate_job_posture(
        self,
        db: Session,
        job_id: str,
        force_recalculate: bool = True
    ) -> JobPostureDashboardResponse:
        """
        Calculates explainable job-level and server-level posture scores and persists results.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Analysis job '{job_id}' not found")

        # Return existing score if not forcing recalculation
        if not force_recalculate:
            existing_job_score = (
                db.query(SecurityPostureScore)
                .filter(SecurityPostureScore.job_id == job_id, SecurityPostureScore.tcp_stream.is_(None), SecurityPostureScore.server_ip.is_(None))
                .first()
            )
            if existing_job_score:
                return self._assemble_dashboard_response(db, job_id, existing_job_score)

        # Clear existing posture records for this job if recalculating
        db.query(SecurityPostureScore).filter(SecurityPostureScore.job_id == job_id).delete()
        db.commit()

        # Query unique findings for job
        all_findings = db.query(UnifiedFinding).filter(UnifiedFinding.job_id == job_id).all()
        unique_findings = [f for f in all_findings if not f.is_duplicate]

        # Calculate Overall Job Posture
        total_deduction = 0.0
        contributing_items: List[ContributingFindingItem] = []
        has_critical = False
        cat_deductions: Dict[str, float] = {}

        for f in unique_findings:
            weight = SEVERITY_DEDUCTION_WEIGHTS.get(f.severity.upper(), 0.0)
            confidence = f.confidence if f.confidence is not None else 1.0
            deduction = round(weight * confidence, 1)

            if f.severity.upper() == "CRITICAL" and confidence >= 0.8:
                has_critical = True

            total_deduction += deduction
            cat = f.finding_type
            cat_deductions[cat] = cat_deductions.get(cat, 0.0) + deduction

            rationale = f"Deducted {deduction} pts for {f.severity} severity finding ({f.title}) with {f.confidence_label} confidence"
            contributing_items.append(
                ContributingFindingItem(
                    finding_id=f.id,
                    rule_id=f.rule_id,
                    title=f.title,
                    severity=f.severity,
                    confidence=confidence,
                    confidence_label=f.confidence_label,
                    deduction_points=deduction,
                    rationale=rationale
                )
            )

        # Calculate numeric score capped between 0 and 100
        raw_score = max(0, int(round(100.0 - total_deduction)))
        overall_grade, risk_level = self.calculate_grade_and_risk(raw_score, has_critical)

        # Build explainable summary text
        summary_lines = []
        summary_lines.append(f"Overall security posture evaluated as {overall_grade} (Score: {raw_score}/100, Risk: {risk_level}).")
        if len(unique_findings) == 0:
            summary_lines.append("No security posture flaws or cryptographic weaknesses identified.")
        else:
            top_contributors = sorted(contributing_items, key=lambda x: x.deduction_points, reverse=True)[:3]
            top_names = [f"'{item.title}' (-{item.deduction_points} pts)" for item in top_contributors]
            summary_lines.append(f"Primary risk drivers: {', '.join(top_names)}.")
            if has_critical:
                summary_lines.append("Critical vulnerability detected; posture rating capped at CRITICAL_RISK.")

        posture_summary = " ".join(summary_lines)

        scoring_breakdown = {
            "base_score": 100,
            "total_deduction": round(total_deduction, 1),
            "category_deductions": cat_deductions,
            "unique_findings_evaluated": len(unique_findings),
            "total_findings_correlated": len(all_findings),
            "has_critical_override": has_critical
        }

        job_score_db = SecurityPostureScore(
            job_id=job_id,
            overall_score=raw_score,
            overall_grade=overall_grade,
            risk_level=risk_level,
            posture_summary=posture_summary,
            total_deduction=round(total_deduction, 1),
            findings_count=len(unique_findings),
            contributing_findings_json=[item.model_dump() for item in contributing_items],
            scoring_breakdown_json=scoring_breakdown
        )
        db.add(job_score_db)
        db.commit()
        db.refresh(job_score_db)

        # Calculate Per-Server Posture Ratings
        self._calculate_server_postures(db, job_id, all_findings)

        return self._assemble_dashboard_response(db, job_id, job_score_db)

    def _calculate_server_postures(
        self,
        db: Session,
        job_id: str,
        all_findings: List[UnifiedFinding]
    ) -> List[SecurityPostureScore]:
        """
        Aggregates security posture ratings grouped by target server IP.
        """
        sessions = db.query(TcpSession).filter(TcpSession.job_id == job_id).all()
        session_server_map = {s.tcp_stream: s.server_ip for s in sessions if s.server_ip}
        server_streams: Dict[str, List[int]] = {}
        for s in sessions:
            if s.server_ip:
                server_streams.setdefault(s.server_ip, []).append(s.tcp_stream)

        server_scores_db: List[SecurityPostureScore] = []

        for server_ip, streams in server_streams.items():
            server_findings = [
                f for f in all_findings if f.tcp_stream in streams and not f.is_duplicate
            ]

            deduction = 0.0
            crit_count = 0
            high_count = 0
            server_contribs = []

            for f in server_findings:
                weight = SEVERITY_DEDUCTION_WEIGHTS.get(f.severity.upper(), 0.0)
                conf = f.confidence if f.confidence is not None else 1.0
                pts = round(weight * conf, 1)
                deduction += pts

                if f.severity == "CRITICAL":
                    crit_count += 1
                elif f.severity == "HIGH":
                    high_count += 1

                server_contribs.append(
                    ContributingFindingItem(
                        finding_id=f.id,
                        rule_id=f.rule_id,
                        title=f.title,
                        severity=f.severity,
                        confidence=conf,
                        confidence_label=f.confidence_label,
                        deduction_points=pts,
                        rationale=f"Server {server_ip} deduction for {f.title}"
                    ).model_dump()
                )

            s_score = max(0, int(round(100.0 - deduction)))
            s_grade, s_risk = self.calculate_grade_and_risk(s_score, crit_count > 0)
            s_summary = f"Server {server_ip} security posture rated {s_grade} ({s_score}/100) across {len(streams)} TCP streams."

            server_posture_db = SecurityPostureScore(
                job_id=job_id,
                server_ip=server_ip,
                overall_score=s_score,
                overall_grade=s_grade,
                risk_level=s_risk,
                posture_summary=s_summary,
                total_deduction=round(deduction, 1),
                findings_count=len(server_findings),
                contributing_findings_json=server_contribs,
                scoring_breakdown_json={"stream_count": len(streams), "critical_count": crit_count, "high_count": high_count}
            )
            server_scores_db.append(server_posture_db)

        db.add_all(server_scores_db)
        db.commit()
        return server_scores_db

    def _assemble_dashboard_response(
        self,
        db: Session,
        job_id: str,
        job_score_db: SecurityPostureScore
    ) -> JobPostureDashboardResponse:
        """
        Assembles complete JobPostureDashboardResponse containing overall posture and server items.
        """
        raw_contribs = job_score_db.contributing_findings_json or []
        contrib_items = [ContributingFindingItem(**item) for item in raw_contribs]

        job_posture_resp = SecurityPostureResponse(
            id=job_score_db.id,
            job_id=job_score_db.job_id,
            tcp_stream=job_score_db.tcp_stream,
            server_ip=job_score_db.server_ip,
            overall_score=job_score_db.overall_score,
            overall_grade=job_score_db.overall_grade,
            risk_level=job_score_db.risk_level,
            posture_summary=job_score_db.posture_summary,
            total_deduction=job_score_db.total_deduction,
            findings_count=job_score_db.findings_count,
            contributing_findings=contrib_items,
            scoring_breakdown=job_score_db.scoring_breakdown_json or {},
            created_at=job_score_db.created_at
        )

        server_records = (
            db.query(SecurityPostureScore)
            .filter(SecurityPostureScore.job_id == job_id, SecurityPostureScore.server_ip.isnot(None))
            .all()
        )

        server_items: List[ServerPostureSummaryItem] = []
        for s in server_records:
            bkd = s.scoring_breakdown_json or {}
            server_items.append(
                ServerPostureSummaryItem(
                    server_ip=s.server_ip or "0.0.0.0",
                    stream_count=bkd.get("stream_count", 1),
                    overall_score=s.overall_score,
                    overall_grade=s.overall_grade,
                    risk_level=s.risk_level,
                    critical_findings_count=bkd.get("critical_count", 0),
                    high_findings_count=bkd.get("high_count", 0)
                )
            )

        return JobPostureDashboardResponse(
            job_id=job_id,
            job_posture=job_posture_resp,
            server_postures=server_items,
            evaluated_at=datetime.now(timezone.utc)
        )
