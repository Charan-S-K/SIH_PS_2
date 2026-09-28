"""
Prioritization & Explainability Engine for Stage 18.
Calculates transparent evidence-backed Risk Priority Scores (0-100) using configurable weights
for severity, confidence, exposure, affected sessions, and ML signals, alongside SHAP-like feature attributions.
"""

import ipaddress
import logging
from typing import Dict, List, Tuple, Any, Optional
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.finding import UnifiedFinding
from app.models.session import TcpSession
from app.models.ml_model import MlPredictionResult
from app.models.tls_anomaly import TlsAnomalyResult
from app.models.prioritization import FindingPrioritization, JobPrioritizationSummary
from app.schemas.prioritization import (
    PrioritizationWeightsConfig,
    FindingPrioritizationResponse,
    JobPrioritizationSummaryResponse
)

logger = logging.getLogger(__name__)

SEVERITY_SCORES = {
    "CRITICAL": 100.0,
    "HIGH": 75.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
    "INFO": 10.0
}


class PrioritizationEngineService:
    """
    Service for evidence-backed finding prioritization and feature attribution explanations.
    """

    def calculate_job_prioritization(
        self,
        db: Session,
        job_id: str,
        weights_config: Optional[PrioritizationWeightsConfig] = None
    ) -> JobPrioritizationSummaryResponse:
        """
        Calculates prioritization score & rankings for all findings/sessions in an analysis job.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Analysis job '{job_id}' not found")

        cfg = weights_config or PrioritizationWeightsConfig()
        
        # Delete previous prioritization results for this job
        db.query(FindingPrioritization).filter(FindingPrioritization.job_id == job_id).delete()
        db.query(JobPrioritizationSummary).filter(JobPrioritizationSummary.job_id == job_id).delete()
        db.commit()

        # Fetch findings for job
        findings = db.query(UnifiedFinding).filter(UnifiedFinding.job_id == job_id).all()
        sessions = db.query(TcpSession).filter(TcpSession.job_id == job_id).all()

        scored_items = []

        if findings:
            for f in findings:
                item_score = self._score_finding(db, f, sessions, cfg)
                scored_items.append(item_score)
        else:
            # Fallback: score sessions directly if no findings exist yet
            for s in sessions:
                item_score = self._score_session(db, s, cfg)
                scored_items.append(item_score)

        # Sort by priority score descending
        scored_items.sort(key=lambda x: x["priority_score"], reverse=True)

        crit_count = high_count = med_count = low_count = 0
        persisted_rows = []

        for rank_idx, item in enumerate(scored_items, start=1):
            level = item["priority_level"]
            if level == "CRITICAL_ACTION_REQUIRED":
                crit_count += 1
            elif level == "HIGH_PRIORITY":
                high_count += 1
            elif level == "MEDIUM_PRIORITY":
                med_count += 1
            else:
                low_count += 1

            row_db = FindingPrioritization(
                job_id=job_id,
                finding_id=item.get("finding_id"),
                tcp_stream=item.get("tcp_stream"),
                priority_score=round(item["priority_score"], 2),
                priority_level=level,
                rank=rank_idx,
                severity_score=round(item["severity_score"], 2),
                confidence_score=round(item["confidence_score"], 2),
                exposure_score=round(item["exposure_score"], 2),
                affected_score=round(item["affected_score"], 2),
                ml_risk_score=round(item["ml_risk_score"], 2),
                explanation_summary=item["explanation_summary"],
                factor_breakdown_json=item["factor_breakdown"],
                feature_attributions_json=item["feature_attributions"]
            )
            db.add(row_db)
            persisted_rows.append(row_db)

        weights_dict = {
            "weight_severity": cfg.weight_severity,
            "weight_confidence": cfg.weight_confidence,
            "weight_exposure": cfg.weight_exposure,
            "weight_affected": cfg.weight_affected,
            "weight_ml": cfg.weight_ml,
        }

        summary_db = JobPrioritizationSummary(
            job_id=job_id,
            total_findings_evaluated=len(scored_items),
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            weights_config_json=weights_dict
        )
        db.add(summary_db)
        db.commit()
        db.refresh(summary_db)

        # Build response list
        rankings_resp = [FindingPrioritizationResponse.model_validate(r) for r in persisted_rows]

        return JobPrioritizationSummaryResponse(
            id=summary_db.id,
            job_id=job_id,
            total_findings_evaluated=summary_db.total_findings_evaluated,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            weights_config_json=summary_db.weights_config_json,
            rankings=rankings_resp,
            created_at=summary_db.created_at
        )

    def _score_finding(
        self,
        db: Session,
        finding: UnifiedFinding,
        sessions: List[TcpSession],
        cfg: PrioritizationWeightsConfig
    ) -> Dict[str, Any]:
        """Calculates prioritization factors and feature attributions for a finding."""
        # 1. Severity Score
        sev_str = (finding.severity or "MEDIUM").upper()
        s_sev = SEVERITY_SCORES.get(sev_str, 50.0)

        # 2. Confidence Score
        conf_val = float(finding.confidence or 0.8)
        s_conf = conf_val * 100.0

        # 3. Exposure Score
        s_exp = 40.0  # Default internal
        related_sess = next((s for s in sessions if s.tcp_stream == finding.tcp_stream), None)
        if related_sess:
            if self._is_public_ip(related_sess.client_ip) or self._is_public_ip(related_sess.server_ip):
                s_exp = 100.0
            elif related_sess.server_port in [465, 587, 993, 995]:
                s_exp = 75.0

        # 4. Affected Score
        s_aff = min(100.0, len(sessions) * 15.0)

        # 5. ML Risk Signal Score
        s_ml = 10.0
        ml_pred = db.query(MlPredictionResult).filter(MlPredictionResult.job_id == finding.job_id).first()
        tls_anom = db.query(TlsAnomalyResult).filter(TlsAnomalyResult.job_id == finding.job_id).first()

        if ml_pred and ml_pred.risk_class in ["PLAINTEXT_LEAK", "DOWNGRADE_ATTACK", "ANOMALOUS"]:
            s_ml = 90.0
        elif tls_anom and tls_anom.is_anomalous:
            s_ml = 85.0

        # Total Weighted Score
        w_total = cfg.weight_severity + cfg.weight_confidence + cfg.weight_exposure + cfg.weight_affected + cfg.weight_ml
        p_score = (
            cfg.weight_severity * s_sev +
            cfg.weight_confidence * s_conf +
            cfg.weight_exposure * s_exp +
            cfg.weight_affected * s_aff +
            cfg.weight_ml * s_ml
        ) / w_total if w_total > 0 else 50.0

        p_score = min(100.0, max(0.0, p_score))

        # Assign Priority Level
        if p_score >= 75.0:
            level = "CRITICAL_ACTION_REQUIRED"
        elif p_score >= 55.0:
            level = "HIGH_PRIORITY"
        elif p_score >= 35.0:
            level = "MEDIUM_PRIORITY"
        else:
            level = "LOW_PRIORITY"

        # Feature Attributions (SHAP-equivalent marginal contributions)
        c_sev = round((cfg.weight_severity * s_sev) / w_total, 2)
        c_conf = round((cfg.weight_confidence * s_conf) / w_total, 2)
        c_exp = round((cfg.weight_exposure * s_exp) / w_total, 2)
        c_aff = round((cfg.weight_affected * s_aff) / w_total, 2)
        c_ml = round((cfg.weight_ml * s_ml) / w_total, 2)

        attributions = {
            "severity_impact_pts": c_sev,
            "confidence_impact_pts": c_conf,
            "exposure_impact_pts": c_exp,
            "affected_sessions_impact_pts": c_aff,
            "ml_signal_impact_pts": c_ml,
        }

        explanation = f"Finding '{finding.title}' rated {level} (Score: {round(p_score, 1)}/100). Driven by {sev_str} severity (+{c_sev} pts) and exposure (+{c_exp} pts)."

        return {
            "finding_id": finding.id,
            "tcp_stream": finding.tcp_stream,
            "priority_score": p_score,
            "priority_level": level,
            "severity_score": s_sev,
            "confidence_score": s_conf,
            "exposure_score": s_exp,
            "affected_score": s_aff,
            "ml_risk_score": s_ml,
            "explanation_summary": explanation,
            "factor_breakdown": {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": sev_str,
                "confidence": conf_val
            },
            "feature_attributions": attributions
        }

    def _score_session(
        self,
        db: Session,
        session: TcpSession,
        cfg: PrioritizationWeightsConfig
    ) -> Dict[str, Any]:
        """Fallback scoring for an individual TCP session."""
        s_sev = 50.0
        s_conf = 80.0
        s_exp = 100.0 if (self._is_public_ip(session.client_ip) or self._is_public_ip(session.server_ip)) else 40.0
        s_aff = 30.0
        s_ml = 20.0

        w_total = cfg.weight_severity + cfg.weight_confidence + cfg.weight_exposure + cfg.weight_affected + cfg.weight_ml
        p_score = (
            cfg.weight_severity * s_sev +
            cfg.weight_confidence * s_conf +
            cfg.weight_exposure * s_exp +
            cfg.weight_affected * s_aff +
            cfg.weight_ml * s_ml
        ) / w_total

        level = "HIGH_PRIORITY" if p_score >= 55.0 else "MEDIUM_PRIORITY"

        return {
            "finding_id": None,
            "tcp_stream": session.tcp_stream,
            "priority_score": p_score,
            "priority_level": level,
            "severity_score": s_sev,
            "confidence_score": s_conf,
            "exposure_score": s_exp,
            "affected_score": s_aff,
            "ml_risk_score": s_ml,
            "explanation_summary": f"Session Stream #{session.tcp_stream} evaluated with score {round(p_score, 1)}.",
            "factor_breakdown": {"tcp_stream": session.tcp_stream},
            "feature_attributions": {"exposure_impact_pts": round(cfg.weight_exposure * s_exp, 2)}
        }

    def _is_public_ip(self, ip_str: Optional[str]) -> bool:
        """Helper to determine if an IP address is public vs private."""
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except ValueError:
            return False
