import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  X,
  RefreshCw,
  Award,
  Server,
  FileCode,
  TrendingDown,
  ShieldCheck
} from 'lucide-react';
import {
  fetchJobSecurityPosture,
  calculateJobSecurityPosture,
  JobPostureDashboardResponse
} from '../services/api';

interface SecurityPostureModalProps {
  jobId: string;
  filename: string;
  isOpen: boolean;
  onClose: () => void;
  onInspectFinding?: (findingId: string) => void;
}

export const SecurityPostureModal: React.FC<SecurityPostureModalProps> = ({
  jobId,
  filename,
  isOpen,
  onClose,
}) => {
  const [dashboard, setDashboard] = useState<JobPostureDashboardResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [recalculating, setRecalculating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'OVERALL' | 'SERVERS' | 'LOGIC'>('OVERALL');

  const loadPosture = useCallback(async () => {
    setLoading(true);
    setError(null);
    const { data, error: err } = await fetchJobSecurityPosture(jobId);
    if (err) {
      setError(err);
    } else if (data) {
      setDashboard(data);
    }
    setLoading(false);
  }, [jobId]);

  const handleRecalculate = async () => {
    setRecalculating(true);
    setError(null);
    const { data, error: err } = await calculateJobSecurityPosture(jobId);
    if (err) {
      setError(err);
    } else if (data) {
      setDashboard(data);
    }
    setRecalculating(false);
  };

  useEffect(() => {
    if (isOpen && jobId) {
      loadPosture();
    }
  }, [isOpen, jobId, loadPosture]);

  if (!isOpen) return null;

  const getGradeBadge = (grade: string) => {
    switch (grade.toUpperCase()) {
      case 'EXCELLENT':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle className="w-4 h-4" />
            EXCELLENT POSTURE
          </span>
        );
      case 'GOOD':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <ShieldCheck className="w-4 h-4" />
            GOOD POSTURE
          </span>
        );
      case 'FAIR':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertCircle className="w-4 h-4" />
            FAIR POSTURE
          </span>
        );
      case 'POOR':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-bold bg-orange-500/10 text-orange-400 border border-orange-500/20">
            <AlertTriangle className="w-4 h-4" />
            POOR POSTURE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert className="w-4 h-4" />
            CRITICAL RISK
          </span>
        );
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    if (score >= 75) return 'text-blue-400 border-blue-500/30 bg-blue-500/10';
    if (score >= 50) return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    if (score >= 25) return 'text-orange-400 border-orange-500/30 bg-orange-500/10';
    return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
  };

  const posture = dashboard?.job_posture;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 rounded-lg border border-emerald-500/20 text-emerald-400">
              <Award className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                Explainable Security Posture Engine
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono">
                  Stage 12
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                0-100 posture scoring, risk level ratings, and mathematical deduction breakdown for <span className="font-mono text-slate-300">{filename}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRecalculate}
              disabled={recalculating || loading}
              className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${recalculating ? 'animate-spin' : ''}`} />
              {recalculating ? 'Calculating...' : 'Recalculate Posture'}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {error && (
            <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 text-sm flex items-center gap-2">
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {loading ? (
            <div className="flex flex-col items-center justify-center py-12 text-slate-400 gap-3">
              <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
              <span className="text-xs font-mono">Aggregating explainable security posture ratings...</span>
            </div>
          ) : posture ? (
            <>
              {/* Scorecard Hero Panel */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Score Dial / Rating Box */}
                <div className={`p-6 rounded-xl border flex flex-col items-center justify-center text-center space-y-2 ${getScoreColor(posture.overall_score)}`}>
                  <span className="text-xs font-semibold uppercase tracking-wider">Overall Posture Score</span>
                  <div className="text-5xl font-black font-mono tracking-tight">{posture.overall_score}<span className="text-2xl text-slate-500 font-normal">/100</span></div>
                  <div>{getGradeBadge(posture.overall_grade)}</div>
                </div>

                {/* Summary Rationale Box */}
                <div className="md:col-span-2 bg-slate-950/60 border border-slate-800 p-5 rounded-xl flex flex-col justify-between space-y-3">
                  <div>
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <Info className="w-3.5 h-3.5 text-indigo-400" />
                      Security Posture Executive Rationale
                    </h3>
                    <p className="text-xs text-slate-200 leading-relaxed font-sans">
                      {posture.posture_summary}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-4 text-xs font-mono pt-3 border-t border-slate-800/80 text-slate-400">
                    <div>
                      <span className="text-slate-500">Base Score: </span>
                      <span className="text-emerald-400 font-semibold">100</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Total Deduction: </span>
                      <span className="text-rose-400 font-semibold">-{posture.total_deduction} pts</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Evaluated Findings: </span>
                      <span className="text-slate-200 font-semibold">{posture.findings_count}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Tab Navigation */}
              <div className="flex border-b border-slate-800 gap-2">
                <button
                  onClick={() => setActiveTab('OVERALL')}
                  className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                    activeTab === 'OVERALL'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Job Posture & Deductions ({posture.contributing_findings.length})
                </button>
                <button
                  onClick={() => setActiveTab('SERVERS')}
                  className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                    activeTab === 'SERVERS'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Target Server Breakdown ({dashboard.server_postures.length})
                </button>
                <button
                  onClick={() => setActiveTab('LOGIC')}
                  className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                    activeTab === 'LOGIC'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Documented Scoring Logic
                </button>
              </div>

              {/* Tab 1: Contributing Findings & Point Deductions Table */}
              {activeTab === 'OVERALL' && (
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <TrendingDown className="w-3.5 h-3.5 text-rose-400" />
                    Contributing Risk Drivers & Deductions
                  </h4>

                  {posture.contributing_findings.length === 0 ? (
                    <div className="p-8 text-center border border-dashed border-slate-800 rounded-lg text-slate-400 text-xs">
                      No point deductions recorded. The security posture is uncompromised.
                    </div>
                  ) : (
                    <div className="overflow-x-auto border border-slate-800 rounded-lg">
                      <table className="w-full text-left text-xs text-slate-300">
                        <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                          <tr>
                            <th className="py-2.5 px-3">Deduction</th>
                            <th className="py-2.5 px-3">Severity</th>
                            <th className="py-2.5 px-3">Finding Title</th>
                            <th className="py-2.5 px-3">Rule ID</th>
                            <th className="py-2.5 px-3">Confidence</th>
                            <th className="py-2.5 px-3">Scoring Rationale</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          {posture.contributing_findings.map((item) => (
                            <tr key={item.finding_id} className="hover:bg-slate-900/40">
                              <td className="py-2.5 px-3 text-rose-400 font-bold">-{item.deduction_points} pts</td>
                              <td className="py-2.5 px-3 font-sans">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  item.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                                  item.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                                  item.severity === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                                  'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                                }`}>
                                  {item.severity}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 text-slate-100 font-sans font-medium">{item.title}</td>
                              <td className="py-2.5 px-3 text-purple-300 text-[11px]">{item.rule_id || '—'}</td>
                              <td className="py-2.5 px-3 text-slate-300 font-sans">
                                {(item.confidence * 100).toFixed(0)}% ({item.confidence_label})
                              </td>
                              <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">{item.rationale}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: Server-Level Posture Breakdown */}
              {activeTab === 'SERVERS' && (
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-indigo-400" />
                    Target Server IP Security Postures
                  </h4>

                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs text-slate-300">
                      <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                        <tr>
                          <th className="py-2.5 px-3">Target Server IP</th>
                          <th className="py-2.5 px-3">TCP Streams</th>
                          <th className="py-2.5 px-3">Posture Score</th>
                          <th className="py-2.5 px-3">Grade & Risk Level</th>
                          <th className="py-2.5 px-3">Critical Findings</th>
                          <th className="py-2.5 px-3">High Findings</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {dashboard.server_postures.map((srv) => (
                          <tr key={srv.server_ip} className="hover:bg-slate-900/40">
                            <td className="py-2.5 px-3 text-indigo-300 font-bold">{srv.server_ip}</td>
                            <td className="py-2.5 px-3 text-slate-300">{srv.stream_count} streams</td>
                            <td className="py-2.5 px-3 font-bold text-slate-100">{srv.overall_score}/100</td>
                            <td className="py-2.5 px-3 font-sans">{getGradeBadge(srv.overall_grade)}</td>
                            <td className="py-2.5 px-3 font-bold text-rose-400">{srv.critical_findings_count}</td>
                            <td className="py-2.5 px-3 font-bold text-orange-400">{srv.high_findings_count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Tab 3: Documented Scoring Logic Explanation */}
              {activeTab === 'LOGIC' && (
                <div className="bg-slate-950/60 border border-slate-800 p-5 rounded-xl space-y-4 text-xs font-sans leading-relaxed text-slate-300">
                  <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-emerald-400" />
                    Documented Posture Calculation & Scoring Model
                  </h4>

                  <div className="space-y-2">
                    <p className="font-semibold text-emerald-400">1. Base Score & Deduction Formula:</p>
                    <p className="bg-slate-900 p-3 rounded border border-slate-800 font-mono text-[11px] text-slate-200">
                      Overall Score = MAX(0, 100 - SUM(Severity Weight * Finding Confidence))
                    </p>
                  </div>

                  <div className="space-y-2">
                    <p className="font-semibold text-emerald-400">2. Severity Weights (Max Deduction per Unique Finding):</p>
                    <ul className="grid grid-cols-2 md:grid-cols-4 gap-2 font-mono text-[11px]">
                      <li className="bg-rose-500/10 border border-rose-500/20 p-2 rounded text-rose-300">CRITICAL: -35 pts</li>
                      <li className="bg-orange-500/10 border border-orange-500/20 p-2 rounded text-orange-300">HIGH: -20 pts</li>
                      <li className="bg-amber-500/10 border border-amber-500/20 p-2 rounded text-amber-300">MEDIUM: -10 pts</li>
                      <li className="bg-blue-500/10 border border-blue-500/20 p-2 rounded text-blue-300">LOW: -3 pts</li>
                    </ul>
                  </div>

                  <div className="space-y-2">
                    <p className="font-semibold text-emerald-400">3. Risk Level Thresholds:</p>
                    <ul className="list-disc list-inside space-y-1 font-mono text-[11px] text-slate-300">
                      <li>Score 90–100: <span className="text-emerald-400">EXCELLENT</span> (LOW Risk)</li>
                      <li>Score 75–89: <span className="text-blue-400">GOOD</span> (LOW Risk)</li>
                      <li>Score 50–74: <span className="text-amber-400">FAIR</span> (MEDIUM Risk)</li>
                      <li>Score 25–49: <span className="text-orange-400">POOR</span> (HIGH Risk)</li>
                      <li>Score 0–24: <span className="text-rose-400">CRITICAL_RISK</span> (CRITICAL Risk)</li>
                    </ul>
                  </div>

                  <div className="space-y-2">
                    <p className="font-semibold text-emerald-400">4. Deduplication & Critical Override Guardrails:</p>
                    <p>
                      Identical finding fingerprints across sessions are deduplicated so duplicate observations do not unfairly double-count deductions.
                      If any active CRITICAL vulnerability is confirmed (Confidence ≥ 0.8), overall posture score is capped at 40 (CRITICAL_RISK).
                    </p>
                  </div>
                </div>
              )}
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
};
