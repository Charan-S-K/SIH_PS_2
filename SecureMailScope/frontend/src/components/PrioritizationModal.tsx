import React, { useState, useEffect, useCallback } from 'react';
import {
  ListOrdered,
  X,
  Sliders,
  AlertTriangle,
  Play
} from 'lucide-react';
import {
  calculateJobPrioritization,
  getJobPrioritizationSummary,
  JobPrioritizationSummaryItem
} from '../services/api';

interface PrioritizationModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentJobId?: string;
}

export const PrioritizationModal: React.FC<PrioritizationModalProps> = ({ isOpen, onClose, currentJobId }) => {
  const [targetJobId, setTargetJobId] = useState<string>(currentJobId || '');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<JobPrioritizationSummaryItem | null>(null);

  // Configurable weights state
  const [wSeverity, setWSeverity] = useState<number>(0.35);
  const [wConfidence, setWConfidence] = useState<number>(0.20);
  const [wExposure, setWExposure] = useState<number>(0.20);
  const [wAffected, setWAffected] = useState<number>(0.15);
  const [wMl, setWMl] = useState<number>(0.10);

  useEffect(() => {
    if (currentJobId) {
      setTargetJobId(currentJobId);
    }
  }, [currentJobId]);

  const fetchPrioritization = useCallback(async (jobId: string) => {
    if (!jobId.trim()) return;
    setLoading(true);
    setError(null);

    const { data, error: err } = await getJobPrioritizationSummary(jobId.trim());
    if (err) {
      setError(err);
    } else if (data) {
      setSummary(data);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    if (isOpen && currentJobId) {
      fetchPrioritization(currentJobId);
    }
  }, [isOpen, currentJobId, fetchPrioritization]);

  const handleRecalculate = async () => {
    if (!targetJobId.trim()) {
      setError("Please provide a valid Job ID.");
      return;
    }

    setLoading(true);
    setError(null);

    const weights = {
      weight_severity: wSeverity,
      weight_confidence: wConfidence,
      weight_exposure: wExposure,
      weight_affected: wAffected,
      weight_ml: wMl,
    };

    const { data, error: calcErr } = await calculateJobPrioritization(targetJobId.trim(), weights);
    if (calcErr) {
      setError(calcErr);
    } else if (data) {
      setSummary(data);
    }
    setLoading(false);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col text-slate-100">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-amber-500/20 border border-amber-500/30 rounded-lg text-amber-400">
              <ListOrdered className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                Stage 18: Prioritization & Explainability Engine
                <span className="text-xs bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded font-mono">
                  Evidence-Backed Ranking
                </span>
              </h2>
              <p className="text-xs text-slate-400">Risk Priority Score calculation & SHAP-like feature attributions</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {error && (
            <div className="p-3 bg-red-950/60 border border-red-500/40 rounded-lg text-red-200 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Controls & Weights Configuration */}
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-5 space-y-4">
            <div className="flex flex-col md:flex-row items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-amber-300 flex items-center gap-2">
                <Sliders className="w-4 h-4" />
                Configurable Prioritization Scoring Weights
              </h3>

              <div className="flex items-center gap-2 w-full md:w-auto">
                <input
                  type="text"
                  placeholder="Job ID..."
                  value={targetJobId}
                  onChange={(e) => setTargetJobId(e.target.value)}
                  className="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono w-full md:w-64"
                />
                <button
                  onClick={handleRecalculate}
                  disabled={loading || !targetJobId.trim()}
                  className="px-4 py-1.5 bg-amber-600 hover:bg-amber-500 disabled:bg-amber-900/50 text-white font-medium text-xs rounded-lg transition flex items-center gap-1.5 shrink-0"
                >
                  {loading ? (
                    <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Play className="w-3.5 h-3.5 fill-current" />
                  )}
                  Calculate Rankings
                </button>
              </div>
            </div>

            {/* Weights Sliders */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 pt-2 text-xs">
              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg">
                <span className="text-slate-400 font-medium">Severity ({(wSeverity * 100).toFixed(0)}%)</span>
                <input
                  type="range"
                  min="0.0"
                  max="0.8"
                  step="0.05"
                  value={wSeverity}
                  onChange={(e) => setWSeverity(parseFloat(e.target.value))}
                  className="w-full h-1 bg-slate-700 rounded appearance-none cursor-pointer accent-amber-500 mt-2"
                />
              </div>

              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg">
                <span className="text-slate-400 font-medium">Confidence ({(wConfidence * 100).toFixed(0)}%)</span>
                <input
                  type="range"
                  min="0.0"
                  max="0.5"
                  step="0.05"
                  value={wConfidence}
                  onChange={(e) => setWConfidence(parseFloat(e.target.value))}
                  className="w-full h-1 bg-slate-700 rounded appearance-none cursor-pointer accent-amber-500 mt-2"
                />
              </div>

              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg">
                <span className="text-slate-400 font-medium">Exposure ({(wExposure * 100).toFixed(0)}%)</span>
                <input
                  type="range"
                  min="0.0"
                  max="0.5"
                  step="0.05"
                  value={wExposure}
                  onChange={(e) => setWExposure(parseFloat(e.target.value))}
                  className="w-full h-1 bg-slate-700 rounded appearance-none cursor-pointer accent-amber-500 mt-2"
                />
              </div>

              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg">
                <span className="text-slate-400 font-medium">Affected ({(wAffected * 100).toFixed(0)}%)</span>
                <input
                  type="range"
                  min="0.0"
                  max="0.4"
                  step="0.05"
                  value={wAffected}
                  onChange={(e) => setWAffected(parseFloat(e.target.value))}
                  className="w-full h-1 bg-slate-700 rounded appearance-none cursor-pointer accent-amber-500 mt-2"
                />
              </div>

              <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg">
                <span className="text-slate-400 font-medium">ML Risk ({(wMl * 100).toFixed(0)}%)</span>
                <input
                  type="range"
                  min="0.0"
                  max="0.4"
                  step="0.05"
                  value={wMl}
                  onChange={(e) => setWMl(parseFloat(e.target.value))}
                  className="w-full h-1 bg-slate-700 rounded appearance-none cursor-pointer accent-amber-500 mt-2"
                />
              </div>
            </div>
          </div>

          {/* Results Summary & Rankings */}
          {summary ? (
            <div className="space-y-4">
              {/* Summary Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl">
                  <span className="text-xs text-slate-400 font-medium">Evaluated Items</span>
                  <div className="text-xl font-bold font-mono text-slate-100 mt-1">
                    {summary.total_findings_evaluated}
                  </div>
                </div>

                <div className="bg-red-950/30 border border-red-500/40 p-4 rounded-xl">
                  <span className="text-xs text-red-300 font-medium">Critical Priority</span>
                  <div className="text-xl font-bold font-mono text-red-400 mt-1">
                    {summary.critical_count}
                  </div>
                </div>

                <div className="bg-amber-950/30 border border-amber-500/40 p-4 rounded-xl">
                  <span className="text-xs text-amber-300 font-medium">High Priority</span>
                  <div className="text-xl font-bold font-mono text-amber-400 mt-1">
                    {summary.high_count}
                  </div>
                </div>

                <div className="bg-blue-950/30 border border-blue-500/40 p-4 rounded-xl">
                  <span className="text-xs text-blue-300 font-medium">Medium / Low Priority</span>
                  <div className="text-xl font-bold font-mono text-blue-400 mt-1">
                    {summary.medium_count + summary.low_count}
                  </div>
                </div>
              </div>

              {/* Ranked Findings List */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-slate-200">Ranked Evidence Findings & Factor Attributions</h3>

                {summary.rankings.length === 0 ? (
                  <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
                    No findings evaluated for this job.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {summary.rankings.map((item) => (
                      <div
                        key={item.id}
                        className="p-4 bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl transition space-y-3"
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex items-center gap-3">
                            <span className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-mono font-bold text-xs text-amber-400">
                              #{item.rank}
                            </span>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-slate-100 text-sm">
                                  {item.factor_breakdown_json?.title || `Stream #${item.tcp_stream}`}
                                </span>
                                <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-semibold ${
                                  item.priority_level === 'CRITICAL_ACTION_REQUIRED'
                                    ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                    : item.priority_level === 'HIGH_PRIORITY'
                                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                    : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                                }`}>
                                  {item.priority_level}
                                </span>
                              </div>
                              <p className="text-xs text-slate-400 mt-0.5">{item.explanation_summary}</p>
                            </div>
                          </div>

                          <div className="text-right shrink-0">
                            <span className="text-[10px] text-slate-400 uppercase tracking-wide">Risk Priority Score</span>
                            <div className="text-xl font-bold font-mono text-amber-400">{item.priority_score.toFixed(1)} / 100</div>
                          </div>
                        </div>

                        {/* Feature Attributions Progress Bar */}
                        {item.feature_attributions_json && (
                          <div className="pt-2 border-t border-slate-800/80 grid grid-cols-5 gap-2 text-[11px] font-mono text-slate-400">
                            <div>
                              Sev: <span className="text-slate-200">+{item.feature_attributions_json.severity_impact_pts}</span>
                            </div>
                            <div>
                              Conf: <span className="text-slate-200">+{item.feature_attributions_json.confidence_impact_pts}</span>
                            </div>
                            <div>
                              Exp: <span className="text-slate-200">+{item.feature_attributions_json.exposure_impact_pts}</span>
                            </div>
                            <div>
                              Aff: <span className="text-slate-200">+{item.feature_attributions_json.affected_sessions_impact_pts}</span>
                            </div>
                            <div>
                              ML: <span className="text-slate-200">+{item.feature_attributions_json.ml_signal_impact_pts}</span>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
              Enter a Job ID above and click "Calculate Rankings" to evaluate evidence-backed prioritization scores.
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-800 flex justify-end bg-slate-950/60">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs rounded-lg transition"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
