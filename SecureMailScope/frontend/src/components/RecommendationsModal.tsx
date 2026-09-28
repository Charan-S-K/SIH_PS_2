import React, { useState, useEffect, useCallback } from 'react';
import {
  Wrench,
  X,
  AlertTriangle,
  Play,
  Copy,
  Check,
  ShieldCheck,
  Server,
  FileCode
} from 'lucide-react';
import {
  generateJobRecommendations,
  getJobRecommendationsSummary,
  JobRecommendationsSummaryItem
} from '../services/api';

interface RecommendationsModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentJobId?: string;
}

export const RecommendationsModal: React.FC<RecommendationsModalProps> = ({ isOpen, onClose, currentJobId }) => {
  const [targetJobId, setTargetJobId] = useState<string>(currentJobId || '');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<JobRecommendationsSummaryItem | null>(null);
  const [activeSeverityFilter, setActiveSeverityFilter] = useState<string>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    if (currentJobId) {
      setTargetJobId(currentJobId);
    }
  }, [currentJobId]);

  const fetchRecommendations = useCallback(async (jobId: string) => {
    if (!jobId.trim()) return;
    setLoading(true);
    setError(null);

    const { data, error: err } = await getJobRecommendationsSummary(jobId.trim());
    if (err) {
      setError(err);
    } else if (data) {
      setSummary(data);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    if (isOpen && currentJobId) {
      fetchRecommendations(currentJobId);
    }
  }, [isOpen, currentJobId, fetchRecommendations]);

  const handleGenerate = async () => {
    if (!targetJobId.trim()) {
      setError("Please provide a valid Job ID.");
      return;
    }

    setLoading(true);
    setError(null);

    const { data, error: genErr } = await generateJobRecommendations(targetJobId.trim());
    if (genErr) {
      setError(genErr);
    } else if (data) {
      setSummary(data);
    }
    setLoading(false);
  };

  const copySnippet = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (!isOpen) return null;

  const filteredRecs = summary ? summary.recommendations.filter(r => {
    if (activeSeverityFilter === 'ALL') return true;
    return r.severity === activeSeverityFilter;
  }) : [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col text-slate-100">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-500/20 border border-blue-500/30 rounded-lg text-blue-400">
              <Wrench className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                Stage 19: Remediation & Hardening Recommendations Engine
                <span className="text-xs bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded font-mono">
                  Deterministic Guidance
                </span>
              </h2>
              <p className="text-xs text-slate-400">Step-by-step MTA configuration snippets & compliance framework mappings</p>
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

          {/* Trigger Input */}
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-300">
              <Server className="w-4 h-4 text-blue-400" />
              <span>Generate Step-by-Step Remediation Snippets for Analysis Job</span>
            </div>

            <div className="flex items-center gap-2 w-full md:w-auto">
              <input
                type="text"
                placeholder="Job ID..."
                value={targetJobId}
                onChange={(e) => setTargetJobId(e.target.value)}
                className="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono w-full md:w-64"
              />
              <button
                onClick={handleGenerate}
                disabled={loading || !targetJobId.trim()}
                className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-900/50 text-white font-medium text-xs rounded-lg transition flex items-center gap-1.5 shrink-0 shadow-md shadow-blue-950/40"
              >
                {loading ? (
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5 fill-current" />
                )}
                Generate Recommendations
              </button>
            </div>
          </div>

          {/* Recommendations Content */}
          {summary ? (
            <div className="space-y-5">
              {/* Metric Cards */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <div className="bg-slate-800/50 border border-slate-700/60 p-3.5 rounded-xl">
                  <span className="text-[11px] text-slate-400 font-medium">Total Actions</span>
                  <div className="text-xl font-bold font-mono text-slate-100 mt-0.5">
                    {summary.total_recommendations}
                  </div>
                </div>

                <div className="bg-red-950/30 border border-red-500/40 p-3.5 rounded-xl">
                  <span className="text-[11px] text-red-300 font-medium">Critical Priority</span>
                  <div className="text-xl font-bold font-mono text-red-400 mt-0.5">
                    {summary.critical_count}
                  </div>
                </div>

                <div className="bg-amber-950/30 border border-amber-500/40 p-3.5 rounded-xl">
                  <span className="text-[11px] text-amber-300 font-medium">High Priority</span>
                  <div className="text-xl font-bold font-mono text-amber-400 mt-0.5">
                    {summary.high_count}
                  </div>
                </div>

                <div className="bg-blue-950/30 border border-blue-500/40 p-3.5 rounded-xl">
                  <span className="text-[11px] text-blue-300 font-medium">Medium Priority</span>
                  <div className="text-xl font-bold font-mono text-blue-400 mt-0.5">
                    {summary.medium_count}
                  </div>
                </div>

                <div className="bg-slate-800/50 border border-slate-700/60 p-3.5 rounded-xl">
                  <span className="text-[11px] text-slate-400 font-medium">Low Priority</span>
                  <div className="text-xl font-bold font-mono text-slate-300 mt-0.5">
                    {summary.low_count}
                  </div>
                </div>
              </div>

              {/* Filter Tabs */}
              <div className="flex border-b border-slate-800 text-xs">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setActiveSeverityFilter(filter)}
                    className={`py-2 px-3 font-medium border-b-2 transition ${
                      activeSeverityFilter === filter
                        ? 'border-blue-500 text-blue-400 font-bold'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {filter}
                  </button>
                ))}
              </div>

              {/* Recommendation Cards List */}
              <div className="space-y-4">
                {filteredRecs.length === 0 ? (
                  <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
                    No recommendations matching severity filter '{activeSeverityFilter}'.
                  </div>
                ) : (
                  filteredRecs.map((rec) => (
                    <div
                      key={rec.id}
                      className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4 shadow-lg hover:border-slate-700 transition"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="text-sm font-semibold text-slate-100">{rec.title}</h3>
                            <span className="text-[10px] bg-slate-800 text-purple-300 border border-slate-700 px-2 py-0.5 rounded font-mono">
                              {rec.rule_id}
                            </span>
                          </div>

                          <div className="flex items-center gap-2 mt-2 text-xs">
                            <span className={`px-2 py-0.5 rounded font-mono font-semibold text-[10px] ${
                              rec.severity === 'CRITICAL'
                                ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                : rec.severity === 'HIGH'
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                            }`}>
                              {rec.severity}
                            </span>

                            <span className="bg-slate-800/80 text-slate-300 border border-slate-700 px-2.5 py-0.5 rounded text-[11px]">
                              {rec.affected_component}
                            </span>

                            <span className="text-[11px] text-slate-400 font-mono">
                              Effort: <strong className="text-slate-200">{rec.implementation_effort}</strong>
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Rationale */}
                      <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/40 p-3 rounded-lg border border-slate-800/80">
                        <strong className="text-slate-400 mr-1">Rationale:</strong>
                        {rec.rationale}
                      </p>

                      {/* Recommended Configuration Code Snippet */}
                      <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden">
                        <div className="px-3 py-1.5 bg-slate-800/60 border-b border-slate-800 flex items-center justify-between text-[11px] text-slate-300 font-mono">
                          <span className="flex items-center gap-1.5 text-blue-300 font-medium">
                            <FileCode className="w-3.5 h-3.5 text-blue-400" />
                            Configuration Snippet & Remediation Action
                          </span>
                          <button
                            onClick={() => copySnippet(rec.id, rec.recommended_action)}
                            className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1 text-[10px] transition"
                          >
                            {copiedId === rec.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                Copied!
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3 text-slate-400" />
                                Copy Snippet
                              </>
                            )}
                          </button>
                        </div>
                        <pre className="p-3 text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                          {rec.recommended_action}
                        </pre>
                      </div>

                      {/* Compliance Frameworks */}
                      {rec.compliance_frameworks && rec.compliance_frameworks.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px]">
                          <ShieldCheck className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          <span className="text-slate-400 font-medium mr-1">Compliance Controls:</span>
                          {rec.compliance_frameworks.map((fw, idx) => (
                            <span key={idx} className="bg-slate-800 text-slate-300 border border-slate-700 px-2 py-0.5 rounded font-mono text-[10px]">
                              {fw}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : (
            <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
              Enter a Job ID above and click "Generate Recommendations" to view deterministic remediation actions.
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
