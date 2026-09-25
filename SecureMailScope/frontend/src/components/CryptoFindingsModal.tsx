import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  X,
  RefreshCw,
  Search,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  ShieldCheck,
  FileCode,
  BookOpen
} from 'lucide-react';
import {
  fetchJobCryptoFindings,
  evaluateJobRules,
  CryptoFinding,
  JobFindingsSummary
} from '../services/api';

interface CryptoFindingsModalProps {
  jobId: string;
  filename: string;
  isOpen: boolean;
  onClose: () => void;
  onInspectPackets?: (streamId: number) => void;
}

export const CryptoFindingsModal: React.FC<CryptoFindingsModalProps> = ({
  jobId,
  filename,
  isOpen,
  onClose,
  onInspectPackets,
}) => {
  const [summary, setSummary] = useState<JobFindingsSummary | null>(null);
  const [findings, setFindings] = useState<CryptoFinding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    const { data, error: err } = await fetchJobCryptoFindings(jobId);
    if (err) {
      setError(err);
    } else if (data) {
      setSummary(data.summary);
      setFindings(data.findings);
    }
    setLoading(false);
  }, [jobId]);

  const handleReevaluate = async () => {
    setEvaluating(true);
    setError(null);
    const { data, error: err } = await evaluateJobRules(jobId, true);
    if (err) {
      setError(err);
    } else if (data) {
      setSummary(data.summary);
      setFindings(data.findings);
    }
    setEvaluating(false);
  };

  useEffect(() => {
    if (isOpen && jobId) {
      loadFindings();
    }
  }, [isOpen, jobId, loadFindings]);

  if (!isOpen) return null;

  // Filter findings
  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      searchQuery === '' ||
      f.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.remediation && f.remediation.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesSeverity =
      severityFilter === 'ALL' || f.severity.toUpperCase() === severityFilter;

    const matchesCategory =
      categoryFilter === 'ALL' || f.category.toUpperCase() === categoryFilter;

    return matchesSearch && matchesSeverity && matchesCategory;
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950 text-red-300 border border-red-800/60">
            <AlertTriangle className="w-3 h-3 mr-1" /> CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950 text-amber-300 border border-amber-800/60">
            <ShieldAlert className="w-3 h-3 mr-1" /> HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-yellow-950 text-yellow-300 border border-yellow-800/60">
            <AlertCircle className="w-3 h-3 mr-1" /> MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-950 text-blue-300 border border-blue-800/60">
            <Info className="w-3 h-3 mr-1" /> LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700">
            <Info className="w-3 h-3 mr-1" /> INFO
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl w-full max-w-6xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-indigo-950/60 border border-indigo-700/50 rounded-lg text-indigo-400">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg font-bold text-white">Cryptographic Security Findings</h2>
                <span className="text-xs px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/50 font-mono">
                  Stage 09 Rules Engine
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Target Capture: <span className="text-slate-200 font-mono">{filename}</span> &bull; Job ID:{' '}
                <span className="text-slate-400 font-mono">{jobId.substring(0, 8)}...</span>
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={handleReevaluate}
              disabled={evaluating || loading}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium transition shadow-sm"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${evaluating ? 'animate-spin' : ''}`} />
              <span>{evaluating ? 'Evaluating...' : 'Re-Evaluate Rules'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {error && (
            <div className="p-4 rounded-xl bg-red-950/60 border border-red-800/60 text-red-200 text-xs flex items-center justify-between">
              <span>{error}</span>
              <button onClick={loadFindings} className="underline text-red-300 ml-4 font-semibold">
                Retry
              </button>
            </div>
          )}

          {/* Metric Summary Cards */}
          {summary && (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col">
                <span className="text-xs font-medium text-slate-400">Total Findings</span>
                <span className="text-xl font-bold text-white mt-1">{summary.total_findings}</span>
                <span className="text-[10px] text-slate-500 mt-1">{summary.rules_triggered_count} rules triggered</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-900 border border-red-900/40 flex flex-col">
                <span className="text-xs font-medium text-red-400">Critical</span>
                <span className="text-xl font-bold text-red-300 mt-1">{summary.critical_count}</span>
                <span className="text-[10px] text-red-400/70 mt-1">Action required</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-900 border border-amber-900/40 flex flex-col">
                <span className="text-xs font-medium text-amber-400">High</span>
                <span className="text-xl font-bold text-amber-300 mt-1">{summary.high_count}</span>
                <span className="text-[10px] text-amber-400/70 mt-1">High severity</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-900 border border-yellow-900/40 flex flex-col">
                <span className="text-xs font-medium text-yellow-400">Medium</span>
                <span className="text-xl font-bold text-yellow-300 mt-1">{summary.medium_count}</span>
                <span className="text-[10px] text-yellow-400/70 mt-1">Moderate risk</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-900 border border-blue-900/40 flex flex-col">
                <span className="text-xs font-medium text-blue-400">Low</span>
                <span className="text-xl font-bold text-blue-300 mt-1">{summary.low_count}</span>
                <span className="text-[10px] text-blue-400/70 mt-1">Minor posture issue</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col">
                <span className="text-xs font-medium text-slate-400">Info / Evidence</span>
                <span className="text-xl font-bold text-slate-300 mt-1">{summary.info_count}</span>
                <span className="text-[10px] text-slate-500 mt-1">Observations</span>
              </div>
            </div>
          )}

          {/* Search & Filter Toolbar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/40 p-3 rounded-xl border border-slate-800">
            {/* Search Input */}
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by rule ID, title, evidence, or remediation..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            {/* Severity Tabs */}
            <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800 overflow-x-auto">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition ${
                    severityFilter === sev
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Category Filter Dropdown */}
            <div className="relative">
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-indigo-500 appearance-none pr-8 cursor-pointer"
              >
                <option value="ALL">All Categories</option>
                <option value="TLS_PROTOCOL">TLS Protocol</option>
                <option value="CIPHER_SUITE">Cipher Suite</option>
                <option value="CERTIFICATE">Certificate</option>
                <option value="PROTOCOL_BEHAVIOR">Protocol Behavior</option>
                <option value="STARTTLS">STARTTLS</option>
                <option value="EVIDENCE">Evidence & Facts</option>
              </select>
              <ChevronDown className="absolute right-2.5 top-2.5 h-3.5 w-3.5 text-slate-500 pointer-events-none" />
            </div>
          </div>

          {/* Findings List */}
          {loading ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-400 space-y-3">
              <RefreshCw className="w-8 h-8 animate-spin text-indigo-500" />
              <p className="text-xs">Evaluating cryptographic rules against forensic evidence...</p>
            </div>
          ) : filteredFindings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-400 space-y-2 rounded-xl border border-dashed border-slate-800 bg-slate-950/40">
              <CheckCircle className="w-10 h-10 text-emerald-500 mb-1" />
              <p className="text-sm font-semibold text-slate-200">No matching cryptographic findings</p>
              <p className="text-xs text-slate-500">
                {findings.length === 0
                  ? 'All evaluated rules passed cleanly for this capture!'
                  : 'Try adjusting your search query or filter parameters.'}
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredFindings.map((finding) => {
                const isExpanded = expandedFindingId === finding.id;
                return (
                  <div
                    key={finding.id}
                    className="rounded-xl border border-slate-800 bg-slate-900/60 hover:border-slate-700/80 transition overflow-hidden shadow-sm"
                  >
                    {/* Header bar */}
                    <div className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 bg-slate-900/90">
                      <div className="flex items-start space-x-3">
                        <div className="pt-0.5">{getSeverityBadge(finding.severity)}</div>
                        <div>
                          <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                            <span className="font-mono text-xs font-bold text-indigo-400 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-800/40">
                              {finding.rule_id}
                            </span>
                            <h3 className="text-sm font-bold text-white">{finding.name}</h3>
                            <span className="text-[10px] text-slate-400 bg-slate-800 px-2 py-0.5 rounded-full">
                              {finding.category}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 mt-1 leading-relaxed">{finding.reason}</p>
                        </div>
                      </div>

                      <div className="flex items-center space-x-3 self-end md:self-auto shrink-0">
                        {finding.tcp_stream !== null && finding.tcp_stream !== undefined && (
                          <span className="text-xs text-slate-400 font-mono bg-slate-950 px-2 py-1 rounded border border-slate-800">
                            Stream #{finding.tcp_stream}
                          </span>
                        )}

                        <span className="text-xs font-medium text-emerald-400 bg-emerald-950/40 px-2 py-1 rounded border border-emerald-900/50">
                          Confidence: {finding.confidence_label} ({(finding.confidence * 100).toFixed(0)}%)
                        </span>

                        {finding.tcp_stream !== null &&
                          finding.tcp_stream !== undefined &&
                          onInspectPackets && (
                            <button
                              onClick={() => onInspectPackets(finding.tcp_stream!)}
                              className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition"
                              title="Inspect raw TCP stream frames"
                            >
                              <ExternalLink className="w-3 h-3" />
                              <span>Stream</span>
                            </button>
                          )}

                        <button
                          onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                          className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Expandable Details Panel */}
                    {isExpanded && (
                      <div className="p-4 border-t border-slate-800 bg-slate-950/80 space-y-4 text-xs">
                        {/* Evidence section */}
                        {finding.evidence && (
                          <div className="space-y-2">
                            <div className="flex items-center space-x-1.5 text-slate-300 font-semibold">
                              <FileCode className="w-3.5 h-3.5 text-indigo-400" />
                              <span>Forensic Evidence Traceability</span>
                            </div>
                            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 font-mono text-slate-300 overflow-x-auto">
                              <pre className="text-[11px] leading-relaxed">
                                {JSON.stringify(finding.evidence, null, 2)}
                              </pre>
                            </div>
                          </div>
                        )}

                        {/* Remediation guidance */}
                        {finding.remediation && (
                          <div className="space-y-2">
                            <div className="flex items-center space-x-1.5 text-emerald-400 font-semibold">
                              <BookOpen className="w-3.5 h-3.5" />
                              <span>Actionable Remediation Guidance</span>
                            </div>
                            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-emerald-200 leading-relaxed">
                              {finding.remediation}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs text-slate-400">
          <span>
            Showing <strong className="text-slate-200">{filteredFindings.length}</strong> of{' '}
            <strong className="text-slate-200">{findings.length}</strong> total findings
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
