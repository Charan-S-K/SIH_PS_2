import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  X,
  RefreshCw,
  Search,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Layers,
  Copy,
  Check,
  Filter,
  ShieldCheck,
  FileCode
} from 'lucide-react';
import {
  fetchJobUnifiedFindings,
  consolidateJobFindings,
  UnifiedFinding,
  FindingsSummary
} from '../services/api';
import { EvidenceChainModal } from './EvidenceChainModal';

interface FindingsModalProps {
  jobId: string;
  filename: string;
  isOpen: boolean;
  onClose: () => void;
  onInspectPackets?: (streamId: number) => void;
}

export const FindingsModal: React.FC<FindingsModalProps> = ({
  jobId,
  filename,
  isOpen,
  onClose,
  onInspectPackets,
}) => {
  const [summary, setSummary] = useState<FindingsSummary | null>(null);
  const [findings, setFindings] = useState<UnifiedFinding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [consolidating, setConsolidating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedFingerprint, setCopiedFingerprint] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [duplicateFilter, setDuplicateFilter] = useState<string>('UNIQUE'); // 'ALL' | 'UNIQUE' | 'DUPLICATES'
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [selectedFindingForEvidenceId, setSelectedFindingForEvidenceId] = useState<string | null>(null);

  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    const { data, error: err } = await fetchJobUnifiedFindings(jobId);
    if (err) {
      setError(err);
    } else if (data) {
      setSummary(data.summary);
      setFindings(data.findings);
    }
    setLoading(false);
  }, [jobId]);

  const handleConsolidate = async () => {
    setConsolidating(true);
    setError(null);
    const { data, error: err } = await consolidateJobFindings(jobId, true);
    if (err) {
      setError(err);
    } else if (data) {
      setSummary(data.summary);
      setFindings(data.findings);
    }
    setConsolidating(false);
  };

  useEffect(() => {
    if (isOpen && jobId) {
      loadFindings();
    }
  }, [isOpen, jobId, loadFindings]);

  if (!isOpen) return null;

  const handleCopyFingerprint = (fingerprint: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(fingerprint);
    setCopiedFingerprint(fingerprint);
    setTimeout(() => setCopiedFingerprint(null), 2000);
  };

  // Filter findings
  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      searchQuery === '' ||
      (f.rule_id && f.rule_id.toLowerCase().includes(searchQuery.toLowerCase())) ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.fingerprint.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.remediation && f.remediation.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesSeverity =
      severityFilter === 'ALL' || f.severity.toUpperCase() === severityFilter;

    const matchesType =
      typeFilter === 'ALL' || f.finding_type.toUpperCase() === typeFilter;

    const matchesDuplicate =
      duplicateFilter === 'ALL' ||
      (duplicateFilter === 'UNIQUE' && !f.is_duplicate) ||
      (duplicateFilter === 'DUPLICATES' && f.is_duplicate);

    return matchesSearch && matchesSeverity && matchesType && matchesDuplicate;
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert className="w-3.5 h-3.5" />
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/20">
            <AlertTriangle className="w-3.5 h-3.5" />
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertCircle className="w-3.5 h-3.5" />
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Info className="w-3.5 h-3.5" />
            LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
            <Info className="w-3.5 h-3.5" />
            INFO
          </span>
        );
    }
  };

  const getFindingTypeBadge = (findingType: string) => {
    switch (findingType.toUpperCase()) {
      case 'CRYPTOGRAPHIC_WEAKNESS':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20">Crypto Weakness</span>;
      case 'CERTIFICATE_FORENSIC':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">Cert Forensic</span>;
      case 'PROTOCOL_SECURITY':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Protocol Sec</span>;
      case 'STARTTLS_INTEGRITY':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">STARTTLS</span>;
      case 'EVIDENCE_GAP':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">Evidence Gap</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-500/10 text-slate-400 border border-slate-500/20">{findingType}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-500/10 rounded-lg border border-indigo-500/20 text-indigo-400">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                Unified Findings & Correlation Model
                <span className="text-xs px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-mono">
                  Stage 10
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Correlated evidence, fingerprint deduplication, and remediations for <span className="font-mono text-slate-300">{filename}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleConsolidate}
              disabled={consolidating || loading}
              className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${consolidating ? 'animate-spin' : ''}`} />
              {consolidating ? 'Consolidating...' : 'Re-consolidate Findings'}
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

          {/* Summary Dashboard Grid */}
          {summary && (
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
              <div className="bg-slate-800/50 border border-slate-700/50 p-3 rounded-lg text-center">
                <span className="text-xs text-slate-400 block font-medium">Total</span>
                <span className="text-xl font-bold text-slate-100">{summary.total_findings}</span>
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 p-3 rounded-lg text-center">
                <span className="text-xs text-slate-400 block font-medium">Unique</span>
                <span className="text-xl font-bold text-emerald-400">{summary.unique_findings}</span>
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 p-3 rounded-lg text-center">
                <span className="text-xs text-slate-400 block font-medium">Duplicates</span>
                <span className="text-xl font-bold text-indigo-400">{summary.duplicate_findings}</span>
              </div>
              <div className="bg-rose-500/10 border border-rose-500/20 p-3 rounded-lg text-center">
                <span className="text-xs text-rose-400 block font-medium">Critical</span>
                <span className="text-xl font-bold text-rose-400">{summary.critical_count}</span>
              </div>
              <div className="bg-orange-500/10 border border-orange-500/20 p-3 rounded-lg text-center">
                <span className="text-xs text-orange-400 block font-medium">High</span>
                <span className="text-xl font-bold text-orange-400">{summary.high_count}</span>
              </div>
              <div className="bg-amber-500/10 border border-amber-500/20 p-3 rounded-lg text-center">
                <span className="text-xs text-amber-400 block font-medium">Medium</span>
                <span className="text-xl font-bold text-amber-400">{summary.medium_count}</span>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/20 p-3 rounded-lg text-center">
                <span className="text-xs text-blue-400 block font-medium">Low</span>
                <span className="text-xl font-bold text-blue-400">{summary.low_count}</span>
              </div>
              <div className="bg-slate-500/10 border border-slate-500/20 p-3 rounded-lg text-center">
                <span className="text-xs text-slate-400 block font-medium">Info</span>
                <span className="text-xl font-bold text-slate-400">{summary.info_count}</span>
              </div>
            </div>
          )}

          {/* Filter Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-800/30 p-3 rounded-lg border border-slate-800">
            <div className="relative flex-1 min-w-[220px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search rule ID, title, fingerprint, reason..."
                className="w-full bg-slate-900 border border-slate-700/60 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <Filter className="w-3.5 h-3.5 text-slate-500" />
                <span>Filters:</span>
              </div>

              {/* Severity filter */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-900 border border-slate-700/60 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Info</option>
              </select>

              {/* Type filter */}
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="bg-slate-900 border border-slate-700/60 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Types</option>
                <option value="CRYPTOGRAPHIC_WEAKNESS">Crypto Weakness</option>
                <option value="CERTIFICATE_FORENSIC">Cert Forensic</option>
                <option value="PROTOCOL_SECURITY">Protocol Security</option>
                <option value="STARTTLS_INTEGRITY">STARTTLS Integrity</option>
                <option value="EVIDENCE_GAP">Evidence Gap</option>
              </select>

              {/* Duplicate filter */}
              <select
                value={duplicateFilter}
                onChange={(e) => setDuplicateFilter(e.target.value)}
                className="bg-slate-900 border border-slate-700/60 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="UNIQUE">Unique Findings Only</option>
                <option value="ALL">All (Unique + Duplicates)</option>
                <option value="DUPLICATES">Duplicates Only</option>
              </select>
            </div>
          </div>

          {/* Findings Accordion List */}
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12 text-slate-400 gap-3">
              <RefreshCw className="w-6 h-6 animate-spin text-indigo-400" />
              <span className="text-xs font-mono">Consolidating unified findings and correlation metrics...</span>
            </div>
          ) : filteredFindings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-slate-400 gap-2 border border-dashed border-slate-800 rounded-lg">
              <ShieldCheck className="w-10 h-10 text-slate-600" />
              <span className="text-sm font-medium">No findings match the selected criteria.</span>
              <span className="text-xs text-slate-500">Try adjusting search filters or re-consolidating.</span>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredFindings.map((finding) => {
                const isExpanded = expandedFindingId === finding.id;

                return (
                  <div
                    key={finding.id}
                    className={`border rounded-lg transition-all overflow-hidden ${
                      finding.is_duplicate
                        ? 'bg-slate-900/40 border-slate-800/80 opacity-85'
                        : 'bg-slate-800/30 border-slate-700/60 hover:border-slate-600'
                    }`}
                  >
                    {/* Finding Header Bar */}
                    <div
                      onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                      className="flex items-center justify-between p-4 cursor-pointer select-none"
                    >
                      <div className="flex items-start gap-3 flex-1 min-w-0 pr-4">
                        <div className="mt-0.5 flex-shrink-0">
                          {getSeverityBadge(finding.severity)}
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="text-sm font-semibold text-slate-100 truncate">
                              {finding.title}
                            </h3>
                            {getFindingTypeBadge(finding.finding_type)}
                            {finding.rule_id && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                                {finding.rule_id}
                              </span>
                            )}
                            {finding.tcp_stream !== null && finding.tcp_stream !== undefined && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                                Stream #{finding.tcp_stream}
                              </span>
                            )}
                            {finding.is_duplicate ? (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                Duplicate Record
                              </span>
                            ) : finding.occurrence_count > 1 ? (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                Occurrences: {finding.occurrence_count}
                              </span>
                            ) : null}
                          </div>

                          <p className="text-xs text-slate-400 mt-1 line-clamp-1">
                            {finding.reason}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 flex-shrink-0">
                        <button
                          onClick={(e) => handleCopyFingerprint(finding.fingerprint, e)}
                          title="Copy fingerprint SHA-256"
                          className="flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-slate-300 px-2 py-1 rounded bg-slate-800/80 border border-slate-700/50"
                        >
                          {copiedFingerprint === finding.fingerprint ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                          <span>{finding.fingerprint.substring(0, 10)}...</span>
                        </button>

                        <div className="text-slate-400">
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-indigo-400" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Expanded Detail View */}
                    {isExpanded && (
                      <div className="px-4 pb-4 pt-2 border-t border-slate-800 bg-slate-900/60 space-y-4 animate-fadeIn">
                        {/* Finding Description / Reason */}
                        <div>
                          <h4 className="text-xs font-semibold text-slate-300 mb-1 flex items-center gap-1.5">
                            <Info className="w-3.5 h-3.5 text-indigo-400" />
                            Forensic Finding Explanation
                          </h4>
                          <p className="text-xs text-slate-300 bg-slate-950/70 p-3 rounded border border-slate-800/80 leading-relaxed font-sans">
                            {finding.reason}
                          </p>
                        </div>

                        {/* Remediation */}
                        {finding.remediation && (
                          <div>
                            <h4 className="text-xs font-semibold text-slate-300 mb-1 flex items-center gap-1.5">
                              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                              Remediation Guidance
                            </h4>
                            <div className="text-xs text-emerald-300/90 bg-emerald-950/20 p-3 rounded border border-emerald-800/30 leading-relaxed">
                              {finding.remediation}
                            </div>
                          </div>
                        )}

                        {/* References and Evidence Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                          {/* Analysis References */}
                          {finding.analysis_references && (
                            <div className="bg-slate-950/50 p-3 rounded border border-slate-800">
                              <span className="font-semibold text-slate-300 block mb-2 flex items-center gap-1.5">
                                <FileCode className="w-3.5 h-3.5 text-purple-400" />
                                Analysis References
                              </span>
                              <pre className="text-[11px] font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap">
                                {JSON.stringify(finding.analysis_references, null, 2)}
                              </pre>
                            </div>
                          )}

                          {/* Evidence References */}
                          {finding.evidence_references && (
                            <div className="bg-slate-950/50 p-3 rounded border border-slate-800">
                              <span className="font-semibold text-slate-300 block mb-2 flex items-center gap-1.5">
                                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                                Forensic Evidence References
                              </span>
                              <pre className="text-[11px] font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap">
                                {JSON.stringify(finding.evidence_references, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>

                        {/* Evidence Action Buttons */}
                        <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
                          <button
                            onClick={() => setSelectedFindingForEvidenceId(finding.id)}
                            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-purple-900/60 hover:bg-purple-800 text-purple-200 border border-purple-700/60 rounded-lg transition-colors"
                          >
                            <FileCode className="w-3.5 h-3.5 text-purple-400" />
                            View Evidence Chain & Provenance (Stage 11)
                          </button>

                          {finding.tcp_stream !== null && finding.tcp_stream !== undefined && onInspectPackets && (
                            <button
                              onClick={() => {
                                onInspectPackets(finding.tcp_stream!);
                                onClose();
                              }}
                              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-indigo-300 border border-slate-700 rounded-lg transition-colors"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                              Inspect TCP Stream #{finding.tcp_stream} Packets
                            </button>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Stage 11: Evidence Chain & Provenance Modal */}
      {selectedFindingForEvidenceId && (
        <EvidenceChainModal
          jobId={jobId}
          findingId={selectedFindingForEvidenceId}
          isOpen={true}
          onClose={() => setSelectedFindingForEvidenceId(null)}
          onInspectPackets={onInspectPackets}
        />
      )}
    </div>
  );
};
