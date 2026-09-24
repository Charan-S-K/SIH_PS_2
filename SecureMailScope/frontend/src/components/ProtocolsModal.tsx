import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldCheck,
  AlertTriangle,
  Info,
  RefreshCw,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Mail,
  Network
} from 'lucide-react';
import {
  fetchJobProtocols,
  identifyJobProtocols,
  ProtocolListResponse
} from '../services/api';


interface ProtocolsModalProps {
  jobId: string;
  filename: string;
  onClose: () => void;
  onInspectFrames?: (streamId: number) => void;
}

export const ProtocolsModal: React.FC<ProtocolsModalProps> = ({
  jobId,
  filename,
  onClose,
  onInspectFrames
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [data, setData] = useState<ProtocolListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filterMailOnly, setFilterMailOnly] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedStreams, setExpandedStreams] = useState<Record<string, boolean>>({});

  const loadProtocols = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    const res = await fetchJobProtocols(jobId);
    if (res.error) {
      setError(res.error);
    } else {
      setData(res.data);
      // Auto-expand first 2 streams if present
      if (res.data && res.data.protocols.length > 0) {
        const initialExpanded: Record<string, boolean> = {};
        res.data.protocols.slice(0, 2).forEach((p) => {
          initialExpanded[p.id] = true;
        });
        setExpandedStreams(initialExpanded);
      }
    }
    setLoading(false);
    setRefreshing(false);
  };

  const handleReanalyze = async () => {
    setRefreshing(true);
    setError(null);
    const res = await identifyJobProtocols(jobId);
    if (res.error) {
      setError(res.error);
    } else {
      setData(res.data);
    }
    setRefreshing(false);
  };

  useEffect(() => {
    loadProtocols();
  }, [jobId]);

  const toggleExpand = (id: string) => {
    setExpandedStreams((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredProtocols = (data?.protocols || []).filter((p) => {
    if (filterMailOnly && !p.is_mail_protocol) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      p.protocol.toLowerCase().includes(q) ||
      (p.client_ip && p.client_ip.toLowerCase().includes(q)) ||
      (p.server_ip && p.server_ip.toLowerCase().includes(q)) ||
      (p.summary && p.summary.toLowerCase().includes(q)) ||
      (p.tcp_stream !== null && String(p.tcp_stream).includes(q))
    );
  });

  const getProtocolBadge = (protocol: string, _isMail?: boolean) => {
    const proto = protocol.toUpperCase();

    if (proto.includes('SMTP')) {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-900/60 text-emerald-300 border border-emerald-700/50">SMTP</span>;
    } else if (proto.includes('IMAP')) {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-900/60 text-blue-300 border border-blue-700/50">IMAP</span>;
    } else if (proto.includes('POP3') || proto.includes('POP')) {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-900/60 text-purple-300 border border-purple-700/50">POP3</span>;
    } else if (proto.includes('TLS')) {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-900/60 text-indigo-300 border border-indigo-700/50">TLS</span>;
    } else if (proto === 'HTTP') {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-900/60 text-amber-300 border border-amber-700/50">HTTP</span>;
    } else if (proto === 'SSH') {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-orange-900/60 text-orange-300 border border-orange-700/50">SSH</span>;
    } else if (proto === 'DNS') {
      return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-900/60 text-cyan-300 border border-cyan-700/50">DNS</span>;
    }
    return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">UNKNOWN</span>;
  };

  const getConfidenceBadge = (confidence: number, level: string) => {
    const pct = Math.round(confidence * 100);
    if (level === 'HIGH') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-emerald-950 text-emerald-300 border border-emerald-800/60">
          <ShieldCheck className="w-3.5 h-3.5" />
          {pct}% (High)
        </span>
      );
    } else if (level === 'MEDIUM') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-950 text-amber-300 border border-amber-800/60">
          <Info className="w-3.5 h-3.5" />
          {pct}% (Medium)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
        <AlertTriangle className="w-3.5 h-3.5" />
        {pct}% (Unknown)
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                Protocol Identification & Evidence
                <span className="text-xs font-normal text-slate-400 px-2 py-0.5 bg-slate-800 rounded">
                  {filename}
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Deterministic signature & conversational analysis; ports used as corroborating evidence only
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleReanalyze()}
              disabled={refreshing}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-colors disabled:opacity-50"
              title="Re-run protocol identification"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Re-analyze
            </button>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Toolbar & Summary stats */}
        <div className="px-6 py-3 border-b border-slate-800 bg-slate-900/40 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Total Conversations:</span>
              <span className="px-2 py-0.5 bg-slate-800 rounded font-semibold text-slate-200">
                {data?.total_streams ?? 0}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Email Streams:</span>
              <span className="px-2 py-0.5 bg-emerald-950 text-emerald-300 border border-emerald-800/60 rounded font-semibold">
                {data?.mail_streams ?? 0}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={filterMailOnly}
                onChange={(e) => setFilterMailOnly(e.target.checked)}
                className="rounded border-slate-700 bg-slate-800 text-blue-600 focus:ring-0"
              />
              <Mail className="w-3.5 h-3.5 text-blue-400" />
              Mail protocols only
            </label>

            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search protocol, IP, port..."
                className="pl-8 pr-3 py-1 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 focus:outline-none focus:border-blue-500 w-52"
              />
            </div>
          </div>
        </div>

        {/* Body Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {loading && (
            <div className="flex flex-col items-center justify-center py-16 text-slate-400">
              <RefreshCw className="w-8 h-8 animate-spin text-blue-500 mb-3" />
              <p className="text-sm">Inspecting streams and matching protocol signatures...</p>
            </div>
          )}

          {error && (
            <div className="p-4 bg-red-950/40 border border-red-800/60 rounded-lg text-sm text-red-300 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 flex-shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          {!loading && !error && filteredProtocols.length === 0 && (
            <div className="text-center py-12 text-slate-500 text-sm">
              No protocol streams match your current filters.
            </div>
          )}

          {!loading && !error && filteredProtocols.map((item) => {
            const isExpanded = !!expandedStreams[item.id];
            const evidence = item.evidence;
            const portAnalysis = evidence?.port_analysis;
            const hasAnomalies = (evidence?.anomalies || []).length > 0;

            return (
              <div
                key={item.id}
                className="bg-slate-950/70 border border-slate-800 rounded-lg overflow-hidden transition-all hover:border-slate-700"
              >
                {/* Stream Header Row */}
                <div
                  onClick={() => toggleExpand(item.id)}
                  className="px-4 py-3 cursor-pointer flex items-center justify-between gap-4 bg-slate-900/30 hover:bg-slate-900/60 select-none"
                >
                  <div className="flex items-center gap-3">
                    <button className="text-slate-400 hover:text-slate-200">
                      {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </button>

                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs px-2 py-0.5 bg-slate-800 text-slate-300 rounded font-medium">
                        {item.tcp_stream !== null && item.tcp_stream !== undefined ? `Stream #${item.tcp_stream}` : 'UDP Flow'}
                      </span>
                      {getProtocolBadge(item.protocol, item.is_mail_protocol)}
                      {getConfidenceBadge(item.confidence, item.confidence_level)}
                    </div>

                    <div className="font-mono text-xs text-slate-300">
                      <span>{item.client_ip || '?'}:{item.client_port || '?'}</span>
                      <span className="mx-1 text-slate-500">→</span>
                      <span>{item.server_ip || '?'}:{item.server_port || '?'}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-slate-400">
                    <div className="flex items-center gap-3">
                      <span>{item.packet_count} packets</span>
                      <span>{item.total_bytes} bytes</span>
                    </div>

                    {hasAnomalies && (
                      <span className="flex items-center gap-1 text-amber-400 text-xs px-2 py-0.5 bg-amber-950/80 border border-amber-800/60 rounded">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Anomaly
                      </span>
                    )}

                    {item.tcp_stream !== null && item.tcp_stream !== undefined && onInspectFrames && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onInspectFrames(item.tcp_stream!);
                        }}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-blue-600 hover:text-white text-slate-300 rounded text-xs font-medium border border-slate-700 transition-colors flex items-center gap-1"
                        title="View packet frames in modal"
                      >
                        <ExternalLink className="w-3 h-3" />
                        Inspect Frames
                      </button>
                    )}
                  </div>
                </div>

                {/* Summary bar */}
                <div className="px-4 py-2 bg-slate-900/10 border-t border-slate-900 text-xs text-slate-300 flex items-center justify-between">
                  <span className="text-slate-400">Summary: <strong className="text-slate-200">{item.summary}</strong></span>
                  <span className="text-slate-500 font-mono text-[11px] uppercase tracking-wider">Method: {item.classification_method}</span>
                </div>

                {/* Expanded Forensic Evidence Card */}
                {isExpanded && (
                  <div className="p-4 border-t border-slate-800 bg-slate-950/40 space-y-3">
                    {/* Anomalies Alert */}
                    {hasAnomalies && (
                      <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-md text-xs text-amber-200 space-y-1">
                        <div className="font-semibold flex items-center gap-1.5 text-amber-300">
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                          Security & Protocol Anomalies Detected
                        </div>
                        {evidence?.anomalies.map((ano, idx) => (
                          <div key={idx} className="font-mono text-amber-200/90 pl-5">
                            • {ano}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Port Corroboration Analysis */}
                    {portAnalysis && (
                      <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-md text-xs space-y-1">
                        <div className="text-slate-400 font-medium flex items-center justify-between">
                          <span>Port Analysis:</span>
                          <span className={portAnalysis.matches_detected_protocol ? 'text-emerald-400' : 'text-amber-400'}>
                            {portAnalysis.matches_detected_protocol ? '✓ Port Corroborates Protocol' : '⚠ Non-standard / Mismatched Port'}
                          </span>
                        </div>
                        <p className="text-slate-300">{portAnalysis.notes}</p>
                      </div>
                    )}

                    {/* Insufficient evidence warning */}
                    {evidence?.insufficient_evidence_reason && (
                      <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-md text-xs text-slate-400 flex items-start gap-2">
                        <Info className="w-4 h-4 text-slate-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <span className="font-medium text-slate-300">Insufficient Evidence Explanation:</span>
                          <p className="mt-0.5 text-slate-400">{evidence.insufficient_evidence_reason}</p>
                        </div>
                      </div>
                    )}

                    {/* Matched Signatures Tags */}
                    {evidence?.matched_signatures && evidence.matched_signatures.length > 0 && (
                      <div className="space-y-1.5">
                        <span className="text-xs font-medium text-slate-400">Forensic Signatures Matched:</span>
                        <div className="flex flex-wrap gap-1.5">
                          {evidence.matched_signatures.map((sig, sIdx) => (
                            <span
                              key={sIdx}
                              className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-xs font-mono text-slate-300"
                            >
                              {sig}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Evidence Frames Table */}
                    {evidence?.evidence_frames && evidence.evidence_frames.length > 0 && (
                      <div className="space-y-1.5 pt-1">
                        <span className="text-xs font-medium text-slate-400">Key Evidence Frames:</span>
                        <div className="border border-slate-800 rounded overflow-hidden">
                          <table className="w-full text-left text-xs font-mono">
                            <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                              <tr>
                                <th className="px-3 py-1.5">Frame #</th>
                                <th className="px-3 py-1.5">Direction</th>
                                <th className="px-3 py-1.5">Signature</th>
                                <th className="px-3 py-1.5">Matched Content</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800 bg-slate-950/80 text-slate-300">
                              {evidence.evidence_frames.map((ef, eIdx) => (
                                <tr key={eIdx} className="hover:bg-slate-900/40">
                                  <td className="px-3 py-1.5 text-blue-400">#{ef.frame_number}</td>
                                  <td className="px-3 py-1.5 text-slate-400">
                                    {ef.direction === 'client_to_server' ? 'Client → Server' : 'Server → Client'}
                                  </td>
                                  <td className="px-3 py-1.5 text-emerald-400">{ef.signature_matched}</td>
                                  <td className="px-3 py-1.5 text-slate-300 truncate max-w-xs">{ef.matched_text || '—'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <strong className="text-slate-200">{filteredProtocols.length}</strong> of{' '}
            <strong className="text-slate-200">{data?.total_streams ?? 0}</strong> stream classifications
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-medium border border-slate-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
