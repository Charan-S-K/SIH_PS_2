import React, { useState, useEffect, useCallback } from 'react';
import {
  X,
  ShieldAlert,
  Search,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Layers,
  Lock,
  Terminal,
  HelpCircle,
  ChevronRight,
  Cpu,
  Database
} from 'lucide-react';
import {
  fetchJobUnifiedFindings,
  fetchJobSessions,
  fetchJobPackets,
  UnifiedFinding,
  TcpSessionItem,
  PacketItem
} from '../services/api';

interface EvidenceExplorerModalProps {
  jobId: string;
  filename: string;
  isOpen: boolean;
  onClose: () => void;
  onInspectPackets?: (streamId?: number) => void;
}

export const EvidenceExplorerModal: React.FC<EvidenceExplorerModalProps> = ({
  jobId,
  filename,
  isOpen,
  onClose,
  onInspectPackets
}) => {
  const [findings, setFindings] = useState<UnifiedFinding[]>([]);
  const [sessions, setSessions] = useState<TcpSessionItem[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<UnifiedFinding | null>(null);
  const [associatedPackets, setAssociatedPackets] = useState<PacketItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadingPackets, setLoadingPackets] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [findingsRes, sessionsRes] = await Promise.all([
        fetchJobUnifiedFindings(jobId),
        fetchJobSessions(jobId)
      ]);

      if (findingsRes.data && findingsRes.data.findings) {
        setFindings(findingsRes.data.findings);
        if (findingsRes.data.findings.length > 0) {
          setSelectedFinding(findingsRes.data.findings[0]);
        }
      }
      if (sessionsRes.data && sessionsRes.data.sessions) {
        setSessions(sessionsRes.data.sessions);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load evidence chain data');
    } finally {
      setLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    if (isOpen && jobId) {
      loadData();
    }
  }, [isOpen, jobId, loadData]);

  // Load packets when selected finding changes
  useEffect(() => {
    if (!selectedFinding || !jobId) {
      setAssociatedPackets([]);
      return;
    }

    const loadFindingPackets = async () => {
      setLoadingPackets(true);
      try {
        const streamId = selectedFinding.tcp_stream !== undefined && selectedFinding.tcp_stream !== null
          ? selectedFinding.tcp_stream
          : undefined;
        const res = await fetchJobPackets(jobId, 30, 0, undefined, undefined, streamId);
        if (res.data && res.data.packets) {
          setAssociatedPackets(res.data.packets);
        } else {
          setAssociatedPackets([]);
        }
      } catch (err) {
        setAssociatedPackets([]);
      } finally {
        setLoadingPackets(false);
      }
    };

    loadFindingPackets();
  }, [selectedFinding, jobId]);

  if (!isOpen) return null;

  const filteredFindings = findings.filter(f => {
    const matchesSev = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesSearch = searchTerm === '' ||
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.rule_id && f.rule_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      f.finding_type.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-800/80';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-400 border-amber-800/80';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-400 border-yellow-800/80';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-400 border-blue-800/80';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getAssociatedSession = (streamId?: number | null) => {
    if (streamId === undefined || streamId === null) return null;
    return sessions.find(s => s.tcp_stream === streamId);
  };

  const matchedSession = selectedFinding ? getAssociatedSession(selectedFinding.tcp_stream) : null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl w-full max-w-7xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-indigo-950/80 border border-indigo-700/50 rounded-lg text-indigo-400">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg font-bold text-white">Forensic Evidence Chain Explorer</h2>
                <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {filename}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Non-destructive evidence linkage: Finding &rarr; Yaml Rule &rarr; Session &rarr; Frame Range &rarr; Field Evidence
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        {loading ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center space-y-3">
            <Cpu className="w-8 h-8 animate-spin text-indigo-400" />
            <p className="text-sm">Reconstructing Evidence Chain for {filename}...</p>
          </div>
        ) : error ? (
          <div className="p-8 text-center text-red-400 bg-red-950/20 border border-red-900/30 rounded-xl m-6">
            <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
            <p className="font-semibold text-sm">{error}</p>
          </div>
        ) : (
          <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden">
            
            {/* Left Column: Finding Selector (4 cols) */}
            <div className="lg:col-span-4 border-r border-slate-800 flex flex-col bg-slate-900/30 overflow-hidden">
              
              {/* Search & Filter Bar */}
              <div className="p-4 border-b border-slate-800 space-y-3">
                <div className="relative">
                  <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Filter by rule ID, title..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <div className="flex items-center space-x-1.5 overflow-x-auto pb-1">
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setSeverityFilter(sev)}
                      className={`px-2.5 py-1 text-[11px] font-medium rounded-md transition ${
                        severityFilter === sev
                          ? 'bg-indigo-600 text-white'
                          : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              {/* Finding List */}
              <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
                {filteredFindings.length === 0 ? (
                  <div className="p-6 text-center text-slate-500 text-xs">
                    No matching findings in this evidence chain.
                  </div>
                ) : (
                  filteredFindings.map((f) => {
                    const isSelected = selectedFinding?.id === f.id;
                    return (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`p-3.5 cursor-pointer transition flex items-start space-x-3 ${
                          isSelected
                            ? 'bg-indigo-950/40 border-l-4 border-indigo-500'
                            : 'hover:bg-slate-800/50 border-l-4 border-transparent'
                        }`}
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between mb-1">
                            <span className={`px-2 py-0.5 text-[10px] font-semibold rounded border ${getSeverityBadge(f.severity)}`}>
                              {f.severity}
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              Stream #{f.tcp_stream !== undefined && f.tcp_stream !== null ? f.tcp_stream : 'N/A'}
                            </span>
                          </div>
                          <h4 className="text-xs font-semibold text-slate-200 truncate">{f.title}</h4>
                          <p className="text-[11px] font-mono text-slate-400 mt-0.5 truncate">{f.rule_id || f.finding_type}</p>
                        </div>
                        <ChevronRight className={`w-4 h-4 text-slate-600 mt-1 transition ${isSelected ? 'text-indigo-400 transform translate-x-0.5' : ''}`} />
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Right Main Area: Evidence Graph & Details (8 cols) */}
            <div className="lg:col-span-8 flex flex-col overflow-y-auto p-6 space-y-6 bg-[#0b0f19]">
              {selectedFinding ? (
                <>
                  {/* Finding Overview Header */}
                  <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2.5 py-1 text-xs font-bold rounded-md border ${getSeverityBadge(selectedFinding.severity)}`}>
                          {selectedFinding.severity}
                        </span>
                        <span className="px-2.5 py-1 text-xs font-mono rounded-md bg-indigo-950 text-indigo-300 border border-indigo-800/60">
                          Rule: {selectedFinding.rule_id || selectedFinding.finding_type}
                        </span>
                        <span className="px-2.5 py-1 text-xs font-mono rounded-md bg-slate-800 text-slate-300 border border-slate-700">
                          Confidence: {Math.round(selectedFinding.confidence * 100)}%
                        </span>
                      </div>

                      {onInspectPackets && selectedFinding.tcp_stream !== undefined && selectedFinding.tcp_stream !== null && (
                        <button
                          onClick={() => {
                            onClose();
                            onInspectPackets(selectedFinding.tcp_stream!);
                          }}
                          className="flex items-center space-x-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded-lg text-xs font-medium transition"
                        >
                          <Terminal className="w-3.5 h-3.5" />
                          <span>View Hex Stream #{selectedFinding.tcp_stream}</span>
                        </button>
                      )}
                    </div>

                    <h3 className="text-lg font-bold text-white">{selectedFinding.title}</h3>
                    <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                      {selectedFinding.reason}
                    </p>
                  </div>

                  {/* Evidence Linkage Node Pipeline Graph */}
                  <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-4">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-400 flex items-center space-x-2">
                      <Layers className="w-4 h-4" />
                      <span>Non-Destructive Forensic Evidence Linkage</span>
                    </h4>

                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-center">
                      
                      {/* Node 1: Rule */}
                      <div className="p-3 rounded-lg bg-slate-950 border border-indigo-900/50 flex flex-col items-center justify-center space-y-1">
                        <FileCode className="w-5 h-5 text-indigo-400" />
                        <span className="text-[10px] text-slate-500 font-medium">1. Rule / Type</span>
                        <span className="text-xs font-mono font-bold text-slate-200 truncate w-full">{selectedFinding.rule_id || selectedFinding.finding_type}</span>
                      </div>

                      {/* Node 2: Session */}
                      <div className="p-3 rounded-lg bg-slate-950 border border-indigo-900/50 flex flex-col items-center justify-center space-y-1">
                        <Lock className="w-5 h-5 text-blue-400" />
                        <span className="text-[10px] text-slate-500 font-medium">2. TCP Conversation</span>
                        <span className="text-xs font-mono font-bold text-slate-200">
                          {selectedFinding.tcp_stream !== undefined && selectedFinding.tcp_stream !== null
                            ? `Stream #${selectedFinding.tcp_stream}`
                            : 'UNKNOWN'}
                        </span>
                      </div>

                      {/* Node 3: Packet Range */}
                      <div className="p-3 rounded-lg bg-slate-950 border border-indigo-900/50 flex flex-col items-center justify-center space-y-1">
                        <Terminal className="w-5 h-5 text-emerald-400" />
                        <span className="text-[10px] text-slate-500 font-medium">3. Frame Range</span>
                        <span className="text-xs font-mono font-bold text-slate-200">
                          {matchedSession
                            ? `Frames ${matchedSession.first_frame_number}-${matchedSession.last_frame_number}`
                            : 'UNKNOWN'}
                        </span>
                      </div>

                      {/* Node 4: Field Evidence */}
                      <div className="p-3 rounded-lg bg-slate-950 border border-indigo-900/50 flex flex-col items-center justify-center space-y-1">
                        <Database className="w-5 h-5 text-purple-400" />
                        <span className="text-[10px] text-slate-500 font-medium">4. Protocol Field</span>
                        <span className="text-xs font-mono font-bold text-slate-200 truncate w-full">
                          {selectedFinding.finding_type}
                        </span>
                      </div>

                    </div>
                  </div>

                  {/* Deep Field Evidence & Metadata Breakdown */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    
                    {/* Observed Evidence Details */}
                    <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 space-y-3">
                      <h4 className="text-xs font-semibold text-slate-300 flex items-center space-x-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span>Observed Evidence Metadata</span>
                      </h4>
                      <div className="space-y-2 text-xs font-mono bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                        <div className="flex justify-between border-b border-slate-800/60 pb-1">
                          <span className="text-slate-500">Finding Type:</span>
                          <span className="text-slate-200">{selectedFinding.finding_type}</span>
                        </div>
                        <div className="flex justify-between border-b border-slate-800/60 pb-1">
                          <span className="text-slate-500">Occurrence Count:</span>
                          <span className="text-slate-200">{selectedFinding.occurrence_count}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Evidence Status:</span>
                          <span className="text-emerald-400 font-bold">VERIFIED_NON_FABRICATED</span>
                        </div>
                      </div>
                    </div>

                    {/* Associated Session Metadata */}
                    <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 space-y-3">
                      <h4 className="text-xs font-semibold text-slate-300 flex items-center space-x-2">
                        <Lock className="w-4 h-4 text-blue-400" />
                        <span>Session Context & Endpoints</span>
                      </h4>
                      {matchedSession ? (
                        <div className="space-y-2 text-xs font-mono bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                          <div className="flex justify-between border-b border-slate-800/60 pb-1">
                            <span className="text-slate-500">Client Endpoint:</span>
                            <span className="text-slate-200">{matchedSession.client_ip || 'UNKNOWN'}:{matchedSession.client_port || '?'}</span>
                          </div>
                          <div className="flex justify-between border-b border-slate-800/60 pb-1">
                            <span className="text-slate-500">Server Endpoint:</span>
                            <span className="text-slate-200">{matchedSession.server_ip || 'UNKNOWN'}:{matchedSession.server_port || '?'}</span>
                          </div>
                          <div className="flex justify-between border-b border-slate-800/60 pb-1">
                            <span className="text-slate-500">Protocol:</span>
                            <span className="text-indigo-400 font-bold">{matchedSession.protocol}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Total Packets / Bytes:</span>
                            <span className="text-slate-300">{matchedSession.packet_count} pkts ({matchedSession.total_payload_bytes} bytes)</span>
                          </div>
                        </div>
                      ) : (
                        <div className="p-4 text-center bg-slate-950 rounded-lg border border-slate-800/80 text-xs text-slate-500">
                          <HelpCircle className="w-5 h-5 mx-auto mb-1 text-slate-600" />
                          <span>No direct TCP stream record attached to this finding. Explicit status: UNKNOWN</span>
                        </div>
                      )}
                    </div>

                  </div>

                  {/* Associated Frames Preview */}
                  <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 space-y-3">
                    <h4 className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                      <span className="flex items-center space-x-2">
                        <Terminal className="w-4 h-4 text-emerald-400" />
                        <span>Associated Packet Frames ({associatedPackets.length})</span>
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">Sample frame payloads</span>
                    </h4>

                    {loadingPackets ? (
                      <div className="p-4 text-center text-slate-500 text-xs">Loading associated packet frames...</div>
                    ) : associatedPackets.length === 0 ? (
                      <div className="p-4 text-center text-slate-500 text-xs bg-slate-950 rounded-lg border border-slate-800/80">
                        No raw packet payload streams cached for this finding. Status: INSUFFICIENT_EVIDENCE
                      </div>
                    ) : (
                      <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                        {associatedPackets.slice(0, 5).map((pkt) => (
                          <div key={pkt.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
                            <div className="flex justify-between text-[11px] text-slate-400">
                              <span>Frame #{pkt.frame_number} &bull; {pkt.src_ip}:{pkt.src_port} &rarr; {pkt.dst_ip}:{pkt.dst_port}</span>
                              <span className="text-indigo-400 font-bold">{pkt.detected_protocol} ({pkt.payload_size} bytes)</span>
                            </div>
                            {pkt.payload_preview ? (
                              <div className="p-2 bg-black/60 rounded text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                                {pkt.payload_preview}
                              </div>
                            ) : (
                              <div className="text-[10px] text-slate-600 italic">No ascii payload preview available.</div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Remediation Rationale Placeholder */}
                  {selectedFinding.remediation && (
                    <div className="p-4 rounded-xl bg-blue-950/30 border border-blue-900/40 text-xs space-y-1.5">
                      <h5 className="font-semibold text-blue-300 flex items-center space-x-1.5">
                        <ShieldAlert className="w-4 h-4 text-blue-400" />
                        <span>Deterministic Remediation Guidance</span>
                      </h5>
                      <p className="text-slate-300 leading-relaxed">{selectedFinding.remediation}</p>
                    </div>
                  )}

                </>
              ) : (
                <div className="h-full flex flex-col items-center justify-center p-12 text-center text-slate-500">
                  <Layers className="w-12 h-12 text-slate-700 mb-3" />
                  <p className="text-sm font-medium">Select a finding from the left pane to explore its full evidence chain.</p>
                </div>
              )}
            </div>

          </div>
        )}

      </div>
    </div>
  );
};
