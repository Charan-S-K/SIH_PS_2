import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  AlertCircle,
  X,
  RefreshCw,
  ExternalLink,
  Layers,
  Database,
  Terminal,
  Activity
} from 'lucide-react';
import {
  fetchFindingEvidenceChain,
  ForensicEvidenceChain
} from '../services/api';

interface EvidenceChainModalProps {
  jobId: string;
  findingId: string;
  isOpen: boolean;
  onClose: () => void;
  onInspectPackets?: (streamId: number) => void;
}

export const EvidenceChainModal: React.FC<EvidenceChainModalProps> = ({
  jobId,
  findingId,
  isOpen,
  onClose,
  onInspectPackets,
}) => {
  const [chain, setChain] = useState<ForensicEvidenceChain | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadChain = useCallback(async () => {
    setLoading(true);
    setError(null);
    const { data, error: err } = await fetchFindingEvidenceChain(jobId, findingId);
    if (err) {
      setError(err);
    } else if (data) {
      setChain(data);
    }
    setLoading(false);
  }, [jobId, findingId]);

  useEffect(() => {
    if (isOpen && jobId && findingId) {
      loadChain();
    }
  }, [isOpen, jobId, findingId, loadChain]);

  if (!isOpen) return null;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETE_EVIDENCE':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-4 h-4" />
            100% COMPLETE EVIDENCE
          </span>
        );
      case 'PARTIAL_EVIDENCE':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-4 h-4" />
            PARTIAL EVIDENCE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <AlertCircle className="w-4 h-4" />
            INSUFFICIENT EVIDENCE
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 rounded-lg border border-purple-500/20 text-purple-400">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                Forensic Evidence Chain & Provenance
                <span className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono">
                  Stage 11
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Verifiable traceability from finding to session, packet frames, and observed protocol fields
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
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
              <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
              <span className="text-xs font-mono">Building forensic evidence graph and packet provenance...</span>
            </div>
          ) : chain ? (
            <>
              {/* Finding Title & Status Card */}
              <div className="bg-slate-800/40 border border-slate-700/60 p-4 rounded-xl space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-semibold text-slate-100">{chain.finding_title}</h3>
                    <div className="flex flex-wrap items-center gap-2 mt-1">
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {chain.finding_type}
                      </span>
                      {chain.rule_id && (
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                          {chain.rule_id}
                        </span>
                      )}
                      {chain.tcp_stream !== null && chain.tcp_stream !== undefined && (
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          Stream #{chain.tcp_stream}
                        </span>
                      )}
                    </div>
                  </div>

                  <div>{getStatusBadge(chain.evidence_status)}</div>
                </div>
              </div>

              {/* Provenance Graph Flow Representation */}
              <div className="bg-slate-950/60 border border-slate-800 p-4 rounded-xl space-y-3">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-indigo-400" />
                  Evidence Traceability Graph
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                  {/* Node 1: Finding */}
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                    <span className="text-[10px] text-purple-400 uppercase font-bold block">1. Finding</span>
                    <span className="font-semibold text-slate-200 block truncate">{chain.finding_title}</span>
                    <span className="text-[11px] font-mono text-slate-400 block">Severity: {chain.severity}</span>
                  </div>

                  {/* Node 2: Session */}
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                    <span className="text-[10px] text-indigo-400 uppercase font-bold block">2. TCP Session</span>
                    {chain.session_evidence ? (
                      <>
                        <span className="font-mono text-slate-200 block truncate">
                          {chain.session_evidence.client_ip}:{chain.session_evidence.client_port} → {chain.session_evidence.server_ip}:{chain.session_evidence.server_port}
                        </span>
                        <span className="text-[11px] text-slate-400 block font-mono">
                          Protocol: {chain.session_evidence.protocol}
                        </span>
                      </>
                    ) : (
                      <span className="text-slate-500 italic">No session record</span>
                    )}
                  </div>

                  {/* Node 3: Packet Range */}
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                    <span className="text-[10px] text-cyan-400 uppercase font-bold block">3. Frame Range</span>
                    {chain.packet_range ? (
                      <>
                        <span className="font-mono text-slate-200 block">
                          Frames #{chain.packet_range.first_frame} - #{chain.packet_range.last_frame}
                        </span>
                        <span className="text-[11px] text-slate-400 block">
                          {chain.packet_range.total_packets_in_stream} total packets
                        </span>
                      </>
                    ) : (
                      <span className="text-slate-500 italic">No packet metadata</span>
                    )}
                  </div>

                  {/* Node 4: Field Provenance */}
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                    <span className="text-[10px] text-emerald-400 uppercase font-bold block">4. Field Provenance</span>
                    <span className="font-semibold text-slate-200 block">
                      {chain.field_evidence.length} Field Observations
                    </span>
                    <span className="text-[11px] text-slate-400 block font-mono">
                      Status: {chain.evidence_status}
                    </span>
                  </div>
                </div>
              </div>

              {/* Missing Facts Warning (Non-Fabrication Proof) */}
              {chain.missing_evidence_reasons.length > 0 && (
                <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl space-y-2">
                  <h4 className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    Unobserved Network Evidence (Proof of Non-Fabrication)
                  </h4>
                  <ul className="text-xs text-amber-300/90 list-disc list-inside space-y-1">
                    {chain.missing_evidence_reasons.map((reason, idx) => (
                      <li key={idx}>{reason}</li>
                    ))}
                  </ul>
                  <p className="text-[11px] text-amber-400/80 italic pt-1">
                    * The Evidence Engine explicitly marks missing evidence as INSUFFICIENT_EVIDENCE or PARTIAL_EVIDENCE rather than generating unverified assumptions.
                  </p>
                </div>
              )}

              {/* Field Evidence Observations Table */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-purple-400" />
                  Observed Protocol & Field Evidence ({chain.field_evidence.length})
                </h4>

                <div className="overflow-x-auto border border-slate-800 rounded-lg">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Field Name</th>
                        <th className="py-2.5 px-3">Observed Value</th>
                        <th className="py-2.5 px-3">Source Stage</th>
                        <th className="py-2.5 px-3">Description</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {chain.field_evidence.map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-900/40">
                          <td className="py-2.5 px-3 text-purple-300 font-semibold">{item.field_name}</td>
                          <td className="py-2.5 px-3 text-slate-100">
                            {item.is_present ? (
                              String(item.observed_value)
                            ) : (
                              <span className="text-slate-500 italic">UNKNOWN / UNOBSERVED</span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 font-sans">
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700">
                              {item.source_stage}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-slate-400 font-sans">{item.description || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Sample Packet Frames Table */}
              {chain.sample_packets.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      Packet Frames in Evidence Range ({chain.sample_packets.length})
                    </h4>

                    {chain.tcp_stream !== null && chain.tcp_stream !== undefined && onInspectPackets && (
                      <button
                        onClick={() => {
                          onInspectPackets(chain.tcp_stream!);
                          onClose();
                        }}
                        className="flex items-center gap-1 px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-indigo-300 border border-slate-700 rounded transition-colors"
                      >
                        <ExternalLink className="w-3 h-3" />
                        Inspect Stream #{chain.tcp_stream} Packets
                      </button>
                    )}
                  </div>

                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs text-slate-300">
                      <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Frame</th>
                          <th className="py-2 px-3">Timestamp</th>
                          <th className="py-2 px-3">Src IP:Port</th>
                          <th className="py-2 px-3">Dst IP:Port</th>
                          <th className="py-2 px-3">Proto</th>
                          <th className="py-2 px-3">Length</th>
                          <th className="py-2 px-3">Summary</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                        {chain.sample_packets.map((pkt) => (
                          <tr key={pkt.frame_number} className="hover:bg-slate-900/40">
                            <td className="py-2 px-3 text-cyan-400 font-semibold">#{pkt.frame_number}</td>
                            <td className="py-2 px-3 text-slate-400">{pkt.timestamp.toFixed(4)}s</td>
                            <td className="py-2 px-3">{pkt.src_ip}:{pkt.src_port}</td>
                            <td className="py-2 px-3">{pkt.dst_ip}:{pkt.dst_port}</td>
                            <td className="py-2 px-3">
                              <span className="px-1 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                                {pkt.detected_protocol || 'TCP'}
                              </span>
                            </td>
                            <td className="py-2 px-3">{pkt.length_bytes} B</td>
                            <td className="py-2 px-3 text-slate-400 font-sans truncate max-w-[200px]" title={pkt.summary || ''}>
                              {pkt.summary || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
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
