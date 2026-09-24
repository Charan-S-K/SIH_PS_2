import React, { useState, useEffect } from 'react';
import {
  X,
  MessageSquare,
  Layers,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  Copy,
  Check,
  Zap,
  Split,
  FileText
} from 'lucide-react';
import {
  fetchJobSessions,
  reconstructJobSessions,
  TcpSessionItem,
  TcpSessionListResponse
} from '../services/api';

interface SessionsModalProps {
  jobId: string;
  filename: string;
  onClose: () => void;
  onInspectFrames?: (streamId: number) => void;
}

export const SessionsModal: React.FC<SessionsModalProps> = ({
  jobId,
  filename,
  onClose,
  onInspectFrames,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [data, setData] = useState<TcpSessionListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedStreamId, setSelectedStreamId] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<'flow' | 'payload' | 'diagnostics'>('flow');
  const [copied, setCopied] = useState<boolean>(false);

  const loadSessions = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    const res = await fetchJobSessions(jobId);
    if (res.error) {
      setError(res.error);
    } else {
      setData(res.data);
      if (res.data && res.data.sessions.length > 0) {
        setSelectedStreamId(res.data.sessions[0].tcp_stream);
      }
    }
    setLoading(false);
    setRefreshing(false);
  };

  const handleReconstruct = async () => {
    setRefreshing(true);
    setError(null);
    const res = await reconstructJobSessions(jobId);
    if (res.error) {
      setError(res.error);
    } else {
      setData(res.data);
      if (res.data && res.data.sessions.length > 0) {
        setSelectedStreamId(res.data.sessions[0].tcp_stream);
      }
    }
    setRefreshing(false);
  };

  useEffect(() => {
    loadSessions();
  }, [jobId]);

  const selectedSession: TcpSessionItem | undefined = (data?.sessions || []).find(
    (s) => s.tcp_stream === selectedStreamId
  ) || (data?.sessions && data.sessions.length > 0 ? data.sessions[0] : undefined);

  const handleCopyFlow = () => {
    if (!selectedSession || !selectedSession.conversation_flow) return;
    const formatted = selectedSession.conversation_flow
      .map((t) => `[${t.direction === 'c2s' ? 'CLIENT' : 'SERVER'} - Frames ${t.start_frame}-${t.end_frame}]\n${t.text_preview}`)
      .join('\n\n');
    navigator.clipboard.writeText(formatted);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStateBadge = (state: string) => {
    switch (state) {
      case 'CLOSED_FIN':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3" />
            CLOSED (FIN)
          </span>
        );
      case 'ESTABLISHED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Zap className="w-3 h-3" />
            ESTABLISHED
          </span>
        );
      case 'RESET':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <AlertTriangle className="w-3 h-3" />
            RESET (RST)
          </span>
        );
      case 'CLOSED_HALF':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Split className="w-3 h-3" />
            HALF CLOSED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
            INCOMPLETE
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-6xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <MessageSquare className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                TCP Session Reconstruction & Conversation Stream
              </h2>
              <p className="text-xs text-slate-400 flex items-center gap-2 font-mono">
                <span>{filename}</span>
                <span className="text-slate-600">•</span>
                <span>Job: {jobId}</span>
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleReconstruct()}
              disabled={refreshing || loading}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition disabled:opacity-50"
              title="Re-run TCP sequence reconstruction"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Reconstruct Sessions
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Global Summary Metrics Bar */}
        {data && (
          <div className="px-6 py-3 bg-slate-950/60 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Total TCP Sessions:</span>
                <span className="font-semibold text-slate-200">{data.total_sessions}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Retransmissions:</span>
                <span className={`font-semibold ${data.sessions.reduce((acc, s) => acc + s.retransmissions_count, 0) > 0 ? 'text-amber-400' : 'text-slate-200'}`}>
                  {data.sessions.reduce((acc, s) => acc + s.retransmissions_count, 0)}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Out of Order Segments:</span>
                <span className={`font-semibold ${data.sessions.reduce((acc, s) => acc + s.out_of_order_count, 0) > 0 ? 'text-amber-400' : 'text-slate-200'}`}>
                  {data.sessions.reduce((acc, s) => acc + s.out_of_order_count, 0)}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Sequence Gaps (Loss):</span>
                <span className={`font-semibold ${data.sessions.reduce((acc, s) => acc + s.gaps_count, 0) > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {data.sessions.reduce((acc, s) => acc + s.gaps_count, 0)}
                </span>
              </div>
            </div>
            {selectedSession && onInspectFrames && (
              <button
                onClick={() => onInspectFrames(selectedSession.tcp_stream)}
                className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium text-indigo-300 bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-500/20 rounded-md transition"
              >
                <Layers className="w-3.5 h-3.5" />
                Inspect Stream {selectedSession.tcp_stream} Frames
              </button>
            )}
          </div>
        )}

        {/* Content Body */}
        <div className="flex-1 flex overflow-hidden min-h-[460px]">
          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 gap-3">
              <RefreshCw className="w-8 h-8 animate-spin text-indigo-400" />
              <p className="text-sm font-medium">Reconstructing TCP Sessions & Sequence Numbers...</p>
            </div>
          ) : error ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-rose-400 gap-3">
              <AlertTriangle className="w-8 h-8" />
              <p className="text-sm font-medium">{error}</p>
              <button
                onClick={() => loadSessions()}
                className="px-4 py-2 mt-2 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition"
              >
                Retry
              </button>
            </div>
          ) : !data || data.sessions.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 gap-3">
              <Layers className="w-8 h-8 text-slate-600" />
              <p className="text-sm font-medium">No TCP conversations detected in this capture.</p>
            </div>
          ) : (
            <>
              {/* Left Column: Stream Selector */}
              <div className="w-72 border-r border-slate-800 bg-slate-900/40 flex flex-col overflow-y-auto">
                <div className="p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800/80">
                  TCP Streams ({data.sessions.length})
                </div>
                <div className="divide-y divide-slate-800/50">
                  {data.sessions.map((sess) => {
                    const isSelected = sess.tcp_stream === selectedStreamId;
                    return (
                      <button
                        key={sess.id}
                        onClick={() => setSelectedStreamId(sess.tcp_stream)}
                        className={`w-full text-left p-3.5 transition flex flex-col gap-1.5 ${
                          isSelected
                            ? 'bg-indigo-500/10 border-l-2 border-indigo-400'
                            : 'hover:bg-slate-800/40 border-l-2 border-transparent'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-xs text-indigo-300">
                            Stream #{sess.tcp_stream}
                          </span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                            {sess.protocol}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono truncate">
                          {sess.client_ip}:{sess.client_port} <ArrowRight className="inline w-2.5 h-2.5 text-slate-600" /> {sess.server_ip}:{sess.server_port}
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1">
                          <span>{sess.packet_count} packets</span>
                          <span>{sess.total_payload_bytes} bytes</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Right Column: Detailed View */}
              {selectedSession && (
                <div className="flex-1 flex flex-col overflow-hidden bg-slate-950/20">
                  {/* Selected Stream Info Bar */}
                  <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/30 flex flex-wrap items-center justify-between gap-4">
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-3">
                        <span className="text-sm font-bold text-slate-100 font-mono">
                          Stream #{selectedSession.tcp_stream}
                        </span>
                        {getStateBadge(selectedSession.session_state)}
                        <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-indigo-300 font-mono border border-slate-700">
                          {selectedSession.protocol}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 font-mono flex items-center gap-2">
                        <span>Client: {selectedSession.client_ip}:{selectedSession.client_port}</span>
                        <ArrowRight className="w-3 h-3 text-slate-600" />
                        <span>Server: {selectedSession.server_ip}:{selectedSession.server_port}</span>
                        <span className="text-slate-600">•</span>
                        <span>Frames: {selectedSession.first_frame_number}-{selectedSession.last_frame_number}</span>
                        <span className="text-slate-600">•</span>
                        <span>Duration: {selectedSession.duration_seconds}s</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2 text-xs">
                        <span className="px-2 py-1 rounded bg-slate-800/80 text-slate-300 font-mono border border-slate-700/60">
                          C2S: {selectedSession.c2s_bytes} B ({selectedSession.c2s_packet_count} pkts)
                        </span>
                        <span className="px-2 py-1 rounded bg-slate-800/80 text-slate-300 font-mono border border-slate-700/60">
                          S2C: {selectedSession.s2c_bytes} B ({selectedSession.s2c_packet_count} pkts)
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Tabs Bar */}
                  <div className="flex items-center justify-between px-6 border-b border-slate-800 bg-slate-900/20">
                    <div className="flex items-center gap-4">
                      <button
                        onClick={() => setActiveTab('flow')}
                        className={`py-3 text-xs font-semibold flex items-center gap-1.5 border-b-2 transition ${
                          activeTab === 'flow'
                            ? 'text-indigo-400 border-indigo-500'
                            : 'text-slate-400 border-transparent hover:text-slate-200'
                        }`}
                      >
                        <MessageSquare className="w-3.5 h-3.5" />
                        Follow Stream ({selectedSession.conversation_flow?.length || 0} turns)
                      </button>
                      <button
                        onClick={() => setActiveTab('payload')}
                        className={`py-3 text-xs font-semibold flex items-center gap-1.5 border-b-2 transition ${
                          activeTab === 'payload'
                            ? 'text-indigo-400 border-indigo-500'
                            : 'text-slate-400 border-transparent hover:text-slate-200'
                        }`}
                      >
                        <FileText className="w-3.5 h-3.5" />
                        Unidirectional Payloads
                      </button>
                      <button
                        onClick={() => setActiveTab('diagnostics')}
                        className={`py-3 text-xs font-semibold flex items-center gap-1.5 border-b-2 transition ${
                          activeTab === 'diagnostics'
                            ? 'text-indigo-400 border-indigo-500'
                            : 'text-slate-400 border-transparent hover:text-slate-200'
                        }`}
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Reassembly Diagnostics ({selectedSession.retransmissions_count + selectedSession.out_of_order_count + selectedSession.gaps_count} events)
                      </button>
                    </div>

                    {activeTab === 'flow' && (
                      <button
                        onClick={handleCopyFlow}
                        className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-slate-100 bg-slate-800 hover:bg-slate-700 rounded transition"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        {copied ? 'Copied!' : 'Copy Stream'}
                      </button>
                    )}
                  </div>

                  {/* Tab Contents */}
                  <div className="flex-1 p-6 overflow-y-auto font-mono text-xs">
                    {/* TAB 1: Follow Stream (Conversational Turns) */}
                    {activeTab === 'flow' && (
                      <div className="flex flex-col gap-4">
                        {(!selectedSession.conversation_flow || selectedSession.conversation_flow.length === 0) ? (
                          <div className="p-8 text-center text-slate-400 bg-slate-900/40 rounded-lg border border-slate-800">
                            No application payload exchanged in this session (handshake or control traffic only).
                          </div>
                        ) : (
                          selectedSession.conversation_flow.map((turn, idx) => {
                            const isClient = turn.direction === 'c2s';
                            return (
                              <div
                                key={idx}
                                className={`flex flex-col rounded-lg border overflow-hidden shadow-sm ${
                                  isClient
                                    ? 'bg-indigo-950/20 border-indigo-500/30'
                                    : 'bg-emerald-950/20 border-emerald-500/30'
                                }`}
                              >
                                <div
                                  className={`px-3 py-1.5 flex items-center justify-between text-[11px] font-semibold ${
                                    isClient
                                      ? 'bg-indigo-500/10 text-indigo-300 border-b border-indigo-500/20'
                                      : 'bg-emerald-500/10 text-emerald-300 border-b border-emerald-500/20'
                                  }`}
                                >
                                  <div className="flex items-center gap-2">
                                    <span className="uppercase tracking-wider font-bold">
                                      {isClient ? 'Client' : 'Server'}
                                    </span>
                                    <span className="text-slate-500 font-normal">
                                      (Frames #{turn.start_frame}{turn.start_frame !== turn.end_frame ? `-${turn.end_frame}` : ''})
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-3 font-normal text-slate-400 text-[10px]">
                                    <span>{turn.byte_length} bytes</span>
                                    <span>t={turn.start_time.toFixed(4)}s</span>
                                  </div>
                                </div>
                                <div className="p-3 whitespace-pre-wrap font-mono text-slate-200 text-xs leading-relaxed select-text">
                                  {turn.text_preview || '<Empty payload>'}
                                </div>
                              </div>
                            );
                          })
                        )}
                      </div>
                    )}

                    {/* TAB 2: Unidirectional Payloads */}
                    {activeTab === 'payload' && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="flex flex-col gap-2">
                          <div className="flex items-center justify-between text-xs font-semibold text-indigo-300">
                            <span>Client to Server (C2S) — {selectedSession.c2s_bytes} bytes</span>
                          </div>
                          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 font-mono text-xs whitespace-pre-wrap max-h-[400px] overflow-y-auto">
                            {selectedSession.c2s_payload_preview || '<No payload sent by client>'}
                          </div>
                        </div>

                        <div className="flex flex-col gap-2">
                          <div className="flex items-center justify-between text-xs font-semibold text-emerald-300">
                            <span>Server to Client (S2C) — {selectedSession.s2c_bytes} bytes</span>
                          </div>
                          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 font-mono text-xs whitespace-pre-wrap max-h-[400px] overflow-y-auto">
                            {selectedSession.s2c_payload_preview || '<No payload sent by server>'}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* TAB 3: Reassembly Diagnostics */}
                    {activeTab === 'diagnostics' && (
                      <div className="flex flex-col gap-6">
                        {/* Lifecycle flags */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                            <div className="text-[10px] text-slate-400 uppercase">SYN Handshake</div>
                            <div className="text-xs font-semibold text-slate-200 mt-1">
                              {selectedSession.syn_frame_number ? `Frame #${selectedSession.syn_frame_number}` : 'Not Seen'}
                            </div>
                          </div>
                          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                            <div className="text-[10px] text-slate-400 uppercase">SYN-ACK Handshake</div>
                            <div className="text-xs font-semibold text-slate-200 mt-1">
                              {selectedSession.syn_ack_frame_number ? `Frame #${selectedSession.syn_ack_frame_number}` : 'Not Seen'}
                            </div>
                          </div>
                          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                            <div className="text-[10px] text-slate-400 uppercase">FIN Teardown</div>
                            <div className="text-xs font-semibold text-slate-200 mt-1">
                              {selectedSession.fin_frame_numbers && selectedSession.fin_frame_numbers.length > 0
                                ? selectedSession.fin_frame_numbers.map(f => `#${f}`).join(', ')
                                : 'None'}
                            </div>
                          </div>
                          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                            <div className="text-[10px] text-slate-400 uppercase">RST Abort</div>
                            <div className="text-xs font-semibold text-slate-200 mt-1">
                              {selectedSession.rst_frame_numbers && selectedSession.rst_frame_numbers.length > 0
                                ? selectedSession.rst_frame_numbers.map(f => `#${f}`).join(', ')
                                : 'None'}
                            </div>
                          </div>
                        </div>

                        {/* Diagnostics Lists */}
                        {selectedSession.reconstruction_metadata && (
                          <div className="flex flex-col gap-4">
                            {/* Retransmissions */}
                            <div className="flex flex-col gap-2">
                              <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                                Retransmissions & Duplicates ({selectedSession.retransmissions_count})
                              </h4>
                              {selectedSession.retransmissions_count === 0 ? (
                                <p className="text-slate-400 text-xs italic">No retransmissions detected in this stream.</p>
                              ) : (
                                <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg overflow-hidden bg-slate-950/40">
                                  {(selectedSession.reconstruction_metadata.retransmissions || []).map((r, i) => (
                                    <div key={i} className="p-2.5 flex items-center justify-between text-xs font-mono">
                                      <span className="text-slate-300">Frame #{r.frame_number}</span>
                                      <span className="text-amber-400">{r.type}</span>
                                      <span className="text-slate-400">Seq: {r.seq}</span>
                                      <span className="text-slate-400">{r.length || r.new_bytes} bytes</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>

                            {/* Out of order */}
                            <div className="flex flex-col gap-2">
                              <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                                <Clock className="w-3.5 h-3.5 text-blue-400" />
                                Out-of-Order Deliveries ({selectedSession.out_of_order_count})
                              </h4>
                              {selectedSession.out_of_order_count === 0 ? (
                                <p className="text-slate-400 text-xs italic">All segments arrived strictly in sequence.</p>
                              ) : (
                                <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg overflow-hidden bg-slate-950/40">
                                  {(selectedSession.reconstruction_metadata.out_of_order_segments || []).map((o, i) => (
                                    <div key={i} className="p-2.5 flex items-center justify-between text-xs font-mono">
                                      <span className="text-slate-300">Frame #{o.frame_number}</span>
                                      <span className="text-blue-400">Seq: {o.seq}</span>
                                      <span className="text-slate-400">Arrived after seq: {o.highest_seq_previously_seen}</span>
                                      <span className="text-slate-400">{o.length} bytes</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>

                            {/* Gaps */}
                            <div className="flex flex-col gap-2">
                              <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                                Sequence Gaps / Missing Bytes ({selectedSession.gaps_count})
                              </h4>
                              {selectedSession.gaps_count === 0 ? (
                                <p className="text-slate-400 text-xs italic">No sequence gaps detected (100% contiguous stream).</p>
                              ) : (
                                <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg overflow-hidden bg-slate-950/40">
                                  {(selectedSession.reconstruction_metadata.gaps || []).map((g, i) => (
                                    <div key={i} className="p-2.5 flex items-center justify-between text-xs font-mono">
                                      <span className="text-rose-400 font-bold">{g.missing_bytes} missing bytes</span>
                                      <span className="text-slate-400">Range: {g.missing_start_seq} - {g.missing_end_seq}</span>
                                      <span className="text-slate-300">Resumed at Frame #{g.resuming_frame}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
