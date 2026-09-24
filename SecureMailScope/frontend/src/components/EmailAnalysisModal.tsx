import React, { useState, useEffect } from 'react';
import {
  X,
  MailCheck,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  ArrowLeft,
  ShieldAlert,
  Lock,
  Layers,
  Terminal,
  Zap,
  Tag,
  KeyRound
} from 'lucide-react';
import {
  fetchJobEmailSessions,
  analyzeJobEmailProtocols,
  EmailSessionAnalysisItem,
  EmailSessionAnalysisListResponse
} from '../services/api';

interface EmailAnalysisModalProps {
  jobId: string;
  filename: string;
  onClose: () => void;
  onInspectFrames?: (streamId: number) => void;
}

export const EmailAnalysisModal: React.FC<EmailAnalysisModalProps> = ({
  jobId,
  filename,
  onClose,
  onInspectFrames,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [data, setData] = useState<EmailSessionAnalysisListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedStreamId, setSelectedStreamId] = useState<number>(0);

  const loadSessions = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    const res = await fetchJobEmailSessions(jobId);
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

  const handleReanalyze = async () => {
    setRefreshing(true);
    setError(null);
    const res = await analyzeJobEmailProtocols(jobId);
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

  const selectedSession: EmailSessionAnalysisItem | undefined = (data?.sessions || []).find(
    (s) => s.tcp_stream === selectedStreamId
  ) || (data?.sessions && data.sessions.length > 0 ? data.sessions[0] : undefined);

  const getStateBadge = (state: string) => {
    switch (state) {
      case 'AUTHENTICATED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3" />
            AUTHENTICATED
          </span>
        );
      case 'STARTTLS_NEGOTIATED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Lock className="w-3 h-3" />
            STARTTLS NEGOTIATED
          </span>
        );
      case 'GREETED':
      case 'CONNECTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Zap className="w-3 h-3" />
            {state}
          </span>
        );
      case 'TRANSACTION':
      case 'SELECTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <MailCheck className="w-3 h-3" />
            {state}
          </span>
        );
      case 'TERMINATED':
      case 'LOGOUT':
      case 'UPDATE':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
            {state}
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            {state}
          </span>
        );
    }
  };

  const getEventTypeBadge = (type: string) => {
    switch (type) {
      case 'BANNER':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">BANNER</span>;
      case 'COMMAND':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">COMMAND</span>;
      case 'STARTTLS_NEGOTIATION':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">STARTTLS</span>;
      case 'AUTH_EXCHANGE':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">AUTH</span>;
      case 'CAPABILITY_LIST':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">CAPA</span>;
      case 'CLOSING':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-500/10 text-slate-400 border border-slate-500/20">CLOSING</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-400 border border-slate-700">RESPONSE</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-6xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <MailCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                Email Protocol Analysis & State Machine
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
              onClick={() => handleReanalyze()}
              disabled={refreshing || loading}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition disabled:opacity-50"
              title="Re-run Email Protocol State Machine Analysis"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Re-analyze Protocols
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 flex overflow-hidden min-h-[460px]">
          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 gap-3">
              <RefreshCw className="w-8 h-8 animate-spin text-blue-400" />
              <p className="text-sm font-medium">Analyzing Email Protocol Transactions & State Machines...</p>
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
              <p className="text-sm font-medium">No email protocol sessions (SMTP/IMAP/POP3) identified in this capture.</p>
            </div>
          ) : (
            <>
              {/* Left Column: Stream Selector */}
              <div className="w-72 border-r border-slate-800 bg-slate-900/40 flex flex-col overflow-y-auto">
                <div className="p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800/80">
                  Email Sessions ({data.sessions.length})
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
                            ? 'bg-blue-500/10 border-l-2 border-blue-400'
                            : 'hover:bg-slate-800/40 border-l-2 border-transparent'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-xs text-blue-300">
                            Stream #{sess.tcp_stream}
                          </span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 font-mono font-bold border border-blue-800">
                            {sess.protocol}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono truncate">
                          {sess.client_ip}:{sess.client_port} <ArrowRight className="inline w-2.5 h-2.5 text-slate-600" /> {sess.server_ip}:{sess.server_port}
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1">
                          <span>{sess.commands_count} commands</span>
                          <span className="text-slate-300 font-mono">{sess.session_state}</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Right Column: Detailed View */}
              {selectedSession && (
                <div className="flex-1 flex flex-col overflow-y-auto bg-slate-950/20 p-6 space-y-6">
                  {/* Top Bar for Selected Stream */}
                  <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-3">
                        <span className="text-sm font-bold text-slate-100 font-mono">
                          Stream #{selectedSession.tcp_stream} ({selectedSession.protocol})
                        </span>
                        {getStateBadge(selectedSession.session_state)}
                      </div>
                      <div className="text-xs text-slate-400 font-mono flex items-center gap-2">
                        <span>{selectedSession.client_ip}:{selectedSession.client_port}</span>
                        <ArrowRight className="w-3 h-3 text-slate-600" />
                        <span>{selectedSession.server_ip}:{selectedSession.server_port}</span>
                        {selectedSession.first_frame_number && (
                          <>
                            <span className="text-slate-600">•</span>
                            <span>Frames #{selectedSession.first_frame_number}-{selectedSession.last_frame_number}</span>
                          </>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      {selectedSession.starttls_advertised ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <Lock className="w-3 h-3" />
                          STARTTLS Advertised
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          <AlertTriangle className="w-3 h-3" />
                          No STARTTLS
                        </span>
                      )}

                      {onInspectFrames && (
                        <button
                          onClick={() => onInspectFrames(selectedSession.tcp_stream)}
                          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition"
                        >
                          <Layers className="w-3.5 h-3.5" />
                          Inspect Frames
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Security Warnings Banner */}
                  {selectedSession.security_warnings && selectedSession.security_warnings.length > 0 && (
                    <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 flex flex-col gap-2">
                      <div className="flex items-center gap-2 text-xs font-semibold text-amber-400">
                        <ShieldAlert className="w-4 h-4" />
                        <span>Security & Forensic Posture Warnings ({selectedSession.security_warnings.length})</span>
                      </div>
                      <div className="space-y-1.5">
                        {selectedSession.security_warnings.map((warn, i) => (
                          <div key={i} className="text-xs text-amber-300/90 font-mono bg-amber-500/10 px-3 py-1.5 rounded border border-amber-500/20">
                            {warn}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Session Context Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Server Banner */}
                    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-2">
                      <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                        <Terminal className="w-3.5 h-3.5 text-blue-400" />
                        <span>Server Greeting Banner</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-950 text-slate-300 font-mono text-xs break-all">
                        {selectedSession.server_banner || '<None observed>'}
                      </div>
                    </div>

                    {/* Client Greeting */}
                    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-2">
                      <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                        <Terminal className="w-3.5 h-3.5 text-indigo-400" />
                        <span>Client Greeting (EHLO / HELO)</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-950 text-slate-300 font-mono text-xs break-all">
                        {selectedSession.client_greeting || '<None observed>'}
                      </div>
                    </div>
                  </div>

                  {/* Capabilities & Auth Details */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Capabilities */}
                    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-2">
                      <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                        <Tag className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Advertised Capabilities ({selectedSession.capabilities?.length || 0})</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {selectedSession.capabilities && selectedSession.capabilities.length > 0 ? (
                          selectedSession.capabilities.map((cap, i) => (
                            <span
                              key={i}
                              className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                                cap.includes('STARTTLS') || cap === 'STLS'
                                  ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                                  : cap.startsWith('AUTH') || cap.startsWith('SASL')
                                  ? 'bg-purple-500/10 text-purple-300 border-purple-500/30'
                                  : 'bg-slate-800 text-slate-300 border-slate-700'
                              }`}
                            >
                              {cap}
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-slate-500 italic">No capabilities advertised.</span>
                        )}
                      </div>
                    </div>

                    {/* Authentication Analysis */}
                    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-2">
                      <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                        <KeyRound className="w-3.5 h-3.5 text-purple-400" />
                        <span>Authentication Analysis</span>
                      </div>
                      <div className="space-y-2 text-xs">
                        <div className="flex items-center justify-between text-slate-300">
                          <span className="text-slate-400">Auth Attempted:</span>
                          <span className="font-semibold">{selectedSession.auth_attempted ? 'Yes' : 'No'}</span>
                        </div>
                        {selectedSession.auth_attempted && (
                          <div className="flex items-center justify-between text-slate-300">
                            <span className="text-slate-400">Auth Outcome:</span>
                            <span className={`font-semibold ${selectedSession.auth_successful ? 'text-emerald-400' : 'text-rose-400'}`}>
                              {selectedSession.auth_successful === true ? 'Successful' : selectedSession.auth_successful === false ? 'Failed' : 'Unknown'}
                            </span>
                          </div>
                        )}
                        {selectedSession.auth_mechanisms && selectedSession.auth_mechanisms.length > 0 && (
                          <div className="flex items-center justify-between text-slate-300">
                            <span className="text-slate-400">Supported Mechs:</span>
                            <span className="font-mono text-purple-300">{selectedSession.auth_mechanisms.join(', ')}</span>
                          </div>
                        )}
                        {selectedSession.auth_usernames && selectedSession.auth_usernames.length > 0 && (
                          <div className="flex items-center justify-between text-slate-300">
                            <span className="text-slate-400">Observed Users:</span>
                            <span className="font-mono text-indigo-300">{selectedSession.auth_usernames.join(', ')}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Chronological Event Timeline */}
                  <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                        <Clock className="w-3.5 h-3.5 text-indigo-400" />
                        <span>Command-Response Event Timeline ({selectedSession.events?.length || 0} events)</span>
                      </h3>
                      <span className="text-xs text-slate-400 font-mono">
                        {selectedSession.commands_count} client commands
                      </span>
                    </div>

                    <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg overflow-hidden bg-slate-950/40">
                      {(!selectedSession.events || selectedSession.events.length === 0) ? (
                        <div className="p-4 text-center text-slate-500 text-xs italic">
                          No protocol events recorded.
                        </div>
                      ) : (
                        selectedSession.events.map((evt, idx) => {
                          const isClient = evt.direction === 'c2s';
                          return (
                            <div key={idx} className="p-3 flex items-start justify-between gap-4 text-xs font-mono">
                              <div className="flex items-start gap-3 flex-1 min-w-0">
                                <div className="mt-0.5">
                                  {isClient ? (
                                    <div className="p-1 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20" title="Client to Server">
                                      <ArrowRight className="w-3 h-3" />
                                    </div>
                                  ) : (
                                    <div className="p-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" title="Server to Client">
                                      <ArrowLeft className="w-3 h-3" />
                                    </div>
                                  )}
                                </div>
                                <div className="flex flex-col gap-1 min-w-0 flex-1">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    {getEventTypeBadge(evt.event_type)}
                                    {evt.command && (
                                      <span className="px-1.5 py-0.2 rounded font-bold text-slate-200 bg-slate-800 border border-slate-700">
                                        {evt.command}
                                      </span>
                                    )}
                                    {evt.response_code && (
                                      <span className="px-1.5 py-0.2 rounded font-bold text-slate-200 bg-slate-800 border border-slate-700">
                                        {evt.response_code}
                                      </span>
                                    )}
                                    {evt.frame_number && (
                                      <span className="text-[10px] text-slate-500">
                                        Frame #{evt.frame_number}
                                      </span>
                                    )}
                                  </div>
                                  <div className="text-slate-300 break-words text-[11px] select-text">
                                    {evt.raw_text}
                                  </div>
                                </div>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
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
