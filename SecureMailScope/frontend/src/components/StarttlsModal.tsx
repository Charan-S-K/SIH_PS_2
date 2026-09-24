import React, { useState, useEffect } from 'react';
import {
  X,
  Lock,
  Unlock,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  ArrowRight,
  Layers,
  Terminal,
  KeyRound,
  ExternalLink,
  Info
} from 'lucide-react';
import {
  fetchJobStarttls,
  analyzeJobStarttls,
  StarttlsAnalysisItem,
  StarttlsAnalysisListResponse
} from '../services/api';

interface StarttlsModalProps {
  jobId: string;
  filename: string;
  onClose: () => void;
  onInspectFrames?: (streamId: number) => void;
}

export const StarttlsModal: React.FC<StarttlsModalProps> = ({
  jobId,
  filename,
  onClose,
  onInspectFrames,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [data, setData] = useState<StarttlsAnalysisListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedStreamId, setSelectedStreamId] = useState<number>(0);

  const loadData = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    const res = await fetchJobStarttls(jobId);
    if (res.error) {
      setError(res.error);
    } else {
      setData(res.data);
      if (res.data && res.data.analyses.length > 0) {
        setSelectedStreamId(res.data.analyses[0].tcp_stream);
      }
    }
    setLoading(false);
    setRefreshing(false);
  };

  const handleReanalyze = async () => {
    setRefreshing(true);
    setError(null);
    const res = await analyzeJobStarttls(jobId);
    if (res.error) {
      setError(res.error);
    } else {
      setData(res.data);
      if (res.data && res.data.analyses.length > 0) {
        setSelectedStreamId(res.data.analyses[0].tcp_stream);
      }
    }
    setRefreshing(false);
  };

  useEffect(() => {
    loadData();
  }, [jobId]);

  const selectedItem: StarttlsAnalysisItem | undefined = (data?.analyses || []).find(
    (a) => a.tcp_stream === selectedStreamId
  ) || (data?.analyses && data.analyses.length > 0 ? data.analyses[0] : undefined);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'UPGRADED_SUCCESS':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Lock className="w-3 h-3" />
            TLS UPGRADED
          </span>
        );
      case 'DIRECT_TLS':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <ShieldCheck className="w-3 h-3" />
            DIRECT TLS (IMPLICIT)
          </span>
        );
      case 'CLEARTEXT_AUTH_AFTER_ADVERTISED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30 animate-pulse">
            <KeyRound className="w-3 h-3" />
            CLEARTEXT AUTH IN CLEAR
          </span>
        );
      case 'NOT_REQUESTED_IGNORED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Unlock className="w-3 h-3" />
            DOWNGRADE / STRIPPED RISK
          </span>
        );
      case 'UPGRADE_REJECTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle className="w-3 h-3" />
            UPGRADE REJECTED
          </span>
        );
      case 'UPGRADE_ACCEPTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <CheckCircle2 className="w-3 h-3" />
            ACCEPTED (AWAITING TLS)
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
            <Info className="w-3 h-3" />
            NOT ADVERTISED
          </span>
        );
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">{sev}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-6xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                STARTTLS & Opportunistic TLS Posture Analysis
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
              title="Re-run STARTTLS Negotiation and Downgrade Inspection"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Re-analyze STARTTLS
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Global Summary Statistics Banner */}
        {data && (
          <div className="grid grid-cols-4 gap-4 px-6 py-3 bg-slate-950/50 border-b border-slate-800/80 text-xs">
            <div className="flex flex-col">
              <span className="text-slate-400">Total Email Streams</span>
              <span className="text-base font-semibold text-slate-200 font-mono">{data.total_streams}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-400">Encrypted / Upgraded</span>
              <span className="text-base font-semibold text-emerald-400 font-mono">{data.upgraded_count}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-400">Downgrade / Stripping Risks</span>
              <span className={`text-base font-semibold font-mono ${data.downgrade_risk_count > 0 ? 'text-amber-400' : 'text-slate-300'}`}>
                {data.downgrade_risk_count}
              </span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-400">Critical Posture Alerts</span>
              <span className={`text-base font-semibold font-mono ${data.critical_findings_count > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
                {data.critical_findings_count}
              </span>
            </div>
          </div>
        )}

        {/* Content Body */}
        <div className="flex-1 flex overflow-hidden min-h-[460px]">
          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 gap-3">
              <RefreshCw className="w-8 h-8 animate-spin text-emerald-400" />
              <p className="text-sm font-medium">Analyzing STARTTLS Handshake Transitions & Downgrade Risk...</p>
            </div>
          ) : error ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-rose-400 gap-3">
              <AlertTriangle className="w-8 h-8" />
              <p className="text-sm font-medium">{error}</p>
              <button
                onClick={() => loadData()}
                className="px-4 py-2 mt-2 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition"
              >
                Retry
              </button>
            </div>
          ) : !data || data.analyses.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 gap-3">
              <Layers className="w-8 h-8 text-slate-600" />
              <p className="text-sm font-medium">No email streams detected for STARTTLS posture evaluation.</p>
            </div>
          ) : (
            <>
              {/* Left Column: Stream Selector */}
              <div className="w-80 border-r border-slate-800 bg-slate-900/40 flex flex-col overflow-y-auto">
                <div className="p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800/80">
                  Monitored Streams ({data.analyses.length})
                </div>
                <div className="divide-y divide-slate-800/50">
                  {data.analyses.map((item) => {
                    const isSelected = item.tcp_stream === selectedStreamId;
                    const hasCritical = item.findings?.some((f) => f.severity === 'CRITICAL');
                    const isDowngrade = ['NOT_REQUESTED_IGNORED', 'UPGRADE_REJECTED'].includes(item.upgrade_status);

                    return (
                      <button
                        key={item.id}
                        onClick={() => setSelectedStreamId(item.tcp_stream)}
                        className={`w-full text-left p-3.5 transition flex flex-col gap-1.5 ${
                          isSelected
                            ? 'bg-emerald-500/10 border-l-2 border-emerald-400'
                            : 'hover:bg-slate-800/40 border-l-2 border-transparent'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-xs text-emerald-300">
                            Stream #{item.tcp_stream}
                          </span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">
                            {item.protocol} :{item.server_port}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono truncate">
                          {item.client_ip}:{item.client_port} <ArrowRight className="inline w-2.5 h-2.5 text-slate-600" /> {item.server_ip}:{item.server_port}
                        </div>
                        <div className="flex items-center justify-between text-[10px] pt-1">
                          <div>{getStatusBadge(item.upgrade_status)}</div>
                          {hasCritical ? (
                            <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold border border-rose-500/30">
                              ALERT
                            </span>
                          ) : isDowngrade ? (
                            <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold border border-amber-500/30">
                              RISK
                            </span>
                          ) : null}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Right Column: Selected Stream STARTTLS Posture */}
              <div className="flex-1 flex flex-col overflow-y-auto p-6 space-y-6">
                {selectedItem ? (
                  <>
                    {/* Stream Header */}
                    <div className="flex items-center justify-between p-4 rounded-xl bg-slate-950/40 border border-slate-800">
                      <div>
                        <div className="flex items-center gap-3">
                          <h3 className="text-base font-bold text-slate-100 font-mono">
                            Stream #{selectedItem.tcp_stream}
                          </h3>
                          <span className="text-xs px-2 py-0.5 rounded font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800">
                            {selectedItem.protocol}
                          </span>
                          {getStatusBadge(selectedItem.upgrade_status)}
                        </div>
                        <p className="text-xs text-slate-400 font-mono mt-1">
                          Client: {selectedItem.client_ip}:{selectedItem.client_port} &bull; Server: {selectedItem.server_ip}:{selectedItem.server_port}
                        </p>
                      </div>

                      {onInspectFrames && (
                        <button
                          onClick={() => onInspectFrames(selectedItem.tcp_stream)}
                          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 bg-blue-950/40 hover:bg-blue-900/40 border border-blue-800/60 rounded-lg transition"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                          Inspect Frames
                        </button>
                      )}
                    </div>

                    {/* Upgrade Lifecycle Stepper */}
                    {selectedItem.upgrade_status !== 'DIRECT_TLS' ? (
                      <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                          <Layers className="w-4 h-4 text-emerald-400" />
                          Opportunistic TLS Upgrade Stepper
                        </h4>

                        <div className="grid grid-cols-4 gap-3 relative">
                          {/* Step 1: Advertisement */}
                          <div
                            className={`p-3.5 rounded-lg border flex flex-col justify-between ${
                              selectedItem.advertised
                                ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                                : 'bg-slate-900/50 border-slate-800 text-slate-500'
                            }`}
                          >
                            <div>
                              <div className="flex items-center justify-between mb-1.5">
                                <span className="text-[10px] font-bold tracking-wider uppercase">Step 1</span>
                                {selectedItem.advertised ? (
                                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                                ) : (
                                  <XCircle className="w-4 h-4 text-slate-600" />
                                )}
                              </div>
                              <div className="text-xs font-bold text-slate-200">STARTTLS Offered</div>
                              <div className="text-[11px] font-mono mt-1 text-slate-400 truncate">
                                {selectedItem.advertised_command || 'Not offered in capabilities'}
                              </div>
                            </div>
                            {selectedItem.advertised_frame && (
                              <div className="mt-2 text-[10px] font-mono text-emerald-400/80">
                                Frame #{selectedItem.advertised_frame}
                              </div>
                            )}
                          </div>

                          {/* Step 2: Request */}
                          <div
                            className={`p-3.5 rounded-lg border flex flex-col justify-between ${
                              selectedItem.requested
                                ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                                : selectedItem.advertised
                                ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                                : 'bg-slate-900/50 border-slate-800 text-slate-500'
                            }`}
                          >
                            <div>
                              <div className="flex items-center justify-between mb-1.5">
                                <span className="text-[10px] font-bold tracking-wider uppercase">Step 2</span>
                                {selectedItem.requested ? (
                                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                                ) : selectedItem.advertised ? (
                                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                                ) : (
                                  <XCircle className="w-4 h-4 text-slate-600" />
                                )}
                              </div>
                              <div className="text-xs font-bold text-slate-200">Client Upgrade Request</div>
                              <div className="text-[11px] font-mono mt-1 text-slate-400 truncate">
                                {selectedItem.requested_command || (selectedItem.advertised ? 'Ignored by client' : 'N/A')}
                              </div>
                            </div>
                            {selectedItem.requested_frame && (
                              <div className="mt-2 text-[10px] font-mono text-emerald-400/80">
                                Frame #{selectedItem.requested_frame}
                              </div>
                            )}
                          </div>

                          {/* Step 3: Server Acceptance */}
                          <div
                            className={`p-3.5 rounded-lg border flex flex-col justify-between ${
                              selectedItem.accepted
                                ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                                : selectedItem.requested
                                ? 'bg-rose-950/20 border-rose-500/40 text-rose-300'
                                : 'bg-slate-900/50 border-slate-800 text-slate-500'
                            }`}
                          >
                            <div>
                              <div className="flex items-center justify-between mb-1.5">
                                <span className="text-[10px] font-bold tracking-wider uppercase">Step 3</span>
                                {selectedItem.accepted ? (
                                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                                ) : selectedItem.requested ? (
                                  <XCircle className="w-4 h-4 text-rose-400" />
                                ) : (
                                  <XCircle className="w-4 h-4 text-slate-600" />
                                )}
                              </div>
                              <div className="text-xs font-bold text-slate-200">Server Response</div>
                              <div className="text-[11px] font-mono mt-1 text-slate-400 truncate">
                                {selectedItem.response_text || selectedItem.response_code || 'Pending / Skipped'}
                              </div>
                            </div>
                            {selectedItem.response_frame && (
                              <div className="mt-2 text-[10px] font-mono text-emerald-400/80">
                                Frame #{selectedItem.response_frame}
                              </div>
                            )}
                          </div>

                          {/* Step 4: TLS Record Layer Transition */}
                          <div
                            className={`p-3.5 rounded-lg border flex flex-col justify-between ${
                              selectedItem.tls_record_detected
                                ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                                : selectedItem.accepted
                                ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                                : 'bg-slate-900/50 border-slate-800 text-slate-500'
                            }`}
                          >
                            <div>
                              <div className="flex items-center justify-between mb-1.5">
                                <span className="text-[10px] font-bold tracking-wider uppercase">Step 4</span>
                                {selectedItem.tls_record_detected ? (
                                  <Lock className="w-4 h-4 text-emerald-400" />
                                ) : (
                                  <Unlock className="w-4 h-4 text-slate-600" />
                                )}
                              </div>
                              <div className="text-xs font-bold text-slate-200">TLS Record Layer</div>
                              <div className="text-[11px] font-mono mt-1 text-slate-400 truncate">
                                {selectedItem.tls_record_detected ? 'Handshake (0x16 0x03)' : 'No TLS records seen'}
                              </div>
                            </div>
                            {selectedItem.tls_start_frame && (
                              <div className="mt-2 text-[10px] font-mono text-emerald-400/80">
                                Frame #{selectedItem.tls_start_frame}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-800/40 text-cyan-300 flex items-start gap-3">
                        <ShieldCheck className="w-5 h-5 mt-0.5 text-cyan-400" />
                        <div>
                          <div className="text-sm font-semibold text-cyan-200">Direct Implicit TLS Connection</div>
                          <div className="text-xs text-cyan-300/80 mt-1">
                            This session connects directly to port {selectedItem.server_port}, which enforces immediate TLS encapsulation from packet 1. Opportunistic STARTTLS handshake is neither expected nor required.
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Critical Posture Findings */}
                    {selectedItem.findings && selectedItem.findings.length > 0 && (
                      <div className="space-y-3">
                        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-rose-400" />
                          Forensic Security Findings & Alerts ({selectedItem.findings.length})
                        </h4>

                        <div className="space-y-2">
                          {selectedItem.findings.map((f, idx) => (
                            <div
                              key={idx}
                              className={`p-3.5 rounded-lg border flex items-start gap-3 ${
                                f.severity === 'CRITICAL'
                                  ? 'bg-rose-950/25 border-rose-500/40 text-rose-200'
                                  : f.severity === 'HIGH'
                                  ? 'bg-amber-950/25 border-amber-500/40 text-amber-200'
                                  : 'bg-slate-900 border-slate-800 text-slate-300'
                              }`}
                            >
                              <div className="mt-0.5">
                                {f.severity === 'CRITICAL' ? (
                                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                                ) : f.severity === 'HIGH' ? (
                                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                                ) : (
                                  <Info className="w-5 h-5 text-blue-400" />
                                )}
                              </div>
                              <div className="flex-1">
                                <div className="flex items-center gap-2">
                                  {getSeverityBadge(f.severity)}
                                  <span className="font-mono text-xs font-bold text-slate-100">{f.code}</span>
                                </div>
                                <p className="text-xs mt-1.5 leading-relaxed text-slate-300">{f.message}</p>
                              </div>
                              {f.evidence_frame && (
                                <div className="text-right">
                                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950/70 border border-slate-700 text-slate-300">
                                    Frame #{f.evidence_frame}
                                  </span>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Negotiation Details Card */}
                    <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800 space-y-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-blue-400" />
                        Forensic Negotiation Timeline
                      </h4>

                      <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                        <div className="space-y-1.5">
                          <span className="text-slate-500 text-[11px] block">Server Advertisement:</span>
                          <span className="text-slate-300 bg-slate-900 px-2 py-1 rounded block border border-slate-800">
                            {selectedItem.advertised_command || 'None'}
                          </span>
                        </div>
                        <div className="space-y-1.5">
                          <span className="text-slate-500 text-[11px] block">Client Request:</span>
                          <span className="text-slate-300 bg-slate-900 px-2 py-1 rounded block border border-slate-800">
                            {selectedItem.requested_command || 'None'}
                          </span>
                        </div>
                        <div className="space-y-1.5">
                          <span className="text-slate-500 text-[11px] block">Server Affirmation / Rejection:</span>
                          <span className="text-slate-300 bg-slate-900 px-2 py-1 rounded block border border-slate-800">
                            {selectedItem.response_text || selectedItem.response_code || 'None'}
                          </span>
                        </div>
                        <div className="space-y-1.5">
                          <span className="text-slate-500 text-[11px] block">TLS Record Layer Transition:</span>
                          <span className="text-slate-300 bg-slate-900 px-2 py-1 rounded block border border-slate-800">
                            {selectedItem.tls_record_detected
                              ? `Detected at frame #${selectedItem.tls_start_frame}`
                              : 'Not observed in capture'}
                          </span>
                        </div>
                      </div>

                      {/* Cleartext Auth Warning Box */}
                      {selectedItem.cleartext_auth_observed && (
                        <div className="mt-3 p-3 rounded-lg bg-rose-950/30 border border-rose-500/40 text-xs text-rose-300 flex items-start gap-2.5">
                          <KeyRound className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                          <div>
                            <span className="font-bold">Cleartext Authentication Exposure:</span>
                            <span className="ml-1 text-slate-300">
                              Client issued <code className="text-rose-300 font-bold">{selectedItem.cleartext_auth_command}</code> in cleartext at frame #{selectedItem.cleartext_auth_frame} without negotiating TLS encryption first.
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="flex-1 flex items-center justify-center text-slate-500">
                    Select a stream from the left column to view STARTTLS posture details.
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
