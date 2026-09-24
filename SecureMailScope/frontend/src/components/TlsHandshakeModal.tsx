import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldCheck,
  ShieldAlert,
  Lock,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  ArrowRight,
  Layers,
  ExternalLink,
  Info,
  Clock,
  Cpu
} from 'lucide-react';
import {
  fetchJobTlsHandshakes,
  analyzeJobTlsHandshakes,
  TlsHandshakeAnalysisItem,
  TlsHandshakeAnalysisListResponse
} from '../services/api';

interface TlsHandshakeModalProps {
  jobId: string;
  filename: string;
  onClose: () => void;
  onInspectFrames?: (streamId: number) => void;
}

export const TlsHandshakeModal: React.FC<TlsHandshakeModalProps> = ({
  jobId,
  filename,
  onClose,
  onInspectFrames,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [data, setData] = useState<TlsHandshakeAnalysisListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedStreamId, setSelectedStreamId] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<'flow' | 'client_hello' | 'server_hello'>('flow');

  const loadData = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    const res = await fetchJobTlsHandshakes(jobId);
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
    const res = await analyzeJobTlsHandshakes(jobId);
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

  const selectedItem: TlsHandshakeAnalysisItem | undefined = (data?.analyses || []).find(
    (a) => a.tcp_stream === selectedStreamId
  ) || (data?.analyses && data.analyses.length > 0 ? data.analyses[0] : undefined);

  const getVersionBadge = (version: string) => {
    switch (version) {
      case 'TLS 1.3':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Lock className="w-3 h-3" />
            TLS 1.3 (Modern)
          </span>
        );
      case 'TLS 1.2':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <ShieldCheck className="w-3 h-3" />
            TLS 1.2
          </span>
        );
      case 'TLS 1.1':
      case 'TLS 1.0':
      case 'SSL 3.0':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" />
            {version} (Deprecated)
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
            <Info className="w-3 h-3" />
            UNKNOWN
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-emerald-950 text-emerald-300 border border-emerald-800">
            <CheckCircle2 className="w-3 h-3" />
            Completed
          </span>
        );
      case 'NEGOTIATED_INCOMPLETE':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-blue-950 text-blue-300 border border-blue-800">
            <Clock className="w-3 h-3" />
            Negotiated
          </span>
        );
      case 'CLIENT_HELLO_ONLY':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-amber-950 text-amber-300 border border-amber-800">
            <AlertTriangle className="w-3 h-3" />
            Client Hello Only
          </span>
        );
      case 'ALERT_TERMINATED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-rose-950 text-rose-300 border border-rose-800">
            <XCircle className="w-3 h-3" />
            Alert Terminated
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-6xl max-h-[92vh] flex flex-col bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                TLS Handshake Cryptographic Analysis
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
              title="Re-run TLS Handshake Reconstruction & Dissection"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Re-analyze Handshakes
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
          <div className="grid grid-cols-6 gap-3 px-6 py-3 bg-slate-950/50 border-b border-slate-800/80 text-xs">
            <div className="flex flex-col">
              <span className="text-slate-400">Total Handshakes</span>
              <span className="text-base font-semibold text-slate-200 font-mono">{data.total_handshakes}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-400">Completed</span>
              <span className="text-base font-semibold text-emerald-400 font-mono">{data.completed_count}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-400">TLS 1.3</span>
              <span className="text-base font-semibold text-emerald-400 font-mono">{data.tls13_count}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-400">TLS 1.2</span>
              <span className="text-base font-semibold text-blue-400 font-mono">{data.tls12_count}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-400">Legacy Versions</span>
              <span className={`text-base font-semibold font-mono ${data.legacy_tls_count > 0 ? 'text-amber-400' : 'text-slate-300'}`}>
                {data.legacy_tls_count}
              </span>
            </div>
            <div className="flex flex-col">
              <span className="text-slate-400">TLS Alerts</span>
              <span className={`text-base font-semibold font-mono ${data.alert_count > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
                {data.alert_count}
              </span>
            </div>
          </div>
        )}

        {/* Content Body */}
        <div className="flex-1 flex overflow-hidden min-h-[460px]">
          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-400 gap-3">
              <RefreshCw className="w-8 h-8 animate-spin text-blue-400" />
              <p className="text-sm font-medium">Reconstructing observable TLS handshakes and cipher suites...</p>
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
              <p className="text-sm font-medium">No observable TLS handshake sessions detected in this capture.</p>
            </div>
          ) : (
            <>
              {/* Left Column: Stream Selector */}
              <div className="w-80 border-r border-slate-800 bg-slate-900/40 flex flex-col overflow-y-auto">
                <div className="p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800/80">
                  TLS Handshakes ({data.analyses.length})
                </div>
                <div className="divide-y divide-slate-800/50">
                  {data.analyses.map((item) => {
                    const isSelected = item.tcp_stream === selectedStreamId;

                    return (
                      <button
                        key={item.id}
                        onClick={() => setSelectedStreamId(item.tcp_stream)}
                        className={`w-full text-left p-3.5 transition flex flex-col gap-1.5 ${
                          isSelected
                            ? 'bg-blue-500/10 border-l-2 border-blue-400'
                            : 'hover:bg-slate-800/40 border-l-2 border-transparent'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-xs text-blue-300">
                            Stream #{item.tcp_stream}
                          </span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">
                            {item.protocol} :{item.server_port}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono truncate">
                          {item.sni ? (
                            <span className="text-slate-300 font-semibold">{item.sni}</span>
                          ) : (
                            <span>{item.client_ip}:{item.client_port} <ArrowRight className="inline w-2.5 h-2.5 text-slate-600" /> {item.server_ip}:{item.server_port}</span>
                          )}
                        </div>
                        <div className="flex items-center justify-between text-[10px] pt-1">
                          <div>{getVersionBadge(item.negotiated_version)}</div>
                          <div>{getStatusBadge(item.handshake_status)}</div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Right Column: Selected Handshake Analysis */}
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
                          {getVersionBadge(selectedItem.negotiated_version)}
                          {getStatusBadge(selectedItem.handshake_status)}
                          {selectedItem.is_starttls && (
                            <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800 font-mono">
                              STARTTLS Upgraded
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-400 font-mono mt-1">
                          Client: {selectedItem.client_ip}:{selectedItem.client_port} &bull; Server: {selectedItem.server_ip}:{selectedItem.server_port}
                          {selectedItem.sni && <span> &bull; SNI: <strong className="text-slate-200">{selectedItem.sni}</strong></span>}
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

                    {/* Negotiated Security Parameters Card */}
                    <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800 space-y-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-emerald-400" />
                        Negotiated Cryptographic Parameters
                      </h4>

                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800 flex flex-col gap-1">
                          <span className="text-slate-500 text-[10px] uppercase tracking-wider">TLS Version</span>
                          <span className="text-slate-200 font-bold">{selectedItem.negotiated_version}</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800 flex flex-col gap-1 col-span-2">
                          <span className="text-slate-500 text-[10px] uppercase tracking-wider">Negotiated Cipher Suite</span>
                          <span className="text-emerald-300 font-bold break-all">{selectedItem.negotiated_cipher_suite}</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800 flex flex-col gap-1">
                          <span className="text-slate-500 text-[10px] uppercase tracking-wider">Key Exchange Group</span>
                          <span className="text-slate-300">{selectedItem.key_exchange_group || 'UNKNOWN'}</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800 flex flex-col gap-1">
                          <span className="text-slate-500 text-[10px] uppercase tracking-wider">Signature Scheme</span>
                          <span className="text-slate-300">{selectedItem.signature_scheme || 'UNKNOWN'}</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800 flex flex-col gap-1">
                          <span className="text-slate-500 text-[10px] uppercase tracking-wider">ALPN Protocol</span>
                          <span className="text-slate-300">{selectedItem.alpn_selected || 'None'}</span>
                        </div>
                      </div>

                      {/* Alert Box if present */}
                      {selectedItem.has_alert && (
                        <div className="mt-2 p-3 rounded-lg bg-rose-950/30 border border-rose-500/40 text-xs text-rose-300 flex items-start gap-2.5">
                          <ShieldAlert className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                          <div>
                            <span className="font-bold">TLS Alert Terminated:</span>
                            <span className="ml-1 text-slate-300">
                              Server/Client issued <strong>{selectedItem.alert_level}</strong> alert: <code>{selectedItem.alert_description}</code> at frame #{selectedItem.alert_frame}.
                            </span>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Navigation Tabs */}
                    <div className="flex border-b border-slate-800 gap-2">
                      <button
                        onClick={() => setActiveTab('flow')}
                        className={`pb-2 px-3 text-xs font-semibold transition border-b-2 ${
                          activeTab === 'flow'
                            ? 'text-blue-400 border-blue-400'
                            : 'text-slate-400 border-transparent hover:text-slate-200'
                        }`}
                      >
                        Handshake Flow Timeline ({selectedItem.handshake_messages?.length || 0})
                      </button>
                      <button
                        onClick={() => setActiveTab('client_hello')}
                        className={`pb-2 px-3 text-xs font-semibold transition border-b-2 ${
                          activeTab === 'client_hello'
                            ? 'text-blue-400 border-blue-400'
                            : 'text-slate-400 border-transparent hover:text-slate-200'
                        }`}
                      >
                        Client Hello Dissection ({selectedItem.client_offered_ciphers?.length || 0} ciphers)
                      </button>
                      <button
                        onClick={() => setActiveTab('server_hello')}
                        className={`pb-2 px-3 text-xs font-semibold transition border-b-2 ${
                          activeTab === 'server_hello'
                            ? 'text-blue-400 border-blue-400'
                            : 'text-slate-400 border-transparent hover:text-slate-200'
                        }`}
                      >
                        Server Hello Dissection
                      </button>
                    </div>

                    {/* Tab 1: Handshake Flow Timeline */}
                    {activeTab === 'flow' && (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between text-xs text-slate-400">
                          <span>Chronological Handshake Sequence</span>
                          {selectedItem.handshake_duration_ms !== null && selectedItem.handshake_duration_ms !== undefined && (
                            <span className="font-mono">Handshake Duration: {selectedItem.handshake_duration_ms} ms</span>
                          )}
                        </div>

                        <div className="space-y-2">
                          {(selectedItem.handshake_messages || []).map((msg, idx) => (
                            <div
                              key={idx}
                              className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs font-mono"
                            >
                              <div className="flex items-center gap-3">
                                <span className="w-6 h-6 rounded-full bg-slate-800 text-slate-300 flex items-center justify-center text-[10px] font-bold">
                                  {idx + 1}
                                </span>
                                <span className="font-bold text-blue-300">{msg.message_type}</span>
                                <span className="text-slate-400 text-[11px]">{msg.info}</span>
                              </div>
                              {msg.frame_number && (
                                <span className="text-[11px] px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-400">
                                  Frame #{msg.frame_number}
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Tab 2: Client Hello Dissection */}
                    {activeTab === 'client_hello' && (
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                          <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
                            <span className="text-slate-500 block text-[10px]">Client Hello Version</span>
                            <span className="text-slate-200 font-bold">{selectedItem.client_hello_version || 'UNKNOWN'}</span>
                          </div>
                          <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
                            <span className="text-slate-500 block text-[10px]">Client Random</span>
                            <span className="text-slate-400 text-[10px] break-all">{selectedItem.client_random || 'None'}</span>
                          </div>
                        </div>

                        {/* Supported Versions & Groups */}
                        <div className="grid grid-cols-2 gap-3 text-xs">
                          <div className="p-3 rounded bg-slate-950/60 border border-slate-800 space-y-1.5">
                            <span className="text-slate-400 text-[11px] font-bold block">Advertised Supported Versions:</span>
                            <div className="flex flex-wrap gap-1.5">
                              {(selectedItem.client_supported_versions || ['None']).map((ver, i) => (
                                <span key={i} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-400">
                                  {ver}
                                </span>
                              ))}
                            </div>
                          </div>

                          <div className="p-3 rounded bg-slate-950/60 border border-slate-800 space-y-1.5">
                            <span className="text-slate-400 text-[11px] font-bold block">Supported Groups (Curves):</span>
                            <div className="flex flex-wrap gap-1.5">
                              {(selectedItem.client_supported_groups || ['None']).map((grp, i) => (
                                <span key={i} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-blue-300">
                                  {grp}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>

                        {/* Offered Cipher Suites Table */}
                        <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800 space-y-2">
                          <div className="text-xs font-bold text-slate-300 flex items-center justify-between">
                            <span>Offered Cipher Suites ({selectedItem.client_offered_ciphers?.length || 0})</span>
                          </div>
                          <div className="max-h-56 overflow-y-auto divide-y divide-slate-800/60 border border-slate-800 rounded-lg">
                            {(selectedItem.client_offered_ciphers || []).map((cs, i) => (
                              <div key={i} className="px-3 py-1.5 flex items-center justify-between text-xs font-mono hover:bg-slate-900/60">
                                <span className="text-slate-300">{cs.name}</span>
                                <span className="text-slate-500 text-[11px]">{cs.hex}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Tab 3: Server Hello Dissection */}
                    {activeTab === 'server_hello' && (
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                          <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
                            <span className="text-slate-500 block text-[10px]">Server Hello Frame</span>
                            <span className="text-slate-200 font-bold">
                              {selectedItem.server_hello_frame ? `Frame #${selectedItem.server_hello_frame}` : 'None'}
                            </span>
                          </div>
                          <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
                            <span className="text-slate-500 block text-[10px]">Server Hello Version</span>
                            <span className="text-slate-200 font-bold">{selectedItem.server_hello_version || 'UNKNOWN'}</span>
                          </div>
                        </div>

                        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                          <span className="text-xs font-bold text-slate-400 block uppercase tracking-wider">Negotiated Choice</span>
                          <div className="p-3 rounded bg-slate-900 border border-slate-800 text-xs font-mono">
                            <div className="text-emerald-400 font-bold">{selectedItem.negotiated_cipher_suite}</div>
                            <div className="text-slate-500 text-[11px] mt-1">Version: {selectedItem.negotiated_version}</div>
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="flex-1 flex items-center justify-center text-slate-500">
                    Select a stream from the left column to view TLS Handshake details.
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
