import React, { useEffect, useState, useMemo } from 'react';
import {
  X509CertificateListResponse,
  fetchJobCertificates,
  analyzeJobCertificates,
} from '../services/api';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Key,
  Calendar,
  Layers,
  Copy,
  Check,
  RefreshCw,
  X,
  FileCode,
  Globe,
  Fingerprint,
  Link,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';

interface CertificateModalProps {
  jobId: string;
  isOpen: boolean;
  onClose: () => void;
  onInspectPackets?: (streamId: number) => void;
}

export const CertificateModal: React.FC<CertificateModalProps> = ({
  jobId,
  isOpen,
  onClose,
  onInspectPackets,
}) => {
  const [data, setData] = useState<X509CertificateListResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedCertId, setSelectedCertId] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'VALID' | 'EXPIRED' | 'SELF_SIGNED' | 'WEAK'>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showRawDer, setShowRawDer] = useState<boolean>(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    const res = await fetchJobCertificates(jobId);
    if (res.error) {
      setError(res.error);
    } else {
      setData(res.data);
      if (res.data?.certificates && res.data.certificates.length > 0) {
        setSelectedCertId(res.data.certificates[0].id);
      }
    }
    setLoading(false);
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    const res = await analyzeJobCertificates(jobId);
    if (res.error) {
      setError(res.error);
    } else {
      setData(res.data);
      if (res.data?.certificates && res.data.certificates.length > 0) {
        setSelectedCertId(res.data.certificates[0].id);
      }
    }
    setRefreshing(false);
  };

  useEffect(() => {
    if (isOpen && jobId) {
      loadData();
    }
  }, [isOpen, jobId]);

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const filteredCerts = useMemo(() => {
    if (!data?.certificates) return [];
    return data.certificates.filter((cert) => {
      // Filter by status
      if (statusFilter === 'VALID' && cert.validity_status !== 'VALID') return false;
      if (statusFilter === 'EXPIRED' && cert.validity_status !== 'EXPIRED') return false;
      if (statusFilter === 'SELF_SIGNED' && !cert.is_self_signed) return false;
      if (statusFilter === 'WEAK') {
        const isWeakKey = cert.public_key_algorithm === 'RSA' && (cert.key_size_bits || 0) < 2048;
        const isWeakSig = cert.signature_digest === 'SHA-1' || cert.signature_digest === 'MD5';
        if (!isWeakKey && !isWeakSig) return false;
      }

      // Filter by search
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const matchesCn = cert.subject_cn?.toLowerCase().includes(term);
        const matchesOrg = cert.subject_org?.toLowerCase().includes(term);
        const matchesDn = cert.subject_dn?.toLowerCase().includes(term);
        const matchesStream = cert.tcp_stream.toString() === term;
        const matchesSan = cert.sans?.some((s) => s.value.toLowerCase().includes(term));
        if (!matchesCn && !matchesOrg && !matchesDn && !matchesStream && !matchesSan) return false;
      }

      return true;
    });
  }, [data, statusFilter, searchTerm]);

  const selectedCert = useMemo(() => {
    if (!data?.certificates) return null;
    return data.certificates.find((c) => c.id === selectedCertId) || data.certificates[0] || null;
  }, [data, selectedCertId]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 w-full max-w-7xl rounded-xl shadow-2xl flex flex-col max-h-[92vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-800/50 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                X.509 Certificate Forensic Analysis
                <span className="text-xs font-mono font-normal bg-slate-700/60 text-slate-300 px-2 py-0.5 rounded border border-slate-600/40">
                  Stage 08
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Job ID: <span className="font-mono text-slate-300">{jobId}</span>
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 rounded-lg transition-colors"
              title="Refresh / Re-analyze Certificates"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-emerald-400' : ''}`} />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Global Metrics Bar */}
        {data && (
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3 px-6 py-3 bg-slate-950 border-b border-slate-800 text-xs">
            <div className="bg-slate-900 border border-slate-800 p-2.5 rounded-lg flex flex-col">
              <span className="text-slate-400">Total Observed</span>
              <span className="text-lg font-bold text-slate-100 mt-0.5">{data.total_certificates}</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-2.5 rounded-lg flex flex-col">
              <span className="text-slate-400">Valid</span>
              <span className="text-lg font-bold text-emerald-400 mt-0.5">{data.valid_certificates}</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-2.5 rounded-lg flex flex-col">
              <span className="text-slate-400">Expired / Invalid</span>
              <span className={`text-lg font-bold mt-0.5 ${data.expired_certificates > 0 ? 'text-red-400' : 'text-slate-400'}`}>
                {data.expired_certificates + data.not_yet_valid_certificates}
              </span>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-2.5 rounded-lg flex flex-col">
              <span className="text-slate-400">Self-Signed</span>
              <span className={`text-lg font-bold mt-0.5 ${data.self_signed_certificates > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                {data.self_signed_certificates}
              </span>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-2.5 rounded-lg flex flex-col">
              <span className="text-slate-400">Weak Keys (&lt;2048b)</span>
              <span className={`text-lg font-bold mt-0.5 ${data.weak_keys_count > 0 ? 'text-purple-400' : 'text-slate-400'}`}>
                {data.weak_keys_count}
              </span>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-2.5 rounded-lg flex flex-col">
              <span className="text-slate-400">Weak Hashes (SHA-1/MD5)</span>
              <span className={`text-lg font-bold mt-0.5 ${data.weak_signatures_count > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                {data.weak_signatures_count}
              </span>
            </div>
          </div>
        )}

        {/* Content Body */}
        <div className="flex-1 flex overflow-hidden">
          {loading ? (
            <div className="w-full flex items-center justify-center py-20 text-slate-400">
              <RefreshCw className="w-6 h-6 animate-spin mr-2 text-emerald-400" />
              <span>Parsing X.509 certificates and chains...</span>
            </div>
          ) : error ? (
            <div className="w-full p-8 text-center text-red-400 flex flex-col items-center justify-center">
              <AlertTriangle className="w-10 h-10 mb-2" />
              <p className="text-sm font-semibold">{error}</p>
            </div>
          ) : !data?.certificates || data.certificates.length === 0 ? (
            <div className="w-full p-12 text-center text-slate-400 flex flex-col items-center justify-center">
              <ShieldAlert className="w-12 h-12 text-slate-600 mb-3" />
              <h3 className="text-base font-semibold text-slate-300">No Certificates Observed</h3>
              <p className="text-xs text-slate-500 max-w-md mt-1">
                Passive capture did not observe cleartext X.509 Certificate handshake messages (e.g. session was unencrypted, failed prior to Certificate exchange, or used TLS 1.3 encrypted handshake).
              </p>
            </div>
          ) : (
            <>
              {/* Left Sidebar: Certificates List */}
              <div className="w-80 border-r border-slate-800 flex flex-col bg-slate-900/50">
                {/* Search & Filter Bar */}
                <div className="p-3 border-b border-slate-800 space-y-2">
                  <input
                    type="text"
                    placeholder="Search CN, Org, SAN, or Stream..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-md text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                  <div className="flex flex-wrap gap-1">
                    {(['ALL', 'VALID', 'EXPIRED', 'SELF_SIGNED', 'WEAK'] as const).map((filter) => (
                      <button
                        key={filter}
                        onClick={() => setStatusFilter(filter)}
                        className={`px-2 py-0.5 text-[10px] rounded font-medium transition-colors ${
                          statusFilter === filter
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {filter}
                      </button>
                    ))}
                  </div>
                </div>

                {/* List items */}
                <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
                  {filteredCerts.map((cert) => {
                    const isSelected = cert.id === selectedCert?.id;
                    return (
                      <div
                        key={cert.id}
                        onClick={() => setSelectedCertId(cert.id)}
                        className={`p-3 cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-slate-800/80 border-l-2 border-emerald-500'
                            : 'hover:bg-slate-800/40'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-bold text-slate-200 truncate max-w-[170px]" title={cert.subject_cn || cert.subject_dn}>
                            {cert.subject_cn || cert.subject_dn.slice(0, 24)}
                          </span>
                          <span
                            className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                              cert.validity_status === 'VALID'
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                : 'bg-red-500/10 text-red-400 border border-red-500/30'
                            }`}
                          >
                            {cert.validity_status}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 flex items-center justify-between">
                          <span>Stream #{cert.tcp_stream}</span>
                          <span className="text-slate-500">
                            {cert.chain_index === 0 ? 'Leaf (End-Entity)' : cert.is_ca ? 'CA' : `Chain #${cert.chain_index}`}
                          </span>
                        </div>
                        {cert.is_self_signed && (
                          <div className="mt-1">
                            <span className="text-[10px] bg-amber-500/10 text-amber-300 border border-amber-500/20 px-1.5 py-0.2 rounded font-mono">
                              Self-Signed
                            </span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Main Details Pane */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-slate-900/30">
                {selectedCert ? (
                  <>
                    {/* Top Overview Card */}
                    <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-5 shadow-sm">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-slate-700 text-slate-300">
                              Stream #{selectedCert.tcp_stream}
                            </span>
                            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                              Chain Index {selectedCert.chain_index} of {selectedCert.chain_length}
                            </span>
                            {selectedCert.is_ca && (
                              <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                                CA
                              </span>
                            )}
                          </div>
                          <h3 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                            {selectedCert.subject_cn || 'Untitled Certificate'}
                          </h3>
                          <p className="text-xs text-slate-400 mt-1">
                            Issued by: <span className="text-slate-200 font-medium">{selectedCert.issuer_cn || selectedCert.issuer_dn}</span>
                          </p>
                        </div>

                        {onInspectPackets && (
                          <button
                            onClick={() => onInspectPackets(selectedCert.tcp_stream)}
                            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                            <span>Inspect Frames</span>
                          </button>
                        )}
                      </div>

                      {/* Expiration Alert Banner */}
                      {selectedCert.validity_status === 'EXPIRED' && (
                        <div className="mt-4 p-3 bg-red-950/40 border border-red-800/60 rounded-lg text-xs text-red-300 flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
                          <span>
                            This certificate expired on <strong className="font-mono">{new Date(selectedCert.not_after).toUTCString()}</strong> ({Math.abs(selectedCert.days_until_expiration || 0)} days ago).
                          </span>
                        </div>
                      )}

                      {selectedCert.is_self_signed && (
                        <div className="mt-4 p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg text-xs text-amber-300 flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 shrink-0 text-amber-400" />
                          <span>
                            <strong>Self-Signed Certificate Detected:</strong> Subject and Issuer are identical and cryptographic signature was verified using its own public key.
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Subject & Issuer Details */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Subject Card */}
                      <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4 space-y-2">
                        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                          <Lock className="w-4 h-4 text-emerald-400" />
                          <span>Subject (Distinguished Name)</span>
                        </div>
                        <div className="space-y-1.5 text-xs">
                          <div className="flex justify-between">
                            <span className="text-slate-400">Common Name (CN):</span>
                            <span className="font-mono text-slate-200">{selectedCert.subject_cn || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Organization (O):</span>
                            <span className="text-slate-200">{selectedCert.subject_org || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Organizational Unit (OU):</span>
                            <span className="text-slate-200">{selectedCert.subject_ou || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Country (C):</span>
                            <span className="text-slate-200">{selectedCert.subject_country || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">State / Locality:</span>
                            <span className="text-slate-200">
                              {[selectedCert.subject_state, selectedCert.subject_locality].filter(Boolean).join(', ') || 'N/A'}
                            </span>
                          </div>
                          <div className="pt-2 text-[11px] text-slate-400">
                            <span className="block text-slate-500 mb-0.5">RFC 4514 DN:</span>
                            <span className="font-mono text-[10px] break-all bg-slate-950 p-1.5 rounded block border border-slate-850">
                              {selectedCert.subject_dn}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Issuer Card */}
                      <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4 space-y-2">
                        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                          <ShieldCheck className="w-4 h-4 text-cyan-400" />
                          <span>Issuer (Authority)</span>
                        </div>
                        <div className="space-y-1.5 text-xs">
                          <div className="flex justify-between">
                            <span className="text-slate-400">Common Name (CN):</span>
                            <span className="font-mono text-slate-200">{selectedCert.issuer_cn || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Organization (O):</span>
                            <span className="text-slate-200">{selectedCert.issuer_org || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Organizational Unit (OU):</span>
                            <span className="text-slate-200">{selectedCert.issuer_ou || 'N/A'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Country (C):</span>
                            <span className="text-slate-200">{selectedCert.issuer_country || 'N/A'}</span>
                          </div>
                          <div className="pt-2 text-[11px] text-slate-400">
                            <span className="block text-slate-500 mb-0.5">RFC 4514 DN:</span>
                            <span className="font-mono text-[10px] break-all bg-slate-950 p-1.5 rounded block border border-slate-850">
                              {selectedCert.issuer_dn}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Validity & Cryptography Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Validity Period */}
                      <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4 space-y-3">
                        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                          <Calendar className="w-4 h-4 text-emerald-400" />
                          <span>Temporal Validity & Expiration</span>
                        </div>
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Not Before:</span>
                            <span className="font-mono text-slate-200">{new Date(selectedCert.not_before).toUTCString()}</span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Not After:</span>
                            <span className="font-mono text-slate-200">{new Date(selectedCert.not_after).toUTCString()}</span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Validity Duration:</span>
                            <span className="text-slate-200">{selectedCert.validity_days} days</span>
                          </div>
                          <div className="flex justify-between items-center pt-1 border-t border-slate-800/60">
                            <span className="text-slate-400">Status & Remaining:</span>
                            <span
                              className={`font-semibold font-mono ${
                                selectedCert.validity_status === 'VALID'
                                  ? 'text-emerald-400'
                                  : 'text-red-400'
                              }`}
                            >
                              {selectedCert.validity_status} (
                              {selectedCert.days_until_expiration && selectedCert.days_until_expiration > 0
                                ? `${selectedCert.days_until_expiration} days left`
                                : `${Math.abs(selectedCert.days_until_expiration || 0)} days expired`}
                              )
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Cryptographic Parameters */}
                      <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4 space-y-3">
                        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                          <Key className="w-4 h-4 text-purple-400" />
                          <span>Public Key & Signature Algorithms</span>
                        </div>
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Key Algorithm:</span>
                            <span className="font-semibold text-slate-200">
                              {selectedCert.public_key_algorithm}{' '}
                              {selectedCert.key_size_bits ? `(${selectedCert.key_size_bits} bits)` : ''}
                            </span>
                          </div>
                          {selectedCert.public_key_curve && (
                            <div className="flex justify-between items-center">
                              <span className="text-slate-400">EC Curve:</span>
                              <span className="font-mono text-indigo-300">{selectedCert.public_key_curve}</span>
                            </div>
                          )}
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Signature Algorithm:</span>
                            <span className="font-mono text-slate-200">{selectedCert.signature_algorithm}</span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Signature Digest:</span>
                            <span
                              className={`font-semibold font-mono ${
                                selectedCert.signature_digest === 'SHA-1' || selectedCert.signature_digest === 'MD5'
                                  ? 'text-rose-400'
                                  : 'text-emerald-400'
                              }`}
                            >
                              {selectedCert.signature_digest || 'UNKNOWN'}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Subject Alternative Names (SANs) */}
                    <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                        <Globe className="w-4 h-4 text-blue-400" />
                        <span>Subject Alternative Names (SANs)</span>
                        <span className="text-[10px] text-slate-400 ml-1">({selectedCert.sans?.length || 0} entries)</span>
                      </div>
                      {selectedCert.sans && selectedCert.sans.length > 0 ? (
                        <div className="flex flex-wrap gap-2 pt-1">
                          {selectedCert.sans.map((san, idx) => (
                            <span
                              key={idx}
                              className="px-2.5 py-1 bg-slate-900 border border-slate-700/60 rounded text-xs font-mono text-slate-200 flex items-center gap-1.5"
                            >
                              <span className="text-[10px] font-bold text-slate-400 uppercase">{san.type}:</span>
                              <span>{san.value}</span>
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-slate-500 italic">No Subject Alternative Names defined.</p>
                      )}
                    </div>

                    {/* Chain Hierarchy & Key Usages */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Key Usage & Extended Key Usage */}
                      <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4 space-y-3">
                        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                          <Layers className="w-4 h-4 text-emerald-400" />
                          <span>Constraints & Key Usages</span>
                        </div>
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Basic Constraints:</span>
                            <span className="font-mono text-slate-200">
                              {selectedCert.is_ca ? 'Is CA = TRUE' : 'Is CA = FALSE'}
                              {selectedCert.path_length_constraint !== null && ` (pathlen=${selectedCert.path_length_constraint})`}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-400 block mb-1">Key Usage:</span>
                            <div className="flex flex-wrap gap-1">
                              {selectedCert.key_usage && selectedCert.key_usage.length > 0 ? (
                                selectedCert.key_usage.map((ku, idx) => (
                                  <span key={idx} className="px-2 py-0.5 bg-slate-900 border border-slate-700 text-[10px] rounded font-mono text-slate-300">
                                    {ku}
                                  </span>
                                ))
                              ) : (
                                <span className="text-slate-500 italic text-[11px]">None specified</span>
                              )}
                            </div>
                          </div>
                          <div>
                            <span className="text-slate-400 block mb-1">Extended Key Usage:</span>
                            <div className="flex flex-wrap gap-1">
                              {selectedCert.extended_key_usage && selectedCert.extended_key_usage.length > 0 ? (
                                selectedCert.extended_key_usage.map((eku, idx) => (
                                  <span key={idx} className="px-2 py-0.5 bg-slate-900 border border-slate-700 text-[10px] rounded font-mono text-cyan-300">
                                    {eku}
                                  </span>
                                ))
                              ) : (
                                <span className="text-slate-500 italic text-[11px]">None specified</span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Chain Hierarchy Visualizer */}
                      <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4 space-y-3">
                        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                          <Link className="w-4 h-4 text-amber-400" />
                          <span>Certificate Chain Analysis</span>
                        </div>
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Chain Completeness:</span>
                            <span
                              className={`font-semibold font-mono text-[11px] px-2 py-0.5 rounded ${
                                selectedCert.chain_status === 'COMPLETE_CHAIN'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                  : selectedCert.chain_status === 'SELF_SIGNED_LEAF'
                                  ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                                  : 'bg-rose-500/10 text-rose-300 border border-rose-500/30'
                              }`}
                            >
                              {selectedCert.chain_status}
                            </span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Total Certificates in Stream:</span>
                            <span className="font-mono text-slate-200">{selectedCert.chain_length}</span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400">Chain Order:</span>
                            <span className="text-slate-300">
                              {selectedCert.chain_index === 0
                                ? '0 (Leaf / End-Entity)'
                                : `${selectedCert.chain_index} (${selectedCert.is_ca ? 'CA' : 'Intermediate'})`}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Fingerprints & Serial Number */}
                    <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4 space-y-3">
                      <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                        <Fingerprint className="w-4 h-4 text-emerald-400" />
                        <span>Cryptographic Fingerprints & Serial</span>
                      </div>
                      <div className="space-y-2 text-xs font-mono">
                        <div>
                          <div className="flex justify-between items-center mb-1">
                            <span className="text-slate-400 text-[11px]">Serial Number:</span>
                            <button
                              onClick={() => copyToClipboard(selectedCert.serial_number, 'serial')}
                              className="text-[10px] text-slate-400 hover:text-emerald-400 flex items-center gap-1"
                            >
                              {copiedField === 'serial' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedField === 'serial' ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <div className="p-2 bg-slate-950 border border-slate-800 rounded text-slate-300 break-all text-[11px]">
                            {selectedCert.serial_number}
                          </div>
                        </div>

                        <div>
                          <div className="flex justify-between items-center mb-1">
                            <span className="text-slate-400 text-[11px]">SHA-256 Fingerprint:</span>
                            <button
                              onClick={() => copyToClipboard(selectedCert.fingerprint_sha256, 'sha256')}
                              className="text-[10px] text-slate-400 hover:text-emerald-400 flex items-center gap-1"
                            >
                              {copiedField === 'sha256' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedField === 'sha256' ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <div className="p-2 bg-slate-950 border border-slate-800 rounded text-slate-300 break-all text-[11px]">
                            {selectedCert.fingerprint_sha256}
                          </div>
                        </div>

                        <div>
                          <div className="flex justify-between items-center mb-1">
                            <span className="text-slate-400 text-[11px]">SHA-1 Fingerprint:</span>
                            <button
                              onClick={() => copyToClipboard(selectedCert.fingerprint_sha1, 'sha1')}
                              className="text-[10px] text-slate-400 hover:text-emerald-400 flex items-center gap-1"
                            >
                              {copiedField === 'sha1' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedField === 'sha1' ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <div className="p-2 bg-slate-950 border border-slate-800 rounded text-slate-300 break-all text-[11px]">
                            {selectedCert.fingerprint_sha1}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Collapsible Raw DER Base64 */}
                    {selectedCert.raw_der_base64 && (
                      <div className="border border-slate-800 rounded-lg overflow-hidden">
                        <button
                          onClick={() => setShowRawDer(!showRawDer)}
                          className="w-full px-4 py-2.5 bg-slate-850 hover:bg-slate-800 text-left text-xs font-semibold text-slate-300 flex items-center justify-between transition-colors"
                        >
                          <div className="flex items-center gap-2">
                            <FileCode className="w-4 h-4 text-emerald-400" />
                            <span>Raw DER Base64 Payload ({selectedCert.raw_der_base64.length} chars)</span>
                          </div>
                          <ChevronRight className={`w-4 h-4 transition-transform ${showRawDer ? 'rotate-90' : ''}`} />
                        </button>
                        {showRawDer && (
                          <div className="p-4 bg-slate-950 border-t border-slate-800">
                            <textarea
                              readOnly
                              value={selectedCert.raw_der_base64}
                              rows={5}
                              className="w-full font-mono text-[11px] bg-transparent text-slate-400 resize-none focus:outline-none"
                            />
                          </div>
                        )}
                      </div>
                    )}
                  </>
                ) : (
                  <div className="h-full flex items-center justify-center text-slate-500 text-xs">
                    Select a certificate from the left sidebar to view details.
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-800/40 flex justify-between items-center text-xs text-slate-400">
          <div>
            Showing forensic X.509 parameters from observable TLS handshakes.
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors font-medium border border-slate-700"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
