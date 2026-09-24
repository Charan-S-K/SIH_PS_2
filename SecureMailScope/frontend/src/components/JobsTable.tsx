import React, { useState } from 'react';
import { AnalysisJob, processJob } from '../services/api';
import { RefreshCw, Clock, CheckCircle2, AlertTriangle, FileCode, Play, Eye, ShieldCheck, MessageSquare, MailCheck, Lock } from 'lucide-react';

interface JobsTableProps {
  jobs: AnalysisJob[];
  loading: boolean;
  onRefresh: () => void;
  onInspectJob: (job: AnalysisJob) => void;
  onViewProtocols?: (job: AnalysisJob) => void;
  onViewSessions?: (job: AnalysisJob) => void;
  onViewEmailAnalysis?: (job: AnalysisJob) => void;
  onViewStarttls?: (job: AnalysisJob) => void;
  onViewTlsHandshakes?: (job: AnalysisJob) => void;
  onViewCertificates?: (job: AnalysisJob) => void;
}

export const JobsTable: React.FC<JobsTableProps> = ({
  jobs,
  loading,
  onRefresh,
  onInspectJob,
  onViewProtocols,
  onViewSessions,
  onViewEmailAnalysis,
  onViewStarttls,
  onViewTlsHandshakes,
  onViewCertificates,
}) => {
  const [processingId, setProcessingId] = useState<string | null>(null);

  const handleProcess = async (jobId: string) => {
    setProcessingId(jobId);
    await processJob(jobId);
    setProcessingId(null);
    onRefresh();
  };


  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'QUEUED':
      case 'PENDING':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-blue-950 text-blue-400 border border-blue-800">
            <Clock className="h-3 w-3 mr-1" />
            Queued
          </span>
        );
      case 'PROCESSING':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-amber-950 text-amber-400 border border-amber-800">
            <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
            Processing
          </span>
        );
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
            <CheckCircle2 className="h-3 w-3 mr-1" />
            Completed
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-rose-950 text-rose-400 border border-rose-800">
            <AlertTriangle className="h-3 w-3 mr-1" />
            Failed
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-400 border border-slate-700">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 shadow-xl">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
        <div>
          <h2 className="text-lg font-semibold text-slate-100 flex items-center space-x-2">
            <span>Forensic Analysis Jobs</span>
          </h2>
          <p className="text-sm text-slate-400">
            History of ingested PCAP captures and their processing status
          </p>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center space-x-2 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 transition-colors border border-slate-700"
        >
          <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="mt-4 overflow-x-auto">
        {jobs.length === 0 ? (
          <div className="text-center py-10 text-slate-500 text-xs">
            <FileCode className="h-8 w-8 mx-auto text-slate-600 mb-2" />
            <p>No analysis jobs found. Upload a .pcap or .pcapng file above to start.</p>
          </div>
        ) : (
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Job ID</th>
                <th className="py-2.5 px-3">Filename</th>
                <th className="py-2.5 px-3">Size</th>
                <th className="py-2.5 px-3">Format</th>
                <th className="py-2.5 px-3">Frames</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Created</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {jobs.map((job) => (
                <tr key={job.id} className="hover:bg-slate-900/40 transition-colors">
                  <td className="py-3 px-3 text-blue-400 truncate max-w-[120px]" title={job.id}>
                    {job.id.slice(0, 8)}...
                  </td>
                  <td className="py-3 px-3 text-slate-200 font-sans truncate max-w-[160px]" title={job.pcap_file?.original_filename}>
                    {job.pcap_file?.original_filename || 'unknown'}
                  </td>
                  <td className="py-3 px-3">
                    {job.pcap_file?.file_size_bytes
                      ? `${(job.pcap_file.file_size_bytes / 1024).toFixed(1)} KB`
                      : '—'}
                  </td>
                  <td className="py-3 px-3 uppercase text-[10px] font-sans">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {job.pcap_file?.file_format || 'pcap'}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    {job.total_packets !== undefined && job.total_packets > 0 ? (
                      <span className="text-emerald-400 font-semibold">{job.total_packets} pkts</span>
                    ) : (
                      <span className="text-slate-500">—</span>
                    )}
                  </td>
                  <td className="py-3 px-3 font-sans">
                    {getStatusBadge(job.status)}
                  </td>
                  <td className="py-3 px-3 text-slate-400 font-sans whitespace-nowrap">
                    {new Date(job.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                  <td className="py-3 px-3 text-right font-sans">
                    {job.status === 'QUEUED' || job.status === 'PENDING' ? (
                      <button
                        onClick={() => handleProcess(job.id)}
                        disabled={processingId === job.id}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-[11px] font-medium transition-colors"
                      >
                        <Play className={`h-3 w-3 ${processingId === job.id ? 'animate-spin' : ''}`} />
                        <span>{processingId === job.id ? 'Processing...' : 'Process PCAP'}</span>
                      </button>
                    ) : job.status === 'COMPLETED' ? (
                      <div className="flex items-center justify-end gap-1.5">
                        {onViewProtocols && (
                          <button
                            onClick={() => onViewProtocols(job)}
                            className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-blue-900/60 hover:bg-blue-800 text-blue-200 border border-blue-700/60 text-[11px] font-medium transition-colors"
                            title="View Identified Protocols & Forensic Evidence"
                          >
                            <ShieldCheck className="h-3 w-3 text-blue-400" />
                            <span>Protocols</span>
                          </button>
                        )}
                        {onViewSessions && (
                          <button
                            onClick={() => onViewSessions(job)}
                            className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-indigo-900/60 hover:bg-indigo-800 text-indigo-200 border border-indigo-700/60 text-[11px] font-medium transition-colors"
                            title="View TCP Session Reconstruction & Follow Stream"
                          >
                            <MessageSquare className="h-3 w-3 text-indigo-400" />
                            <span>Sessions</span>
                          </button>
                        )}
                        {onViewEmailAnalysis && (
                          <button
                            onClick={() => onViewEmailAnalysis(job)}
                            className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-cyan-900/60 hover:bg-cyan-800 text-cyan-200 border border-cyan-700/60 text-[11px] font-medium transition-colors"
                            title="View Email Protocol State Machine & Events"
                          >
                            <MailCheck className="h-3 w-3 text-cyan-400" />
                            <span>Email Analysis</span>
                          </button>
                        )}
                        {onViewStarttls && (
                          <button
                            onClick={() => onViewStarttls(job)}
                            className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-emerald-900/60 hover:bg-emerald-800 text-emerald-200 border border-emerald-700/60 text-[11px] font-medium transition-colors"
                            title="View STARTTLS Negotiation & Downgrade Risk Posture"
                          >
                            <Lock className="h-3 w-3 text-emerald-400" />
                            <span>STARTTLS</span>
                          </button>
                        )}
                        {onViewTlsHandshakes && (
                          <button
                            onClick={() => onViewTlsHandshakes(job)}
                            className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-blue-900/60 hover:bg-blue-800 text-blue-200 border border-blue-700/60 text-[11px] font-medium transition-colors"
                            title="View Reconstructed TLS Handshake & Cipher Suite Details"
                          >
                            <ShieldCheck className="h-3 w-3 text-blue-400" />
                            <span>TLS</span>
                          </button>
                        )}
                        {onViewCertificates && (
                          <button
                            onClick={() => onViewCertificates(job)}
                            className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-teal-900/60 hover:bg-teal-800 text-teal-200 border border-teal-700/60 text-[11px] font-medium transition-colors"
                            title="View X.509 Certificate Forensic Analysis"
                          >
                            <Lock className="h-3 w-3 text-teal-400" />
                            <span>Certs</span>
                          </button>
                        )}
                        <button
                          onClick={() => onInspectJob(job)}
                          className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-medium transition-colors"
                          title="Inspect raw packet frames"
                        >
                          <Eye className="h-3 w-3 text-emerald-400" />
                          <span>Frames</span>
                        </button>
                      </div>
                    ) : (
                      <span className="text-[11px] text-slate-500">Failed</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
