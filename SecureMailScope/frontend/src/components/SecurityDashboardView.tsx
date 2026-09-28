import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  Server,
  Lock,
  Brain,
  ListOrdered,
  Wrench,
  FileText,
  BarChart3,
  RefreshCw,
  ChevronRight,
  Sliders,
  Layers,
  Unlock
} from 'lucide-react';
import {
  AnalysisJob,
  fetchJobSecurityPosture,
  fetchJobUnifiedFindings,
  fetchJobProtocols,
  fetchJobTlsHandshakes,
  getJobPrioritizationSummary,
  getJobRecommendationsSummary,
  JobPostureDashboardResponse,
  UnifiedFinding,
  ProtocolListResponse,
  TlsHandshakeAnalysisListResponse,
  JobPrioritizationSummaryItem,
  JobRecommendationsSummaryItem
} from '../services/api';

interface SecurityDashboardViewProps {
  jobs: AnalysisJob[];
  selectedJob: AnalysisJob | null;
  onSelectJob: (job: AnalysisJob) => void;
  onOpenModal: (modalName: string) => void;
}

export const SecurityDashboardView: React.FC<SecurityDashboardViewProps> = ({
  jobs,
  selectedJob,
  onSelectJob,
  onOpenModal
}) => {
  const [posture, setPosture] = useState<JobPostureDashboardResponse | null>(null);
  const [findings, setFindings] = useState<UnifiedFinding[]>([]);
  const [protocols, setProtocols] = useState<ProtocolListResponse | null>(null);
  const [handshakes, setHandshakes] = useState<TlsHandshakeAnalysisListResponse | null>(null);
  const [prioritization, setPrioritization] = useState<JobPrioritizationSummaryItem | null>(null);
  const [recommendations, setRecommendations] = useState<JobRecommendationsSummaryItem | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  const loadJobData = useCallback(async (jobId: string) => {
    setLoading(true);
    try {
      const [postureRes, findingsRes, protoRes, tlsRes, prioRes, recRes] = await Promise.all([
        fetchJobSecurityPosture(jobId),
        fetchJobUnifiedFindings(jobId),
        fetchJobProtocols(jobId),
        fetchJobTlsHandshakes(jobId),
        getJobPrioritizationSummary(jobId),
        getJobRecommendationsSummary(jobId)
      ]);

      if (postureRes.data) setPosture(postureRes.data);
      if (findingsRes.data?.findings) setFindings(findingsRes.data.findings);
      if (protoRes.data) setProtocols(protoRes.data);
      if (tlsRes.data) setHandshakes(tlsRes.data);
      if (prioRes.data) setPrioritization(prioRes.data);
      if (recRes.data) setRecommendations(recRes.data);
    } catch (err: any) {
      console.error('Error fetching dashboard metrics', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedJob?.id) {
      loadJobData(selectedJob.id);
    }
  }, [selectedJob, loadJobData]);

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-400 border-red-800';
      case 'HIGH':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'MEDIUM':
        return 'bg-yellow-950 text-yellow-400 border-yellow-800';
      case 'LOW':
        return 'bg-blue-950 text-blue-400 border-blue-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getPostureBadge = (rating?: string) => {
    switch (rating) {
      case 'CRITICAL':
      case 'CRITICAL_RISK':
        return 'bg-red-950 text-red-400 border-red-800';
      case 'HIGH':
      case 'POOR':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'MEDIUM':
      case 'FAIR':
        return 'bg-yellow-950 text-yellow-400 border-yellow-800';
      case 'LOW':
      case 'GOOD':
      case 'EXCELLENT':
        return 'bg-emerald-950 text-emerald-400 border-emerald-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getSeverityCount = (sev: string) => {
    return findings.filter(f => f.severity === sev).length;
  };

  const jobPostureObj = posture?.job_posture;

  return (
    <div className="space-y-6">
      
      {/* Top Controls: Active Job Selector & Overview Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-4">
          <div className="p-3 bg-blue-950/80 border border-blue-700/50 rounded-xl text-blue-400">
            <BarChart3 className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-3">
              <h2 className="text-xl font-extrabold text-white tracking-tight">Cryptographic Security Dashboard</h2>
              {jobPostureObj && (
                <span className={`px-2.5 py-0.5 text-xs font-extrabold uppercase rounded-full border ${getPostureBadge(jobPostureObj.risk_level)}`}>
                  {jobPostureObj.risk_level} RISK ({jobPostureObj.overall_score}/100)
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Unified passive forensic analytics, machine learning risk signals, and compliance hardening overview
            </p>
          </div>
        </div>

        {/* Job Selector Dropdown */}
        <div className="flex items-center space-x-3">
          <label className="text-xs font-medium text-slate-400">Target PCAP Capture:</label>
          <select
            value={selectedJob?.id || ''}
            onChange={(e) => {
              const job = jobs.find(j => j.id === e.target.value);
              if (job) onSelectJob(job);
            }}
            className="bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500 shadow-inner"
          >
            {jobs.length === 0 ? (
              <option value="">No PCAP jobs available</option>
            ) : (
              jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  {j.pcap_file?.original_filename || `Job ${j.id.slice(0, 8)}`} ({j.status})
                </option>
              ))
            )}
          </select>
          {selectedJob && (
            <button
              onClick={() => loadJobData(selectedJob.id)}
              disabled={loading}
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl transition border border-slate-700"
              title="Refresh Dashboard"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* KPI Metric Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Metric 1: Security Posture Score */}
        <div className="p-5 rounded-2xl bg-[#111827] border border-slate-800 flex flex-col justify-between relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Overall Posture</span>
              <div className="text-3xl font-extrabold text-white mt-1">
                {jobPostureObj ? `${jobPostureObj.overall_score}/100` : selectedJob ? 'Calculating...' : 'N/A'}
              </div>
            </div>
            <div className={`p-2.5 rounded-xl border ${getPostureBadge(jobPostureObj?.risk_level)}`}>
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span>Status: <strong className="text-slate-200">{jobPostureObj?.overall_grade || 'UNKNOWN'}</strong></span>
            <button
              onClick={() => onOpenModal('posture')}
              className="text-blue-400 hover:text-blue-300 flex items-center space-x-1 font-medium text-[11px]"
            >
              <span>Inspect</span>
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Metric 2: Total Findings Breakdown */}
        <div className="p-5 rounded-2xl bg-[#111827] border border-slate-800 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Security Findings</span>
              <div className="text-3xl font-extrabold text-white mt-1">
                {findings.length}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center space-x-2 text-[11px] font-mono">
            <span className="text-red-400 font-bold">{getSeverityCount('CRITICAL')} Crit</span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-amber-400 font-bold">{getSeverityCount('HIGH')} High</span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-yellow-400 font-bold">{getSeverityCount('MEDIUM')} Med</span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-blue-400 font-bold">{getSeverityCount('LOW')} Low</span>
          </div>
        </div>

        {/* Metric 3: Mail Protocol Sessions */}
        <div className="p-5 rounded-2xl bg-[#111827] border border-slate-800 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Mail Streams</span>
              <div className="text-3xl font-extrabold text-white mt-1">
                {protocols ? `${protocols.mail_streams} / ${protocols.total_streams}` : '0 / 0'}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-indigo-950/60 border border-indigo-800 text-indigo-400">
              <Server className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span>Protocols: <strong className="text-indigo-300">SMTP / IMAP / POP3</strong></span>
            <button
              onClick={() => onOpenModal('protocols')}
              className="text-indigo-400 hover:text-indigo-300 flex items-center space-x-1 font-medium text-[11px]"
            >
              <span>Explore</span>
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Metric 4: Risk Priority Score */}
        <div className="p-5 rounded-2xl bg-[#111827] border border-slate-800 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Top Priority Risk</span>
              <div className="text-3xl font-extrabold text-amber-400 mt-1">
                {prioritization && prioritization.rankings && prioritization.rankings.length > 0
                  ? `${prioritization.rankings[0].priority_score.toFixed(1)}/100`
                  : 'N/A'}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-purple-950/60 border border-purple-800 text-purple-400">
              <ListOrdered className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span>Prioritized: <strong className="text-purple-300">{prioritization ? `${prioritization.total_findings_evaluated} findings` : '0'}</strong></span>
            <button
              onClick={() => onOpenModal('prioritization')}
              className="text-purple-400 hover:text-purple-300 flex items-center space-x-1 font-medium text-[11px]"
            >
              <span>Rankings</span>
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>

      </div>

      {/* Main Analytical Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Area: Protocol Security & TLS Handshake Matrix (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          
          {/* Protocol Distribution & Encrypted Traffic Status */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="p-2 bg-indigo-950/80 rounded-lg text-indigo-400 border border-indigo-800/60">
                  <Activity className="w-4 h-4" />
                </div>
                <h3 className="font-bold text-white text-sm">Protocol & Encrypted Traffic Distribution</h3>
              </div>
              <span className="text-[11px] font-mono text-slate-500">
                {selectedJob?.pcap_file?.original_filename || 'PCAP Stream'}
              </span>
            </div>

            {protocols && protocols.protocols.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {['SMTP', 'IMAP', 'POP3'].map((proto) => {
                  const protoItems = protocols.protocols.filter(p => p.protocol.toUpperCase() === proto);
                  const count = protoItems.length;
                  return (
                    <div key={proto} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="font-bold text-slate-200">{proto}</span>
                        <span className="font-mono text-indigo-400">{count} streams</span>
                      </div>
                      <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
                        <div
                          className="bg-indigo-500 h-full rounded-full"
                          style={{ width: `${Math.min(100, (count / (protocols.mail_streams || 1)) * 100)}%` }}
                        />
                      </div>
                      <p className="text-[10px] text-slate-500 font-mono">
                        {count > 0 ? 'Mail session observed' : 'No streams detected'}
                      </p>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-6 text-center text-slate-500 text-xs bg-slate-950 rounded-xl border border-slate-800">
                No mail protocol streams identified for this capture.
              </div>
            )}

            {/* TLS Version Breakdown */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <h4 className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>TLS Cryptographic Version Distribution</span>
                <span className="text-[10px] font-mono text-slate-500">
                  {handshakes ? `${handshakes.completed_count} completed handshakes` : 'N/A'}
                </span>
              </h4>

              {handshakes ? (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-900/50">
                    <span className="block text-emerald-400 font-bold text-base">{handshakes.tls13_count}</span>
                    <span className="text-[10px] text-slate-400">TLS 1.3 Modern</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-blue-950/30 border border-blue-900/50">
                    <span className="block text-blue-400 font-bold text-base">{handshakes.tls12_count}</span>
                    <span className="text-[10px] text-slate-400">TLS 1.2 Standard</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-red-950/30 border border-red-900/50">
                    <span className="block text-red-400 font-bold text-base">{handshakes.legacy_tls_count}</span>
                    <span className="text-[10px] text-slate-400">Legacy SSL/TLS</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-900/50">
                    <span className="block text-amber-400 font-bold text-base">{handshakes.alert_count}</span>
                    <span className="text-[10px] text-slate-400">TLS Alerts</span>
                  </div>
                </div>
              ) : (
                <div className="text-center text-xs text-slate-500 p-2">TLS handshake summary pending.</div>
              )}
            </div>
          </div>

          {/* Top Priority Findings Matrix */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="p-2 bg-amber-950/80 rounded-lg text-amber-400 border border-amber-800/60">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <h3 className="font-bold text-white text-sm">Prioritized Forensic Security Findings</h3>
              </div>
              <button
                onClick={() => onOpenModal('findings')}
                className="text-xs text-indigo-400 hover:text-indigo-300 font-medium flex items-center space-x-1"
              >
                <span>View All ({findings.length})</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {findings.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs bg-slate-950 rounded-xl border border-slate-800">
                No security findings recorded for this analysis job.
              </div>
            ) : (
              <div className="space-y-2.5">
                {findings.slice(0, 4).map((f) => (
                  <div
                    key={f.id}
                    className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start justify-between gap-3 hover:border-slate-700 transition"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${getSeverityBadge(f.severity)}`}>
                          {f.severity}
                        </span>
                        <span className="text-[10px] font-mono text-indigo-400 bg-indigo-950 px-2 py-0.5 rounded border border-indigo-900/60">
                          {f.rule_id || f.finding_type}
                        </span>
                      </div>
                      <h4 className="text-xs font-bold text-slate-200">{f.title}</h4>
                      <p className="text-[11px] text-slate-400 line-clamp-1">{f.reason}</p>
                    </div>

                    <button
                      onClick={() => onOpenModal('evidence')}
                      className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-lg border border-slate-800 transition text-[11px] shrink-0"
                      title="Explore Evidence Chain"
                    >
                      <Layers className="w-3.5 h-3.5 text-indigo-400" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>

        {/* Right Area: AI/ML Signals & Automated Remediation Actions (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          
          {/* ML Intelligence & Anomaly Detection Panel */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="p-2 bg-purple-950/80 rounded-lg text-purple-400 border border-purple-800/60">
                  <Brain className="w-4 h-4" />
                </div>
                <h3 className="font-bold text-white text-sm">AI / ML Anomaly Signals</h3>
              </div>
            </div>

            <div className="space-y-3">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300">Unsupervised Isolation Forest</span>
                  <span className="text-[10px] font-mono text-pink-400 bg-pink-950 px-2 py-0.5 rounded border border-pink-900/60">Stage 16</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Detects statistical deviation from baseline normal email TLS behavior.
                </p>
                <button
                  onClick={() => onOpenModal('tlsAnomaly')}
                  className="w-full mt-1 bg-pink-950/50 hover:bg-pink-950 border border-pink-800/60 text-pink-300 py-1.5 rounded-lg text-xs font-medium transition flex items-center justify-center space-x-1.5"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Run TLS Isolation Forest Detector</span>
                </button>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300">Supervised Random Forest Classifier</span>
                  <span className="text-[10px] font-mono text-purple-400 bg-purple-950 px-2 py-0.5 rounded border border-purple-900/60">Stage 15</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Predicts risk class probability across 18 extracted forensic features.
                </p>
                <button
                  onClick={() => onOpenModal('mlClassifier')}
                  className="w-full mt-1 bg-purple-950/50 hover:bg-purple-950 border border-purple-800/60 text-purple-300 py-1.5 rounded-lg text-xs font-medium transition flex items-center justify-center space-x-1.5"
                >
                  <Brain className="w-3.5 h-3.5" />
                  <span>Launch ML Risk Predictor</span>
                </button>
              </div>
            </div>
          </div>

          {/* Hardening Remediation Action Catalog Preview */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="p-2 bg-blue-950/80 rounded-lg text-blue-400 border border-blue-800/60">
                  <Wrench className="w-4 h-4" />
                </div>
                <h3 className="font-bold text-white text-sm">Automated Remediation Catalog</h3>
              </div>
              <button
                onClick={() => onOpenModal('recommendations')}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center space-x-1"
              >
                <span>View All ({recommendations?.total_recommendations || 0})</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {!recommendations || recommendations.recommendations.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs bg-slate-950 rounded-xl border border-slate-800">
                No active remediation actions triggered. Posture is hardened or unanalyzed.
              </div>
            ) : (
              <div className="space-y-2.5">
                {recommendations.recommendations.slice(0, 3).map((rec) => (
                  <div key={rec.id} className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-200">{rec.affected_component}</span>
                      <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-900">
                        {rec.rule_id}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-2">{rec.recommended_action}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>

      </div>

      {/* Quick Launch Action Matrix */}
      <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
        <div className="flex items-center space-x-2">
          <Sliders className="w-5 h-5 text-indigo-400" />
          <h3 className="font-bold text-white text-sm">Forensic Module Direct Access Matrix</h3>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 text-xs">
          <button
            onClick={() => onOpenModal('packets')}
            className="p-3 rounded-xl bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition flex flex-col items-center justify-center space-y-1.5"
          >
            <FileText className="w-4 h-4 text-blue-400" />
            <span>Hex Packets</span>
          </button>
          
          <button
            onClick={() => onOpenModal('protocols')}
            className="p-3 rounded-xl bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition flex flex-col items-center justify-center space-y-1.5"
          >
            <Server className="w-4 h-4 text-indigo-400" />
            <span>Protocols</span>
          </button>

          <button
            onClick={() => onOpenModal('sessions')}
            className="p-3 rounded-xl bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition flex flex-col items-center justify-center space-y-1.5"
          >
            <Activity className="w-4 h-4 text-emerald-400" />
            <span>TCP Streams</span>
          </button>

          <button
            onClick={() => onOpenModal('starttls')}
            className="p-3 rounded-xl bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition flex flex-col items-center justify-center space-y-1.5"
          >
            <Unlock className="w-4 h-4 text-amber-400" />
            <span>STARTTLS</span>
          </button>

          <button
            onClick={() => onOpenModal('tlsHandshake')}
            className="p-3 rounded-xl bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition flex flex-col items-center justify-center space-y-1.5"
          >
            <Lock className="w-4 h-4 text-purple-400" />
            <span>TLS Handshakes</span>
          </button>

          <button
            onClick={() => onOpenModal('evidence')}
            className="p-3 rounded-xl bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition flex flex-col items-center justify-center space-y-1.5"
          >
            <Layers className="w-4 h-4 text-pink-400" />
            <span>Evidence Chain</span>
          </button>
        </div>
      </div>

    </div>
  );
};
