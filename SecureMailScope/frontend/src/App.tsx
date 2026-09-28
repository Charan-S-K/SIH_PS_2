import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { HealthCard } from './components/HealthCard';
import { PcapUploadCard } from './components/PcapUploadCard';
import { JobsTable } from './components/JobsTable';
import { PacketsModal } from './components/PacketsModal';
import { ProtocolsModal } from './components/ProtocolsModal';
import { SessionsModal } from './components/SessionsModal';
import { EmailAnalysisModal } from './components/EmailAnalysisModal';
import { StarttlsModal } from './components/StarttlsModal';
import { TlsHandshakeModal } from './components/TlsHandshakeModal';
import { CertificateModal } from './components/CertificateModal';
import { CryptoFindingsModal } from './components/CryptoFindingsModal';
import { FindingsModal } from './components/FindingsModal';
import { SecurityPostureModal } from './components/SecurityPostureModal';
import { MlDatasetModal } from './components/MlDatasetModal';
import { MlRiskClassifierModal } from './components/MlRiskClassifierModal';
import { TlsAnomalyModal } from './components/TlsAnomalyModal';
import { SyntheticAnomalyModal } from './components/SyntheticAnomalyModal';
import { PrioritizationModal } from './components/PrioritizationModal';
import { RecommendationsModal } from './components/RecommendationsModal';
import { EvidenceExplorerModal } from './components/EvidenceExplorerModal';
import { SecurityDashboardView } from './components/SecurityDashboardView';
import {
  checkLiveness,
  checkReadiness,
  fetchSystemInfo,
  listJobs,
  HealthResponse,
  ReadinessResponse,
  InfoResponse,
  AnalysisJob
} from './services/api';
import {
  ShieldCheck,
  Layers,
  GitBranch,
  HardDrive,
  Brain,
  ShieldAlert,
  ListOrdered,
  Wrench,
  Server,
  Lock
} from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [info, setInfo] = useState<InfoResponse | null>(null);
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [activeJob, setActiveJob] = useState<AnalysisJob | null>(null);

  // Modal inspection target states
  const [selectedJob, setSelectedJob] = useState<AnalysisJob | null>(null);
  const [selectedJobForProtocols, setSelectedJobForProtocols] = useState<AnalysisJob | null>(null);
  const [selectedJobForSessions, setSelectedJobForSessions] = useState<AnalysisJob | null>(null);
  const [selectedJobForEmailAnalysis, setSelectedJobForEmailAnalysis] = useState<AnalysisJob | null>(null);
  const [selectedJobForStarttls, setSelectedJobForStarttls] = useState<AnalysisJob | null>(null);
  const [selectedJobForTlsHandshakes, setSelectedJobForTlsHandshakes] = useState<AnalysisJob | null>(null);
  const [selectedJobForCertificates, setSelectedJobForCertificates] = useState<AnalysisJob | null>(null);
  const [selectedJobForCryptoFindings, setSelectedJobForCryptoFindings] = useState<AnalysisJob | null>(null);
  const [selectedJobForUnifiedFindings, setSelectedJobForUnifiedFindings] = useState<AnalysisJob | null>(null);
  const [selectedJobForSecurityPosture, setSelectedJobForSecurityPosture] = useState<AnalysisJob | null>(null);
  
  // Independent AI/Engine modals
  const [isMlDatasetOpen, setIsMlDatasetOpen] = useState<boolean>(false);
  const [isMlClassifierOpen, setIsMlClassifierOpen] = useState<boolean>(false);
  const [isTlsAnomalyOpen, setIsTlsAnomalyOpen] = useState<boolean>(false);
  const [isSyntheticAnomalyOpen, setIsSyntheticAnomalyOpen] = useState<boolean>(false);
  const [isPrioritizationOpen, setIsPrioritizationOpen] = useState<boolean>(false);
  const [isRecommendationsOpen, setIsRecommendationsOpen] = useState<boolean>(false);
  const [isEvidenceExplorerOpen, setIsEvidenceExplorerOpen] = useState<boolean>(false);

  const [targetStreamId, setTargetStreamId] = useState<number | undefined>(undefined);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadingHealth, setLoadingHealth] = useState<boolean>(true);
  const [loadingJobs, setLoadingJobs] = useState<boolean>(false);

  const loadStatus = useCallback(async () => {
    setLoadingHealth(true);
    const [livenessRes, readinessRes, infoRes] = await Promise.all([
      checkLiveness(),
      checkReadiness(),
      fetchSystemInfo(),
    ]);

    setHealth(livenessRes.data);
    setLatencyMs(livenessRes.latencyMs);
    setError(livenessRes.error);
    setReadiness(readinessRes.data);
    setInfo(infoRes.data);
    setLoadingHealth(false);
  }, []);

  const loadJobs = useCallback(async () => {
    setLoadingJobs(true);
    const { data } = await listJobs(20, 0);
    if (data && data.jobs) {
      setJobs(data.jobs);
      if (!activeJob && data.jobs.length > 0) {
        setActiveJob(data.jobs[0]);
      }
    }
    setLoadingJobs(false);
  }, [activeJob]);

  useEffect(() => {
    loadStatus();
    loadJobs();
    const interval = setInterval(() => {
      loadStatus();
      loadJobs();
    }, 30000);
    return () => clearInterval(interval);
  }, [loadStatus, loadJobs]);

  const handleOpenModalByName = (modalName: string) => {
    const target = activeJob || (jobs.length > 0 ? jobs[0] : null);
    switch (modalName) {
      case 'packets':
        if (target) setSelectedJob(target);
        break;
      case 'protocols':
        if (target) setSelectedJobForProtocols(target);
        break;
      case 'sessions':
        if (target) setSelectedJobForSessions(target);
        break;
      case 'emailAnalysis':
        if (target) setSelectedJobForEmailAnalysis(target);
        break;
      case 'starttls':
        if (target) setSelectedJobForStarttls(target);
        break;
      case 'tlsHandshake':
        if (target) setSelectedJobForTlsHandshakes(target);
        break;
      case 'certificates':
        if (target) setSelectedJobForCertificates(target);
        break;
      case 'cryptoFindings':
        if (target) setSelectedJobForCryptoFindings(target);
        break;
      case 'findings':
        if (target) setSelectedJobForUnifiedFindings(target);
        break;
      case 'evidence':
        setIsEvidenceExplorerOpen(true);
        break;
      case 'posture':
        if (target) setSelectedJobForSecurityPosture(target);
        break;
      case 'mlDataset':
        setIsMlDatasetOpen(true);
        break;
      case 'mlClassifier':
        setIsMlClassifierOpen(true);
        break;
      case 'tlsAnomaly':
        setIsTlsAnomalyOpen(true);
        break;
      case 'synthetic':
        setIsSyntheticAnomalyOpen(true);
        break;
      case 'prioritization':
        setIsPrioritizationOpen(true);
        break;
      case 'recommendations':
        setIsRecommendationsOpen(true);
        break;
      default:
        break;
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0f19] flex flex-col font-sans text-slate-100">
      <Navbar activeTab={activeTab} onTabChange={setActiveTab} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        
        {/* Banner with Quick Launcher Matrix */}
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-blue-950/60 via-slate-900 to-indigo-950/40 border border-blue-900/30 p-8 shadow-2xl flex flex-wrap items-center justify-between gap-6">
          <div className="relative z-10 max-w-3xl">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-blue-900/40 border border-blue-700/50 text-blue-300 text-xs font-medium mb-4">
              <ShieldCheck className="h-4 w-4" />
              <span>SIH 2024 / SIH26159 Project Security Platform</span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              Stage 20 &bull; Security Dashboard
            </h1>
            <p className="mt-3 text-base text-slate-300 leading-relaxed">
              Unified Security Dashboard providing real-time forensic visibility across PCAP ingestion, email protocol analysis, TLS handshakes, cryptographic rules engine, machine learning classifiers, unsupervised isolation forest anomaly detection, and automated remediation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={() => setIsEvidenceExplorerOpen(true)}
              className="flex items-center space-x-2 bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs px-4 py-2 rounded-xl transition shadow-lg shadow-indigo-600/20 border border-indigo-500/30"
            >
              <Layers className="w-4 h-4" />
              <span>Evidence Explorer</span>
            </button>
            <button
              onClick={() => setIsMlClassifierOpen(true)}
              className="flex items-center space-x-2 bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs px-4 py-2 rounded-xl transition shadow-lg shadow-purple-600/20 border border-purple-500/30"
            >
              <Brain className="w-4 h-4" />
              <span>ML Classifier</span>
            </button>
            <button
              onClick={() => setIsTlsAnomalyOpen(true)}
              className="flex items-center space-x-2 bg-pink-600 hover:bg-pink-500 text-white font-medium text-xs px-4 py-2 rounded-xl transition shadow-lg shadow-pink-600/20 border border-pink-500/30"
            >
              <ShieldAlert className="w-4 h-4" />
              <span>TLS Anomaly</span>
            </button>
            <button
              onClick={() => setIsPrioritizationOpen(true)}
              className="flex items-center space-x-2 bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs px-4 py-2 rounded-xl transition shadow-lg shadow-amber-600/20 border border-amber-500/30"
            >
              <ListOrdered className="w-4 h-4" />
              <span>Prioritization</span>
            </button>
            <button
              onClick={() => setIsRecommendationsOpen(true)}
              className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs px-4 py-2 rounded-xl transition shadow-lg shadow-blue-600/20 border border-blue-500/30"
            >
              <Wrench className="w-4 h-4 text-blue-200" />
              <span>Remediation</span>
            </button>
          </div>
        </div>

        {/* Tab-Based Dynamic Main View Rendering */}
        {activeTab === 'dashboard' && (
          <SecurityDashboardView
            jobs={jobs}
            selectedJob={activeJob}
            onSelectJob={setActiveJob}
            onOpenModal={handleOpenModalByName}
          />
        )}

        {activeTab === 'ingestion' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <PcapUploadCard onUploadSuccess={loadJobs} />
              <HealthCard
                health={health}
                readiness={readiness}
                info={info}
                latencyMs={latencyMs}
                error={error}
                loading={loadingHealth}
                onRefresh={loadStatus}
              />
            </div>
            <JobsTable
              jobs={jobs}
              loading={loadingJobs}
              onRefresh={loadJobs}
              onInspectJob={(job) => {
                setTargetStreamId(undefined);
                setSelectedJob(job);
              }}
              onViewProtocols={(job) => setSelectedJobForProtocols(job)}
              onViewSessions={(job) => setSelectedJobForSessions(job)}
              onViewEmailAnalysis={(job) => setSelectedJobForEmailAnalysis(job)}
              onViewStarttls={(job) => setSelectedJobForStarttls(job)}
              onViewTlsHandshakes={(job) => setSelectedJobForTlsHandshakes(job)}
              onViewCertificates={(job) => setSelectedJobForCertificates(job)}
              onViewCryptoFindings={(job) => setSelectedJobForCryptoFindings(job)}
              onViewUnifiedFindings={(job) => setSelectedJobForUnifiedFindings(job)}
              onViewSecurityPosture={(job) => setSelectedJobForSecurityPosture(job)}
            />
          </div>
        )}

        {activeTab === 'protocols' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
              <h3 className="font-bold text-white text-lg flex items-center space-x-2">
                <Server className="w-5 h-5 text-indigo-400" />
                <span>Protocol & TCP Session Forensics</span>
              </h3>
              <p className="text-xs text-slate-400">
                Inspect identified email protocols (SMTP, IMAP, POP3) and bidirectional TCP session reconstruction streams across active PCAP jobs.
              </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <button
                  onClick={() => handleOpenModalByName('protocols')}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Open Protocol Identification Viewer
                </button>
                <button
                  onClick={() => handleOpenModalByName('sessions')}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Open TCP Sessions & Flow Inspector
                </button>
                <button
                  onClick={() => handleOpenModalByName('emailAnalysis')}
                  className="bg-blue-600 hover:bg-blue-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Open Email Command Inspector
                </button>
              </div>
            </div>
            <JobsTable
              jobs={jobs}
              loading={loadingJobs}
              onRefresh={loadJobs}
              onInspectJob={(job) => setSelectedJob(job)}
              onViewProtocols={(job) => setSelectedJobForProtocols(job)}
              onViewSessions={(job) => setSelectedJobForSessions(job)}
              onViewEmailAnalysis={(job) => setSelectedJobForEmailAnalysis(job)}
              onViewStarttls={(job) => setSelectedJobForStarttls(job)}
              onViewTlsHandshakes={(job) => setSelectedJobForTlsHandshakes(job)}
              onViewCertificates={(job) => setSelectedJobForCertificates(job)}
              onViewCryptoFindings={(job) => setSelectedJobForCryptoFindings(job)}
              onViewUnifiedFindings={(job) => setSelectedJobForUnifiedFindings(job)}
              onViewSecurityPosture={(job) => setSelectedJobForSecurityPosture(job)}
            />
          </div>
        )}

        {activeTab === 'tls' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
              <h3 className="font-bold text-white text-lg flex items-center space-x-2">
                <Lock className="w-5 h-5 text-purple-400" />
                <span>TLS Handshakes & X.509 Certificate Cryptography</span>
              </h3>
              <p className="text-xs text-slate-400">
                Detailed inspection of observable TLS Client/Server Hello handshakes, cipher suites, STARTTLS upgrades, and X.509 certificate chains.
              </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <button
                  onClick={() => handleOpenModalByName('starttls')}
                  className="bg-amber-600 hover:bg-amber-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Inspect STARTTLS Upgrades & Downgrades
                </button>
                <button
                  onClick={() => handleOpenModalByName('tlsHandshake')}
                  className="bg-purple-600 hover:bg-purple-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Inspect TLS Handshake Versions & Ciphers
                </button>
                <button
                  onClick={() => handleOpenModalByName('certificates')}
                  className="bg-blue-600 hover:bg-blue-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Inspect X.509 Certificate Chains
                </button>
              </div>
            </div>
            <JobsTable
              jobs={jobs}
              loading={loadingJobs}
              onRefresh={loadJobs}
              onInspectJob={(job) => setSelectedJob(job)}
              onViewProtocols={(job) => setSelectedJobForProtocols(job)}
              onViewSessions={(job) => setSelectedJobForSessions(job)}
              onViewEmailAnalysis={(job) => setSelectedJobForEmailAnalysis(job)}
              onViewStarttls={(job) => setSelectedJobForStarttls(job)}
              onViewTlsHandshakes={(job) => setSelectedJobForTlsHandshakes(job)}
              onViewCertificates={(job) => setSelectedJobForCertificates(job)}
              onViewCryptoFindings={(job) => setSelectedJobForCryptoFindings(job)}
              onViewUnifiedFindings={(job) => setSelectedJobForUnifiedFindings(job)}
              onViewSecurityPosture={(job) => setSelectedJobForSecurityPosture(job)}
            />
          </div>
        )}

        {activeTab === 'findings' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
              <h3 className="font-bold text-white text-lg flex items-center space-x-2">
                <ShieldAlert className="w-5 h-5 text-red-400" />
                <span>Unified Security Findings & Non-Destructive Evidence Chain</span>
              </h3>
              <p className="text-xs text-slate-400">
                Correlated security findings generated by YAML cryptographic rules engine, STARTTLS state machine, and evidence linkage inspector.
              </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <button
                  onClick={() => handleOpenModalByName('evidence')}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Launch Interactive Evidence Chain Explorer
                </button>
                <button
                  onClick={() => handleOpenModalByName('findings')}
                  className="bg-red-600 hover:bg-red-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Open Unified Findings Matrix
                </button>
              </div>
            </div>
            <JobsTable
              jobs={jobs}
              loading={loadingJobs}
              onRefresh={loadJobs}
              onInspectJob={(job) => setSelectedJob(job)}
              onViewProtocols={(job) => setSelectedJobForProtocols(job)}
              onViewSessions={(job) => setSelectedJobForSessions(job)}
              onViewEmailAnalysis={(job) => setSelectedJobForEmailAnalysis(job)}
              onViewStarttls={(job) => setSelectedJobForStarttls(job)}
              onViewTlsHandshakes={(job) => setSelectedJobForTlsHandshakes(job)}
              onViewCertificates={(job) => setSelectedJobForCertificates(job)}
              onViewCryptoFindings={(job) => setSelectedJobForCryptoFindings(job)}
              onViewUnifiedFindings={(job) => setSelectedJobForUnifiedFindings(job)}
              onViewSecurityPosture={(job) => setSelectedJobForSecurityPosture(job)}
            />
          </div>
        )}

        {activeTab === 'posture' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
              <h3 className="font-bold text-white text-lg flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>Explainable Cryptographic Security Posture Aggregation</span>
              </h3>
              <p className="text-xs text-slate-400">
                Calculates session/server/capture posture scores (0-100) with explicit CRITICAL, HIGH, MEDIUM, LOW ratings and contributing factor rationales.
              </p>
              <button
                onClick={() => handleOpenModalByName('posture')}
                className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
              >
                Inspect Posture Score Rationale
              </button>
            </div>
            <JobsTable
              jobs={jobs}
              loading={loadingJobs}
              onRefresh={loadJobs}
              onInspectJob={(job) => setSelectedJob(job)}
              onViewProtocols={(job) => setSelectedJobForProtocols(job)}
              onViewSessions={(job) => setSelectedJobForSessions(job)}
              onViewEmailAnalysis={(job) => setSelectedJobForEmailAnalysis(job)}
              onViewStarttls={(job) => setSelectedJobForStarttls(job)}
              onViewTlsHandshakes={(job) => setSelectedJobForTlsHandshakes(job)}
              onViewCertificates={(job) => setSelectedJobForCertificates(job)}
              onViewCryptoFindings={(job) => setSelectedJobForCryptoFindings(job)}
              onViewUnifiedFindings={(job) => setSelectedJobForUnifiedFindings(job)}
              onViewSecurityPosture={(job) => setSelectedJobForSecurityPosture(job)}
            />
          </div>
        )}

        {activeTab === 'ml' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
              <h3 className="font-bold text-white text-lg flex items-center space-x-2">
                <Brain className="w-5 h-5 text-purple-400" />
                <span>Machine Learning & Anomaly AI Suite</span>
              </h3>
              <p className="text-xs text-slate-400">
                Synthetic dataset generator, Random Forest risk classifier, Isolation Forest unsupervised TLS anomaly detector, and synthetic mutation evaluator.
              </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <button
                  onClick={() => setIsMlDatasetOpen(true)}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  ML Synthetic Dataset Generator
                </button>
                <button
                  onClick={() => setIsMlClassifierOpen(true)}
                  className="bg-purple-600 hover:bg-purple-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  ML Random Forest Classifier
                </button>
                <button
                  onClick={() => setIsTlsAnomalyOpen(true)}
                  className="bg-pink-600 hover:bg-pink-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  TLS Isolation Forest Anomaly Detector
                </button>
                <button
                  onClick={() => setIsSyntheticAnomalyOpen(true)}
                  className="bg-amber-600 hover:bg-amber-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Synthetic Mutation Injector
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'remediation' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 space-y-4">
              <h3 className="font-bold text-white text-lg flex items-center space-x-2">
                <ListOrdered className="w-5 h-5 text-amber-400" />
                <span>Risk Prioritization & Remediation Engine</span>
              </h3>
              <p className="text-xs text-slate-400">
                Risk Priority Scoring S_priority in [0, 100], SHAP feature attributions, and deterministic Postfix/Dovecot/OpenSSL remediation action catalog.
              </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <button
                  onClick={() => setIsPrioritizationOpen(true)}
                  className="bg-amber-600 hover:bg-amber-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Open Prioritization & SHAP Engine
                </button>
                <button
                  onClick={() => setIsRecommendationsOpen(true)}
                  className="bg-blue-600 hover:bg-blue-500 text-white text-xs px-4 py-2 rounded-xl transition font-medium"
                >
                  Open Remediation Action Catalog
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Architectural Principles Preview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
            <div className="p-2.5 w-fit rounded-lg bg-blue-950 text-blue-400 mb-3 border border-blue-800/40">
              <Layers className="h-5 w-5" />
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">Evidence-First Forensic Model</h3>
            <p className="mt-2 text-xs text-slate-400 leading-relaxed">
              Facts &rarr; Rules &rarr; Evidence &rarr; ML &rarr; Prioritization &rarr; Recommendation. No fabricated facts; explicit UNKNOWN support.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
            <div className="p-2.5 w-fit rounded-lg bg-emerald-950 text-emerald-400 mb-3 border border-emerald-800/40">
              <GitBranch className="h-5 w-5" />
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">Strict Stage Lifecycle</h3>
            <p className="mt-2 text-xs text-slate-400 leading-relaxed">
              Human-gated development: Implement &rarr; Review-only Check &rarr; User Validation &rarr; Manual Git Approval. Stage 20 Security Dashboard.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
            <div className="p-2.5 w-fit rounded-lg bg-purple-950 text-purple-400 mb-3 border border-purple-800/40">
              <HardDrive className="h-5 w-5" />
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">Forensic Metadata Engine</h3>
            <p className="mt-2 text-xs text-slate-400 leading-relaxed">
              High-throughput packet parsing, frame indexing, conversation stream isolation, and non-destructive payload inspection.
            </p>
          </div>
        </div>

        {/* Modal overlays */}
        {selectedJob && (
          <PacketsModal
            job={selectedJob}
            initialStreamId={targetStreamId}
            onClose={() => {
              setSelectedJob(null);
              setTargetStreamId(undefined);
            }}
          />
        )}

        {selectedJobForProtocols && (
          <ProtocolsModal
            jobId={selectedJobForProtocols.id}
            filename={selectedJobForProtocols.pcap_file?.original_filename || 'capture.pcap'}
            onClose={() => setSelectedJobForProtocols(null)}
            onInspectFrames={(streamId) => {
              const job = selectedJobForProtocols;
              setSelectedJobForProtocols(null);
              setTargetStreamId(streamId);
              setSelectedJob(job);
            }}
          />
        )}

        {selectedJobForSessions && (
          <SessionsModal
            jobId={selectedJobForSessions.id}
            filename={selectedJobForSessions.pcap_file?.original_filename || 'capture.pcap'}
            onClose={() => setSelectedJobForSessions(null)}
            onInspectFrames={(streamId) => {
              const job = selectedJobForSessions;
              setSelectedJobForSessions(null);
              setTargetStreamId(streamId);
              setSelectedJob(job);
            }}
          />
        )}

        {selectedJobForEmailAnalysis && (
          <EmailAnalysisModal
            jobId={selectedJobForEmailAnalysis.id}
            filename={selectedJobForEmailAnalysis.pcap_file?.original_filename || 'capture.pcap'}
            onClose={() => setSelectedJobForEmailAnalysis(null)}
            onInspectFrames={(streamId) => {
              const job = selectedJobForEmailAnalysis;
              setSelectedJobForEmailAnalysis(null);
              setTargetStreamId(streamId);
              setSelectedJob(job);
            }}
          />
        )}

        {selectedJobForStarttls && (
          <StarttlsModal
            jobId={selectedJobForStarttls.id}
            filename={selectedJobForStarttls.pcap_file?.original_filename || 'capture.pcap'}
            onClose={() => setSelectedJobForStarttls(null)}
            onInspectFrames={(streamId) => {
              const job = selectedJobForStarttls;
              setSelectedJobForStarttls(null);
              setTargetStreamId(streamId);
              setSelectedJob(job);
            }}
          />
        )}

        {selectedJobForTlsHandshakes && (
          <TlsHandshakeModal
            jobId={selectedJobForTlsHandshakes.id}
            filename={selectedJobForTlsHandshakes.pcap_file?.original_filename || 'capture.pcap'}
            onClose={() => setSelectedJobForTlsHandshakes(null)}
            onInspectFrames={(streamId) => {
              const job = selectedJobForTlsHandshakes;
              setSelectedJobForTlsHandshakes(null);
              setTargetStreamId(streamId);
              setSelectedJob(job);
            }}
          />
        )}

        {selectedJobForCertificates && (
          <CertificateModal
            jobId={selectedJobForCertificates.id}
            isOpen={true}
            onClose={() => setSelectedJobForCertificates(null)}
            onInspectPackets={(streamId) => {
              const job = selectedJobForCertificates;
              setSelectedJobForCertificates(null);
              setTargetStreamId(streamId);
              setSelectedJob(job);
            }}
          />
        )}

        {selectedJobForCryptoFindings && (
          <CryptoFindingsModal
            jobId={selectedJobForCryptoFindings.id}
            filename={selectedJobForCryptoFindings.pcap_file?.original_filename || 'capture.pcap'}
            isOpen={true}
            onClose={() => setSelectedJobForCryptoFindings(null)}
            onInspectPackets={(streamId) => {
              const job = selectedJobForCryptoFindings;
              setSelectedJobForCryptoFindings(null);
              setTargetStreamId(streamId);
              setSelectedJob(job);
            }}
          />
        )}

        {selectedJobForUnifiedFindings && (
          <FindingsModal
            jobId={selectedJobForUnifiedFindings.id}
            filename={selectedJobForUnifiedFindings.pcap_file?.original_filename || 'capture.pcap'}
            isOpen={true}
            onClose={() => setSelectedJobForUnifiedFindings(null)}
            onInspectPackets={(streamId) => {
              const job = selectedJobForUnifiedFindings;
              setSelectedJobForUnifiedFindings(null);
              setTargetStreamId(streamId);
              setSelectedJob(job);
            }}
          />
        )}

        {selectedJobForSecurityPosture && (
          <SecurityPostureModal
            jobId={selectedJobForSecurityPosture.id}
            filename={selectedJobForSecurityPosture.pcap_file?.original_filename || 'capture.pcap'}
            isOpen={true}
            onClose={() => setSelectedJobForSecurityPosture(null)}
          />
        )}

        {/* Evidence Explorer Modal */}
        <EvidenceExplorerModal
          jobId={activeJob?.id || (jobs.length > 0 ? jobs[0].id : '')}
          filename={activeJob?.pcap_file?.original_filename || (jobs.length > 0 && jobs[0].pcap_file ? jobs[0].pcap_file.original_filename : 'capture.pcap')}
          isOpen={isEvidenceExplorerOpen}
          onClose={() => setIsEvidenceExplorerOpen(false)}
          onInspectPackets={(streamId) => {
            const target = activeJob || (jobs.length > 0 ? jobs[0] : null);
            if (target) {
              setTargetStreamId(streamId);
              setSelectedJob(target);
            }
          }}
        />

        <MlDatasetModal
          isOpen={isMlDatasetOpen}
          onClose={() => setIsMlDatasetOpen(false)}
        />

        <MlRiskClassifierModal
          isOpen={isMlClassifierOpen}
          onClose={() => setIsMlClassifierOpen(false)}
        />

        <TlsAnomalyModal
          isOpen={isTlsAnomalyOpen}
          onClose={() => setIsTlsAnomalyOpen(false)}
        />

        <SyntheticAnomalyModal
          isOpen={isSyntheticAnomalyOpen}
          onClose={() => setIsSyntheticAnomalyOpen(false)}
        />

        <PrioritizationModal
          isOpen={isPrioritizationOpen}
          onClose={() => setIsPrioritizationOpen(false)}
        />

        <RecommendationsModal
          isOpen={isRecommendationsOpen}
          onClose={() => setIsRecommendationsOpen(false)}
        />
      </main>

      <footer className="border-t border-slate-800/80 bg-[#0e1626]/50 py-4 text-center text-xs text-slate-500">
        SecureMailScope &bull; Stage 20 Security Dashboard &bull; Free & Open-Source Cybersecurity Posture Platform
      </footer>
    </div>
  );
};
