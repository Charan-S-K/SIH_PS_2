import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { HealthCard } from './components/HealthCard';
import { PcapUploadCard } from './components/PcapUploadCard';
import { JobsTable } from './components/JobsTable';
import { PacketsModal } from './components/PacketsModal';
import { ProtocolsModal } from './components/ProtocolsModal';
import { SessionsModal } from './components/SessionsModal';
import { EmailAnalysisModal } from './components/EmailAnalysisModal';
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
import { ShieldCheck, Layers, GitBranch, HardDrive } from 'lucide-react';

export const App: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [info, setInfo] = useState<InfoResponse | null>(null);
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<AnalysisJob | null>(null);
  const [selectedJobForProtocols, setSelectedJobForProtocols] = useState<AnalysisJob | null>(null);
  const [selectedJobForSessions, setSelectedJobForSessions] = useState<AnalysisJob | null>(null);
  const [selectedJobForEmailAnalysis, setSelectedJobForEmailAnalysis] = useState<AnalysisJob | null>(null);
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
    }
    setLoadingJobs(false);
  }, []);

  useEffect(() => {
    loadStatus();
    loadJobs();
    const interval = setInterval(() => {
      loadStatus();
      loadJobs();
    }, 30000);
    return () => clearInterval(interval);
  }, [loadStatus, loadJobs]);

  return (
    <div className="min-h-screen bg-[#0b0f19] flex flex-col font-sans text-slate-100">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Banner */}
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-blue-950/60 via-slate-900 to-indigo-950/40 border border-blue-900/30 p-8 shadow-2xl">
          <div className="relative z-10 max-w-3xl">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-blue-900/40 border border-blue-700/50 text-blue-300 text-xs font-medium mb-4">
              <ShieldCheck className="h-4 w-4" />
              <span>SIH 2024 / SIH26159 Project Posture Engine</span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              Cryptographic Security Posture Assessment
            </h1>
            <p className="mt-3 text-base text-slate-300 leading-relaxed">
              Passive email cryptographic forensics platform analyzing SMTP, IMAP, and POP3 network traffic.
              Stage 03 adds behavioral email protocol identification, conversational flow analysis, TLS handshake inspection, and forensic evidence tracking.
            </p>
          </div>
        </div>

        {/* Ingestion & Status Grid */}
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

        {/* Jobs History Table */}
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
        />

        {/* Architectural Principles Preview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
            <div className="p-2.5 w-fit rounded-lg bg-blue-950 text-blue-400 mb-3 border border-blue-800/40">
              <Layers className="h-5 w-5" />
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">Evidence-First Forensic Model</h3>
            <p className="mt-2 text-xs text-slate-400 leading-relaxed">
              Facts → Rules → Evidence → ML → Prioritization → Recommendation. No fabricated facts; explicit UNKNOWN support.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-slate-800">
            <div className="p-2.5 w-fit rounded-lg bg-emerald-950 text-emerald-400 mb-3 border border-emerald-800/40">
              <GitBranch className="h-5 w-5" />
            </div>
            <h3 className="font-semibold text-slate-200 text-sm">Strict Stage Lifecycle</h3>
            <p className="mt-2 text-xs text-slate-400 leading-relaxed">
              Human-gated development: Implement → Review-only Check → User Validation → Manual Git Approval. 28 modular milestones.
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

        {/* Packet Inspection Modal */}
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

        {/* Protocol Identification & Forensic Evidence Modal */}
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

        {/* TCP Sessions & Conversation Flow Modal */}
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

        {/* Email Protocol Analysis Modal */}
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
      </main>

      <footer className="border-t border-slate-800/80 bg-[#0e1626]/50 py-4 text-center text-xs text-slate-500">
        SecureMailScope &bull; Stage 05 Email Protocol Analysis &bull; Free & Open-Source Cybersecurity Posture Platform
      </footer>
    </div>
  );
};
