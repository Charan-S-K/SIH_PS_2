import React, { useState } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, RefreshCw, Server, Database, Info } from 'lucide-react';
import { HealthResponse, ReadinessResponse, InfoResponse } from '../services/api';

interface HealthCardProps {
  health: HealthResponse | null;
  readiness: ReadinessResponse | null;
  info: InfoResponse | null;
  latencyMs: number | null;
  error: string | null;
  loading: boolean;
  onRefresh: () => void;
}

export const HealthCard: React.FC<HealthCardProps> = ({
  health,
  readiness,
  info,
  latencyMs,
  error,
  loading,
  onRefresh,
}) => {
  const [showDetails, setShowDetails] = useState(false);

  const isBackendOnline = health !== null && !error;
  const isDbConnected = readiness?.database?.status === 'connected';

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 shadow-xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-slate-800/80 gap-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-100 flex items-center space-x-2">
            <span>System Health & Connectivity</span>
          </h2>
          <p className="text-sm text-slate-400">
            Real-time status of FastAPI application and PostgreSQL persistence subsystem
          </p>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center space-x-2 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800/50 text-white transition-colors duration-150 shadow-sm"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>{loading ? 'Probing...' : 'Refresh Status'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
        {/* Backend Status Card */}
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-md bg-blue-950/60 border border-blue-800/40 text-blue-400">
                <Server className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-medium text-slate-200">FastAPI Backend</h3>
                <p className="text-xs text-slate-400">REST API Engine</p>
              </div>
            </div>
            {isBackendOnline ? (
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
                <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
                Online
              </span>
            ) : (
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-rose-950 text-rose-400 border border-rose-800">
                <XCircle className="h-3.5 w-3.5 mr-1" />
                Offline
              </span>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-slate-400">Version:</span>{' '}
              <span className="font-mono text-slate-200">{health?.version || '—'}</span>
            </div>
            <div>
              <span className="text-slate-400">Latency:</span>{' '}
              <span className="font-mono text-slate-200">{latencyMs !== null ? `${latencyMs} ms` : '—'}</span>
            </div>
            <div>
              <span className="text-slate-400">Environment:</span>{' '}
              <span className="font-mono text-slate-200">{health?.environment || '—'}</span>
            </div>
            <div>
              <span className="text-slate-400">Route:</span>{' '}
              <span className="font-mono text-slate-200">/api/v1/health</span>
            </div>
          </div>
        </div>

        {/* Database Status Card */}
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-md bg-purple-950/60 border border-purple-800/40 text-purple-400">
                <Database className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-medium text-slate-200">PostgreSQL</h3>
                <p className="text-xs text-slate-400">Forensic Persistence Store</p>
              </div>
            </div>
            {isDbConnected ? (
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
                <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
                Connected
              </span>
            ) : isBackendOnline ? (
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-amber-950 text-amber-400 border border-amber-800">
                <AlertTriangle className="h-3.5 w-3.5 mr-1" />
                Degraded
              </span>
            ) : (
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
                <XCircle className="h-3.5 w-3.5 mr-1" />
                Unreachable
              </span>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/60 grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-slate-400">Status:</span>{' '}
              <span className="font-mono text-slate-200">{readiness?.database?.status || 'unknown'}</span>
            </div>
            <div>
              <span className="text-slate-400">Probe Route:</span>{' '}
              <span className="font-mono text-slate-200">/api/v1/health/ready</span>
            </div>
            <div className="col-span-2">
              <span className="text-slate-400">Details:</span>{' '}
              <span className="font-mono text-slate-300 truncate block">
                {readiness?.database?.error ? readiness.database.error : 'Connection active (SELECT 1 succeeded)'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Diagnostic Collapsible */}
      <div className="mt-6 pt-4 border-t border-slate-800/80">
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="text-xs text-blue-400 hover:text-blue-300 flex items-center space-x-1.5 focus:outline-none"
        >
          <Info className="h-3.5 w-3.5" />
          <span>{showDetails ? 'Hide Architecture Metadata' : 'View Architecture Metadata'}</span>
        </button>

        {showDetails && info && (
          <div className="mt-3 p-4 rounded-lg bg-black/40 border border-slate-800 text-xs font-mono space-y-2">
            <div><span className="text-slate-500">Project:</span> {info.project_name}</div>
            <div><span className="text-slate-500">Description:</span> {info.project_description}</div>
            <div><span className="text-slate-500">Supported Protocols:</span> {info.supported_protocols.join(', ')}</div>
            <div><span className="text-slate-500">Cryptographic Targets:</span> {info.cryptographic_standards.join(', ')}</div>
            <div><span className="text-slate-500">Current Lifecycle:</span> {info.current_stage}</div>
          </div>
        )}
      </div>
    </div>
  );
};
