import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  X,
  Cpu,
  Activity,
  AlertTriangle,
  CheckCircle,
  Play
} from 'lucide-react';
import {
  trainTlsAnomalyDetector,
  fetchTlsAnomalyDetectors,
  predictJobTlsAnomalies,
  getJobTlsAnomalySummary,
  fetchMlDatasetBatches,
  generateMlDataset,
  TlsAnomalyDetectorItem,
  JobAnomalySummaryResponseItem
} from '../services/api';

interface TlsAnomalyModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentJobId?: string;
}

export const TlsAnomalyModal: React.FC<TlsAnomalyModalProps> = ({ isOpen, onClose, currentJobId }) => {
  const [activeTab, setActiveTab] = useState<'detectors' | 'inference'>('detectors');
  const [detectors, setDetectors] = useState<TlsAnomalyDetectorItem[]>([]);
  const [contamination, setContamination] = useState<number>(0.05);
  const [nEstimators, NEstimators] = useState<number>(100);
  const [training, setTraining] = useState<boolean>(false);
  const [evaluatingJob, setEvaluatingJob] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  
  const [targetJobId, setTargetJobId] = useState<string>(currentJobId || '');
  const [jobSummary, setJobSummary] = useState<JobAnomalySummaryResponseItem | null>(null);

  useEffect(() => {
    if (currentJobId) {
      setTargetJobId(currentJobId);
    }
  }, [currentJobId]);

  const loadDetectors = useCallback(async () => {
    setError(null);
    const { data, error: err } = await fetchTlsAnomalyDetectors();
    if (err) {
      setError(err);
    } else if (data) {
      setDetectors(data);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      loadDetectors();
      if (currentJobId) {
        fetchJobSummary(currentJobId);
      }
    }
  }, [isOpen, loadDetectors, currentJobId]);

  const fetchJobSummary = async (jobId: string) => {
    if (!jobId.trim()) return;
    const { data } = await getJobTlsAnomalySummary(jobId);
    if (data) {
      setJobSummary(data);
    }
  };

  const handleTrain = async () => {
    setTraining(true);
    setError(null);

    try {
      // Find or generate a dataset batch
      const { data: batches } = await fetchMlDatasetBatches();
      let batchId = batches && batches.length > 0 ? batches[0].id : null;

      if (!batchId) {
        const { data: newBatch } = await generateMlDataset(100, 42);
        batchId = newBatch?.id || null;
      }

      if (!batchId) {
        setError("Failed to locate or generate dataset for training.");
        setTraining(false);
        return;
      }

      // Feature extraction
      const resExtract = await fetch('/api/v1/ml/pipeline/extract', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ batch_id: batchId, test_split_ratio: 0.2, random_seed: 42 })
      });

      if (!resExtract.ok) {
        setError("Failed to extract feature set.");
        setTraining(false);
        return;
      }

      const featureSet = await resExtract.json();

      // Train Anomaly Detector
      const { data: trained, error: trainErr } = await trainTlsAnomalyDetector(
        featureSet.id,
        contamination,
        nEstimators
      );

      if (trainErr) {
        setError(trainErr);
      } else if (trained) {
        await loadDetectors();
      }
    } catch (err: any) {
      setError(err.message || 'Anomaly detector training failed');
    } finally {
      setTraining(false);
    }
  };

  const handleEvaluateJob = async () => {
    if (!targetJobId.trim()) {
      setError("Please provide a valid Job ID for evaluation.");
      return;
    }

    setEvaluatingJob(true);
    setError(null);

    const { data, error: evalErr } = await predictJobTlsAnomalies(targetJobId.trim());
    if (evalErr) {
      setError(evalErr);
    } else if (data) {
      setJobSummary(data);
    }
    setEvaluatingJob(false);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col text-slate-100">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-purple-500/20 border border-purple-500/30 rounded-lg text-purple-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                Stage 16: TLS Anomaly Detection
                <span className="text-xs bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded font-mono">
                  Isolation Forest
                </span>
              </h2>
              <p className="text-xs text-slate-400">Unsupervised outlier detection & decision threshold calibration</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Mandatory Non-Malice Proof Disclaimer Banner */}
        <div className="bg-amber-950/40 border-y border-amber-500/30 px-6 py-2.5 flex items-center space-x-3 text-amber-200 text-xs">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
          <div>
            <span className="font-semibold text-amber-300 uppercase tracking-wide mr-1">Non-Malice Proof Guardrail:</span>
            <span>Anomalous behavior indicator only; does not constitute definitive proof of a malicious cyber attack.</span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 px-6 bg-slate-950/30">
          <button
            onClick={() => setActiveTab('detectors')}
            className={`py-3 px-4 text-sm font-medium border-b-2 transition flex items-center gap-2 ${
              activeTab === 'detectors'
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-4 h-4" />
            Detectors & Threshold Calibration
          </button>
          <button
            onClick={() => setActiveTab('inference')}
            className={`py-3 px-4 text-sm font-medium border-b-2 transition flex items-center gap-2 ${
              activeTab === 'inference'
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-4 h-4" />
            Job Anomaly Evaluation
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {error && (
            <div className="p-3 bg-red-950/60 border border-red-500/40 rounded-lg text-red-200 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {activeTab === 'detectors' && (
            <div className="space-y-6">
              {/* Training Controls */}
              <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-5 space-y-4">
                <h3 className="text-sm font-semibold text-purple-300 flex items-center gap-2">
                  <Cpu className="w-4 h-4" />
                  Train Unsupervised Isolation Forest Model
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">
                      Expected Contamination Rate: <span className="text-purple-400 font-mono">{(contamination * 100).toFixed(1)}%</span>
                    </label>
                    <input
                      type="range"
                      min="0.01"
                      max="0.20"
                      step="0.01"
                      value={contamination}
                      onChange={(e) => setContamination(parseFloat(e.target.value))}
                      className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-purple-500"
                    />
                    <p className="text-[11px] text-slate-400 mt-1">Calibrates decision threshold \(T_{'{cal}'}\) at {contamination * 100}th percentile.</p>
                  </div>

                  <div>
                    <label className="block text-slate-300 font-medium mb-1">
                      Number of Isolation Trees: <span className="text-purple-400 font-mono">{nEstimators}</span>
                    </label>
                    <input
                      type="range"
                      min="20"
                      max="300"
                      step="10"
                      value={nEstimators}
                      onChange={(e) => NEstimators(parseInt(e.target.value))}
                      className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-purple-500"
                    />
                    <p className="text-[11px] text-slate-400 mt-1">Ensemble tree capacity for anomaly isolation.</p>
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    onClick={handleTrain}
                    disabled={training}
                    className="w-full md:w-auto px-5 py-2.5 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-900/50 text-white font-medium text-xs rounded-lg transition flex items-center justify-center gap-2 shadow-lg shadow-purple-950/40"
                  >
                    {training ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        Fitting Isolation Forest & Calibrating Threshold...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current" />
                        Train Isolation Forest Anomaly Detector
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Trained Detectors List */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-slate-200">Trained Anomaly Detector Models</h3>

                {detectors.length === 0 ? (
                  <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
                    No trained Isolation Forest anomaly detectors found. Click above to train a baseline model.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-3">
                    {detectors.map((det) => (
                      <div
                        key={det.id}
                        className={`p-4 border rounded-xl transition ${
                          det.is_active
                            ? 'bg-purple-950/20 border-purple-500/50 shadow-md shadow-purple-950/30'
                            : 'bg-slate-800/30 border-slate-700/50 hover:border-slate-600'
                        }`}
                      >
                        <div className="flex items-start justify-between">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-slate-100 text-sm">{det.name}</span>
                              <span className="text-xs bg-slate-800 border border-slate-700 px-2 py-0.5 rounded font-mono text-purple-300">
                                {det.version}
                              </span>
                              {det.is_active && (
                                <span className="text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded font-medium flex items-center gap-1">
                                  <CheckCircle className="w-3 h-3" /> ACTIVE
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-slate-400 mt-1">Algorithm: <span className="font-mono text-slate-300">{det.algorithm}</span></p>
                          </div>

                          <div className="text-right">
                            <span className="text-xs text-slate-400">Calibrated Threshold \(T_{'{cal}'}\)</span>
                            <div className="text-base font-bold font-mono text-amber-400">{det.calibrated_threshold}</div>
                          </div>
                        </div>

                        <div className="mt-3 pt-3 border-t border-slate-800/80 grid grid-cols-3 gap-2 text-xs text-slate-400 font-mono">
                          <div>Contamination: <span className="text-slate-200">{(det.contamination * 100).toFixed(1)}%</span></div>
                          <div>Trees: <span className="text-slate-200">{det.n_estimators}</span></div>
                          <div>Baseline Samples: <span className="text-slate-200">{det.baseline_samples_count}</span></div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'inference' && (
            <div className="space-y-6">
              {/* Job Anomaly Trigger */}
              <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-5 space-y-3">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-purple-400" />
                  Evaluate Job Sessions Anomaly Scores
                </h3>

                <div className="flex flex-col md:flex-row items-center gap-3">
                  <div className="w-full flex-1">
                    <input
                      type="text"
                      placeholder="Enter Analysis Job ID (e.g. job-abc-123)..."
                      value={targetJobId}
                      onChange={(e) => setTargetJobId(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
                    />
                  </div>
                  <button
                    onClick={handleEvaluateJob}
                    disabled={evaluatingJob || !targetJobId.trim()}
                    className="w-full md:w-auto px-5 py-2 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-900/50 text-white font-medium text-xs rounded-lg transition flex items-center justify-center gap-2"
                  >
                    {evaluatingJob ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        Evaluating...
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 fill-current" />
                        Run Anomaly Evaluation
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Job Summary Results */}
              {jobSummary ? (
                <div className="space-y-4">
                  {/* Summary Metric Cards */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl">
                      <span className="text-xs text-slate-400 font-medium">Evaluated Sessions</span>
                      <div className="text-xl font-bold font-mono text-slate-100 mt-1">
                        {jobSummary.total_sessions_evaluated}
                      </div>
                    </div>

                    <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl">
                      <span className="text-xs text-slate-400 font-medium">Anomalous Sessions</span>
                      <div className={`text-xl font-bold font-mono mt-1 ${
                        jobSummary.anomalous_sessions_count > 0 ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {jobSummary.anomalous_sessions_count}
                      </div>
                    </div>

                    <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl">
                      <span className="text-xs text-slate-400 font-medium">Anomaly Rate</span>
                      <div className="text-xl font-bold font-mono text-purple-400 mt-1">
                        {jobSummary.anomaly_rate_percent}%
                      </div>
                    </div>

                    <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl">
                      <span className="text-xs text-slate-400 font-medium">Calibrated Threshold \(T_{'{cal}'}\)</span>
                      <div className="text-xl font-bold font-mono text-amber-300 mt-1">
                        {jobSummary.calibrated_threshold}
                      </div>
                    </div>
                  </div>

                  {/* Results Table */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                    <div className="px-4 py-3 bg-slate-950/60 border-b border-slate-800 flex items-center justify-between text-xs font-semibold text-slate-300">
                      <span>Evaluated Session Anomaly Results</span>
                      <span className="font-mono text-slate-400">Model: {jobSummary.model_version}</span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-xs text-left text-slate-300">
                        <thead className="bg-slate-800/40 text-slate-400 font-mono border-b border-slate-800">
                          <tr>
                            <th className="py-2.5 px-4">TCP Stream</th>
                            <th className="py-2.5 px-4">Raw Score</th>
                            <th className="py-2.5 px-4">Threshold \(T_{'{cal}'}\)</th>
                            <th className="py-2.5 px-4">Anomaly Status</th>
                            <th className="py-2.5 px-4">Latency</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          {jobSummary.results.map((res) => (
                            <tr key={res.id} className="hover:bg-slate-800/30">
                              <td className="py-2.5 px-4 text-purple-300 font-bold">
                                Stream #{res.tcp_stream !== null ? res.tcp_stream : 'N/A'}
                              </td>
                              <td className="py-2.5 px-4 font-bold text-slate-100">
                                {res.raw_anomaly_score}
                              </td>
                              <td className="py-2.5 px-4 text-slate-400">
                                {res.calibrated_threshold}
                              </td>
                              <td className="py-2.5 px-4">
                                {res.is_anomalous ? (
                                  <span className="bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded font-sans font-medium flex items-center gap-1 inline-flex">
                                    <AlertTriangle className="w-3 h-3 text-amber-400" />
                                    ANOMALOUS_BEHAVIOR
                                  </span>
                                ) : (
                                  <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded font-sans font-medium flex items-center gap-1 inline-flex">
                                    <CheckCircle className="w-3 h-3 text-emerald-400" />
                                    NORMAL_BEHAVIOR
                                  </span>
                                )}
                              </td>
                              <td className="py-2.5 px-4 text-slate-400">
                                {res.execution_time_ms} ms
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
                  Provide a Job ID above and click "Run Anomaly Evaluation" to inspect session anomaly scores.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-800 flex justify-end bg-slate-950/60">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs rounded-lg transition"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
