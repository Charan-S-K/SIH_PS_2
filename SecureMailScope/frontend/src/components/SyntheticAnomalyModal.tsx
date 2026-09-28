import React, { useState, useEffect, useCallback } from 'react';
import {
  Zap,
  X,
  Sliders,
  BarChart,
  AlertTriangle,
  Play
} from 'lucide-react';
import {
  injectSyntheticAnomalies,
  fetchSyntheticInjections,
  evaluateSyntheticInjection,
  fetchMlDatasetBatches,
  generateMlDataset,
  trainTlsAnomalyDetector,
  fetchTlsAnomalyDetectors,
  SyntheticAnomalyBatchItem,
  SyntheticAnomalyEvaluationResponseItem
} from '../services/api';

interface SyntheticAnomalyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const PROFILES = [
  { id: 'DEPRECATED_TLS_SPIKE', name: 'Deprecated TLS Spike', desc: 'Sudden influx of SSL 3.0 / TLS 1.0 connections' },
  { id: 'EXPIRED_CERT_SURGE', name: 'Expired Cert Surge', desc: 'Surge in invalid / expired X.509 certificates' },
  { id: 'UNENCRYPTED_AUTH_BURST', name: 'Unencrypted Auth Burst', desc: 'Burst of plaintext SMTP PLAIN/LOGIN credentials' },
  { id: 'KEY_STRENGTH_DEGRADATION', name: 'Key Strength Degradation', desc: 'Drop in RSA/DH key exchange bits to sub-1024' },
  { id: 'MALFORMED_PACKET_STORM', name: 'Malformed Packet Storm', desc: 'Extreme packet volume & payload duration outliers' },
  { id: 'COMBINED_MUTATION_SURGE', name: 'Combined Mutation Surge', desc: 'Multi-vector cryptographic anomaly mutations' },
];

export const SyntheticAnomalyModal: React.FC<SyntheticAnomalyModalProps> = ({ isOpen, onClose }) => {
  const [injections, setInjections] = useState<SyntheticAnomalyBatchItem[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<string>('DEPRECATED_TLS_SPIKE');
  const [injectionRate, setInjectionRate] = useState<number>(0.15);
  const [seed, setSeed] = useState<number>(42);
  const [injecting, setInjecting] = useState<boolean>(false);
  const [evaluating, setEvaluating] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [evalResult, setEvalResult] = useState<SyntheticAnomalyEvaluationResponseItem | null>(null);

  const loadInjections = useCallback(async () => {
    setError(null);
    const { data, error: err } = await fetchSyntheticInjections();
    if (err) {
      setError(err);
    } else if (data) {
      setInjections(data);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      loadInjections();
    }
  }, [isOpen, loadInjections]);

  const handleInject = async () => {
    setInjecting(true);
    setError(null);

    try {
      // Find or generate a dataset batch
      const { data: batches } = await fetchMlDatasetBatches();
      let batchId = batches && batches.length > 0 ? batches[0].id : null;

      if (!batchId) {
        const { data: newBatch } = await generateMlDataset(100, seed);
        batchId = newBatch?.id || null;
      }

      if (!batchId) {
        setError("Failed to locate or generate a baseline dataset batch.");
        setInjecting(false);
        return;
      }

      // Feature extraction (Stage 14)
      const resExtract = await fetch('/api/v1/ml/pipeline/extract', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ batch_id: batchId, test_split_ratio: 0.2, random_seed: seed })
      });

      if (!resExtract.ok) {
        setError("Failed to extract baseline feature set.");
        setInjecting(false);
        return;
      }

      const featureSet = await resExtract.json();

      // Ensure an active Anomaly Detector exists
      const { data: detectors } = await fetchTlsAnomalyDetectors();
      if (!detectors || detectors.length === 0) {
        await trainTlsAnomalyDetector(featureSet.id, 0.05, 50);
      }

      // Inject synthetic profile
      const { data: injectedBatch, error: injErr } = await injectSyntheticAnomalies(
        featureSet.id,
        selectedProfile,
        injectionRate,
        seed
      );

      if (injErr) {
        setError(injErr);
      } else if (injectedBatch) {
        await loadInjections();
        // Auto trigger evaluation
        await handleEvaluate(injectedBatch.id);
      }
    } catch (err: any) {
      setError(err.message || 'Synthetic anomaly injection failed');
    } finally {
      setInjecting(false);
    }
  };

  const handleEvaluate = async (injectionBatchId: string) => {
    setEvaluating(injectionBatchId);
    setError(null);

    const { data, error: evalErr } = await evaluateSyntheticInjection(injectionBatchId);
    if (evalErr) {
      setError(evalErr);
    } else if (data) {
      setEvalResult(data);
    }
    setEvaluating(null);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col text-slate-100">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-pink-500/20 border border-pink-500/30 rounded-lg text-pink-400">
              <Zap className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                Stage 17: Synthetic Anomaly Injection & Evaluation
                <span className="text-xs bg-pink-500/20 text-pink-300 border border-pink-500/30 px-2 py-0.5 rounded font-mono">
                  Ground Truth Benchmark
                </span>
              </h2>
              <p className="text-xs text-slate-400">Controlled anomaly profile injection & detector validation</p>
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

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {error && (
            <div className="p-3 bg-red-950/60 border border-red-500/40 rounded-lg text-red-200 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Injection Controls */}
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-pink-300 flex items-center gap-2">
              <Sliders className="w-4 h-4" />
              Configure Synthetic Anomaly Profile Injection
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Target Anomaly Profile</label>
                <select
                  value={selectedProfile}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-pink-500 font-mono"
                >
                  {PROFILES.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.id})
                    </option>
                  ))}
                </select>
                <p className="text-[11px] text-slate-400 mt-1">
                  {PROFILES.find((p) => p.id === selectedProfile)?.desc}
                </p>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="block text-slate-300 font-medium">
                    Injection Rate: <span className="text-pink-400 font-mono">{(injectionRate * 100).toFixed(0)}%</span>
                  </label>
                  <div className="flex items-center gap-1 text-[11px] text-slate-400">
                    <span>Random Seed:</span>
                    <input
                      type="number"
                      value={seed}
                      onChange={(e) => setSeed(parseInt(e.target.value) || 42)}
                      className="w-14 px-1.5 py-0.5 bg-slate-900 border border-slate-700 rounded text-pink-300 font-mono text-[11px]"
                    />
                  </div>
                </div>
                <input
                  type="range"
                  min="0.05"
                  max="0.50"
                  step="0.05"
                  value={injectionRate}
                  onChange={(e) => setInjectionRate(parseFloat(e.target.value))}
                  className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-pink-500"
                />
                <div className="text-[11px] text-slate-400 mt-1">
                  <span>Proportion of baseline dataset samples mutated into anomalies</span>
                </div>
              </div>
            </div>

            <div className="pt-2">
              <button
                onClick={handleInject}
                disabled={injecting}
                className="w-full md:w-auto px-5 py-2.5 bg-pink-600 hover:bg-pink-500 disabled:bg-pink-900/50 text-white font-medium text-xs rounded-lg transition flex items-center justify-center gap-2 shadow-lg shadow-pink-950/40"
              >
                {injecting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Injecting Synthetic Profile & Mutating Feature Matrix...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 fill-current" />
                    Inject Synthetic Anomaly Profile
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Evaluation Performance Card */}
          {evalResult && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xl">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <BarChart className="w-4 h-4 text-emerald-400" />
                  Isolation Forest Detection Performance Evaluation
                </h3>
                <span className="text-xs bg-slate-800 border border-slate-700 text-purple-300 font-mono px-2 py-0.5 rounded">
                  Model: {evalResult.detector_version}
                </span>
              </div>

              {/* Metric Cards Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl text-center">
                  <span className="text-xs text-slate-400 font-medium">Precision</span>
                  <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                    {(evalResult.precision * 100).toFixed(1)}%
                  </div>
                  <span className="text-[10px] text-slate-500">\(TP / (TP + FP)\)</span>
                </div>

                <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl text-center">
                  <span className="text-xs text-slate-400 font-medium">Recall (Detection Rate)</span>
                  <div className="text-2xl font-bold font-mono text-blue-400 mt-1">
                    {(evalResult.recall * 100).toFixed(1)}%
                  </div>
                  <span className="text-[10px] text-slate-500">\(TP / (TP + FN)\)</span>
                </div>

                <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl text-center">
                  <span className="text-xs text-slate-400 font-medium">F1 Score</span>
                  <div className="text-2xl font-bold font-mono text-purple-400 mt-1">
                    {(evalResult.f1_score * 100).toFixed(1)}%
                  </div>
                  <span className="text-[10px] text-slate-500">Harmonic Mean</span>
                </div>

                <div className="bg-slate-800/50 border border-slate-700/60 p-4 rounded-xl text-center">
                  <span className="text-xs text-slate-400 font-medium">False Positive Rate</span>
                  <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
                    {(evalResult.false_positive_rate * 100).toFixed(1)}%
                  </div>
                  <span className="text-[10px] text-slate-500">\(FP / (FP + TN)\)</span>
                </div>
              </div>

              {/* Confusion Matrix Table */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 font-mono text-xs">
                <span className="text-slate-400 font-sans font-semibold text-xs mb-2 block">Detection Confusion Matrix Breakdown</span>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                  <div className="p-2 bg-emerald-950/40 border border-emerald-500/30 rounded">
                    <span className="text-slate-400 text-[10px]">True Positives (TP)</span>
                    <div className="text-base font-bold text-emerald-300">{evalResult.true_positives}</div>
                  </div>
                  <div className="p-2 bg-amber-950/40 border border-amber-500/30 rounded">
                    <span className="text-slate-400 text-[10px]">False Positives (FP)</span>
                    <div className="text-base font-bold text-amber-300">{evalResult.false_positives}</div>
                  </div>
                  <div className="p-2 bg-blue-950/40 border border-blue-500/30 rounded">
                    <span className="text-slate-400 text-[10px]">True Negatives (TN)</span>
                    <div className="text-base font-bold text-blue-300">{evalResult.true_negatives}</div>
                  </div>
                  <div className="p-2 bg-red-950/40 border border-red-500/30 rounded">
                    <span className="text-slate-400 text-[10px]">False Negatives (FN)</span>
                    <div className="text-base font-bold text-red-300">{evalResult.false_negatives}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Injected Batches List */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-slate-200">Synthetic Anomaly Injection Batches</h3>

            {injections.length === 0 ? (
              <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
                No synthetic anomaly injection batches found. Click above to inject a profile.
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-3">
                {injections.map((inj) => (
                  <div
                    key={inj.id}
                    className="p-4 bg-slate-800/30 border border-slate-700/50 hover:border-slate-600 rounded-xl transition flex items-center justify-between"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-100 text-sm">{inj.name}</span>
                        <span className="text-xs bg-pink-950/40 text-pink-300 border border-pink-500/30 px-2 py-0.5 rounded font-mono">
                          {inj.anomaly_profile}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-slate-400 mt-1 font-mono">
                        <span>Total Samples: <strong className="text-slate-200">{inj.total_samples_count}</strong></span>
                        <span>Injected Anomalies: <strong className="text-pink-400">{inj.injected_samples_count}</strong></span>
                        <span>Rate: <strong className="text-slate-200">{(inj.injection_rate * 100).toFixed(0)}%</strong></span>
                      </div>
                    </div>

                    <button
                      onClick={() => handleEvaluate(inj.id)}
                      disabled={evaluating === inj.id}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-xs text-slate-200 font-medium rounded-lg transition flex items-center gap-1.5"
                    >
                      {evaluating === inj.id ? (
                        <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      ) : (
                        <Play className="w-3.5 h-3.5 text-emerald-400 fill-current" />
                      )}
                      Evaluate Detector
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
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
