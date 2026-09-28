import React, { useState, useEffect, useCallback } from 'react';
import {
  Brain,
  X,
  Layers,
  Cpu,
  BarChart2,
  CheckCircle,
  Play
} from 'lucide-react';
import {
  trainMlRiskClassifier,
  fetchMlModels,
  predictMlRisk,
  fetchMlDatasetBatches,
  generateMlDataset,
  MlTrainedModelItem,
  MlPredictionResponseItem
} from '../services/api';

interface MlRiskClassifierModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const CLASS_LABELS = ['SECURE (0)', 'WEAK_CRYPTO (1)', 'PLAINTEXT_LEAK (2)', 'DOWNGRADE_ATTACK (3)', 'ANOMALOUS (4)'];

export const MlRiskClassifierModal: React.FC<MlRiskClassifierModalProps> = ({ isOpen, onClose }) => {
  const [models, setModels] = useState<MlTrainedModelItem[]>([]);
  const [selectedModel, setSelectedModel] = useState<MlTrainedModelItem | null>(null);
  const [nEstimators, setNEstimators] = useState<number>(100);
  const [maxDepth, setMaxDepth] = useState<number>(12);
  const [training, setTraining] = useState<boolean>(false);
  const [testingInference, setTestingInference] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [prediction, setPrediction] = useState<MlPredictionResponseItem | null>(null);

  // Test input feature vector state
  const [testFeatures, setTestFeatures] = useState({
    protocol_code: 1,
    tls_version_code: 0,
    cipher_strength_bits: 0,
    is_starttls_used: 0,
    is_auth_encrypted: 0,
    cert_validity_code: 0,
    packet_count: 15,
    duration_seconds: 1.2,
    total_bytes: 1500,
    avg_packet_size: 100.0
  });

  const loadModels = useCallback(async () => {
    setError(null);
    const { data, error: err } = await fetchMlModels();
    if (err) {
      setError(err);
    } else if (data) {
      setModels(data);
      if (data.length > 0) {
        setSelectedModel(data[0]);
      }
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      loadModels();
    }
  }, [isOpen, loadModels]);

  const handleTrain = async () => {
    setTraining(true);
    setError(null);
    
    // Auto-generate or fetch dataset/features if needed
    const { data: batches } = await fetchMlDatasetBatches();
    let batchId = batches && batches.length > 0 ? batches[0].id : null;
    
    if (!batchId) {
      const { data: newBatch } = await generateMlDataset(100, 42);
      batchId = newBatch?.id || null;
    }

    if (!batchId) {
      setError("Failed to locate or generate a synthetic dataset batch for training");
      setTraining(false);
      return;
    }

    // Trigger Stage 14 feature extraction first
    const resExtract = await fetch('/api/v1/ml/pipeline/extract', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ batch_id: batchId, pipeline_version: 'v1.0.0', test_split_ratio: 0.2, random_seed: 42 })
    });

    if (!resExtract.ok) {
      setError("Failed to extract feature set for training");
      setTraining(false);
      return;
    }

    const featureSetData = await resExtract.json();
    const featureSetId = featureSetData.id;

    // Train Stage 15 Random Forest model
    const { data: newModel, error: errTrain } = await trainMlRiskClassifier(featureSetId, nEstimators, maxDepth);
    if (errTrain) {
      setError(errTrain);
    } else if (newModel) {
      await loadModels();
      setSelectedModel(newModel);
    }
    setTraining(false);
  };

  const handlePredict = async () => {
    setTestingInference(true);
    setError(null);
    const { data, error: err } = await predictMlRisk(testFeatures, selectedModel?.version);
    if (err) {
      setError(err);
    } else if (data) {
      setPrediction(data);
    }
    setTestingInference(false);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl text-slate-100 overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-purple-500/10 border border-purple-500/20 rounded-lg text-purple-400">
              <Brain className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">ML Risk Classifier (Stage 15)</h2>
              <p className="text-xs text-slate-400">Explainable Random Forest Classifier & Metrics Evaluation (Precision, Recall, F1, Confusion Matrix)</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">

          {/* Controls Bar */}
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Trees (n_estimators)</label>
                <input
                  type="number"
                  min={10}
                  max={500}
                  value={nEstimators}
                  onChange={(e) => setNEstimators(parseInt(e.target.value) || 100)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-purple-500 w-32"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Max Depth</label>
                <input
                  type="number"
                  min={2}
                  max={50}
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(parseInt(e.target.value) || 12)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-purple-500 w-28"
                />
              </div>
            </div>

            <button
              onClick={handleTrain}
              disabled={training}
              className="flex items-center space-x-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-lg transition shadow-md shadow-purple-600/20"
            >
              <Cpu className={`w-4 h-4 ${training ? 'animate-spin' : ''}`} />
              <span>{training ? 'Training Model...' : 'Train Random Forest Model'}</span>
            </button>
          </div>

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          {/* Model Selector & Evaluation Dashboard */}
          {selectedModel && (
            <div className="space-y-6">
              <div className="flex items-center space-x-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Model Version:</span>
                <select
                  value={selectedModel.id}
                  onChange={(e) => {
                    const m = models.find((mod) => mod.id === e.target.value);
                    if (m) setSelectedModel(m);
                  }}
                  className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-purple-300 font-medium focus:outline-none"
                >
                  {models.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name} ({m.version} - F1: {(m.f1_macro * 100).toFixed(1)}%)
                    </option>
                  ))}
                </select>
              </div>

              {/* Metric Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-4 text-center">
                  <div className="text-xs text-slate-400 font-medium mb-1">Accuracy</div>
                  <div className="text-2xl font-bold text-emerald-400">{(selectedModel.accuracy * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-4 text-center">
                  <div className="text-xs text-slate-400 font-medium mb-1">Precision (Macro)</div>
                  <div className="text-2xl font-bold text-indigo-400">{(selectedModel.precision_macro * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-4 text-center">
                  <div className="text-xs text-slate-400 font-medium mb-1">Recall (Macro)</div>
                  <div className="text-2xl font-bold text-cyan-400">{(selectedModel.recall_macro * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-4 text-center">
                  <div className="text-xs text-slate-400 font-medium mb-1">F1-Score (Macro)</div>
                  <div className="text-2xl font-bold text-purple-400">{(selectedModel.f1_macro * 100).toFixed(1)}%</div>
                </div>
              </div>

              {/* Confusion Matrix & Feature Importances Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* 5x5 Confusion Matrix */}
                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                    <BarChart2 className="w-4 h-4 text-purple-400" />
                    <span>5x5 Confusion Matrix</span>
                  </h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-center text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="p-2 text-left">Actual \ Pred</th>
                          {CLASS_LABELS.map((_lbl, idx) => (
                            <th key={idx} className="p-2 text-[10px] font-mono">{idx}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {selectedModel.confusion_matrix.map((row, rIdx) => (
                          <tr key={rIdx} className="hover:bg-slate-800/30">
                            <td className="p-2 text-left font-mono text-[10px] text-slate-400">{rIdx}</td>
                            {row.map((val, cIdx) => (
                              <td
                                key={cIdx}
                                className={`p-2 font-mono font-semibold ${
                                  rIdx === cIdx
                                    ? val > 0 ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-500'
                                    : val > 0 ? 'bg-red-500/20 text-red-300' : 'text-slate-600'
                                }`}
                              >
                                {val}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Feature Importances */}
                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                    <Layers className="w-4 h-4 text-indigo-400" />
                    <span>Random Forest Feature Importances</span>
                  </h4>
                  <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                    {Object.entries(selectedModel.feature_importances)
                      .sort(([, a], [, b]) => b - a)
                      .map(([feat, score]) => (
                        <div key={feat} className="space-y-1">
                          <div className="flex justify-between text-xs font-mono">
                            <span className="text-slate-300">{feat}</span>
                            <span className="text-indigo-400 font-semibold">{(score * 100).toFixed(1)}%</span>
                          </div>
                          <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className="bg-indigo-500 h-1.5 rounded-full"
                              style={{ width: `${Math.max(2, score * 100)}%` }}
                            ></div>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>

              </div>

              {/* Inference Tester Section */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <Play className="w-4 h-4 text-emerald-400" />
                    <h4 className="text-sm font-semibold text-slate-200">Live Model Inference Tester</h4>
                  </div>
                  <button
                    onClick={handlePredict}
                    disabled={testingInference}
                    className="flex items-center space-x-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition"
                  >
                    <Play className={`w-3.5 h-3.5 ${testingInference ? 'animate-spin' : ''}`} />
                    <span>Run Inference</span>
                  </button>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">Protocol Code</label>
                    <select
                      value={testFeatures.protocol_code}
                      onChange={(e) => setTestFeatures({ ...testFeatures, protocol_code: parseInt(e.target.value) })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200"
                    >
                      <option value={1}>1 (SMTP)</option>
                      <option value={2}>2 (SMTPS)</option>
                      <option value={3}>3 (IMAP)</option>
                      <option value={4}>4 (IMAPS)</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">TLS Version Code</label>
                    <select
                      value={testFeatures.tls_version_code}
                      onChange={(e) => setTestFeatures({ ...testFeatures, tls_version_code: parseInt(e.target.value) })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200"
                    >
                      <option value={0}>0 (None)</option>
                      <option value={2}>2 (TLS 1.0)</option>
                      <option value={4}>4 (TLS 1.2)</option>
                      <option value={5}>5 (TLS 1.3)</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">STARTTLS Used</label>
                    <select
                      value={testFeatures.is_starttls_used}
                      onChange={(e) => setTestFeatures({ ...testFeatures, is_starttls_used: parseInt(e.target.value) })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200"
                    >
                      <option value={0}>0 (No)</option>
                      <option value={1}>1 (Yes)</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Auth Encrypted</label>
                    <select
                      value={testFeatures.is_auth_encrypted}
                      onChange={(e) => setTestFeatures({ ...testFeatures, is_auth_encrypted: parseInt(e.target.value) })}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200"
                    >
                      <option value={0}>0 (No - Cleartext)</option>
                      <option value={1}>1 (Yes - Encrypted)</option>
                    </select>
                  </div>
                </div>

                {/* Inference Result Box */}
                {prediction && (
                  <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-4 h-4 text-emerald-400" />
                        <span className="text-xs font-semibold text-slate-300">Predicted Class:</span>
                        <span className="text-sm font-bold text-purple-300 font-mono">
                          {prediction.predicted_label} ({prediction.predicted_class_code})
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-400">
                        Latency: {prediction.inference_time_ms} ms
                      </span>
                    </div>

                    {/* Class Probabilities Bar */}
                    <div className="space-y-1.5">
                      <div className="text-[11px] text-slate-400 font-medium">Confidence Probabilities:</div>
                      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-[11px] font-mono">
                        {Object.entries(prediction.confidence_probabilities).map(([lbl, p]) => (
                          <div key={lbl} className="bg-slate-950 p-2 rounded border border-slate-800 text-center">
                            <div className="text-[10px] text-slate-400 truncate">{lbl}</div>
                            <div className="font-bold text-indigo-300">{(p * 100).toFixed(1)}%</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="text-[11px] text-emerald-400/80 font-mono">
                      Guaranteed Rule Fact Non-Override: `is_deterministic_fact_overridden: {String(prediction.is_deterministic_fact_overridden)}`
                    </div>
                  </div>
                )}
              </div>

            </div>
          )}

        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/50 flex justify-end">
          <button
            onClick={onClose}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium px-4 py-2 rounded-lg transition"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
