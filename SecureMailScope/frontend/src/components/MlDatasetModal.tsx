import React, { useState, useEffect, useCallback } from 'react';
import {
  Database,
  RefreshCw,
  X,
  Layers,
  FileSpreadsheet
} from 'lucide-react';
import {
  generateMlDataset,
  fetchMlDatasetBatches,
  fetchMlDatasetBatchDetails,
  getMlDatasetCsvExportUrl,
  MlDatasetBatchItem,
  MlDatasetRecordItem
} from '../services/api';

interface MlDatasetModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const MlDatasetModal: React.FC<MlDatasetModalProps> = ({ isOpen, onClose }) => {
  const [batches, setBatches] = useState<MlDatasetBatchItem[]>([]);
  const [selectedBatch, setSelectedBatch] = useState<MlDatasetBatchItem | null>(null);
  const [sampleCount, setSampleCount] = useState<number>(100);
  const [seed, setSeed] = useState<number>(42);
  const [generating, setGenerating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<MlDatasetRecordItem | null>(null);

  const loadBatches = useCallback(async () => {
    setError(null);
    const { data, error: err } = await fetchMlDatasetBatches();
    if (err) {
      setError(err);
    } else if (data) {
      setBatches(data);
      if (data.length > 0) {
        loadBatchDetails(data[0].id);
      }
    }
  }, []);

  const loadBatchDetails = async (batchId: string) => {
    const { data } = await fetchMlDatasetBatchDetails(batchId);
    if (data) {
      setSelectedBatch(data);
      if (data.records && data.records.length > 0) {
        setSelectedRecord(data.records[0]);
      }
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadBatches();
    }
  }, [isOpen, loadBatches]);

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    const { data, error: err } = await generateMlDataset(sampleCount, seed);
    if (err) {
      setError(err);
    } else if (data) {
      await loadBatches();
      await loadBatchDetails(data.id);
    }
    setGenerating(false);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl text-slate-100 overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">ML Dataset Generator (Stage 13)</h2>
              <p className="text-xs text-slate-400">Reproducible synthetic dataset generation & feature mapping for security risk ML</p>
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

          {/* Generator Controls */}
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Sample Count</label>
                <input
                  type="number"
                  min={10}
                  max={5000}
                  value={sampleCount}
                  onChange={(e) => setSampleCount(parseInt(e.target.value) || 100)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 w-32"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Random Seed</label>
                <input
                  type="number"
                  value={seed}
                  onChange={(e) => setSeed(parseInt(e.target.value) || 42)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 w-28"
                />
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={handleGenerate}
                disabled={generating}
                className="flex items-center space-x-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-lg transition shadow-md shadow-indigo-600/20"
              >
                <RefreshCw className={`w-4 h-4 ${generating ? 'animate-spin' : ''}`} />
                <span>{generating ? 'Generating...' : 'Generate New Dataset Batch'}</span>
              </button>
            </div>
          </div>

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          {/* Batch Selector & Summary Cards */}
          {selectedBatch && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Active Batch:</span>
                  <select
                    value={selectedBatch.id}
                    onChange={(e) => loadBatchDetails(e.target.value)}
                    className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-indigo-300 font-medium focus:outline-none"
                  >
                    {batches.map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.name} ({b.sample_count} samples, Seed: {b.seed})
                      </option>
                    ))}
                  </select>
                </div>

                <a
                  href={getMlDatasetCsvExportUrl(selectedBatch.id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center space-x-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 px-3 py-1.5 rounded-lg transition"
                >
                  <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
                  <span>Export CSV</span>
                </a>
              </div>

              {/* Label Distribution Cards */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg p-3 text-center">
                  <div className="text-xs text-emerald-400 font-medium">SECURE</div>
                  <div className="text-xl font-bold text-slate-100">{selectedBatch.secure_samples_count}</div>
                  <div className="text-[10px] text-slate-500">Label Code: 0</div>
                </div>

                <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg p-3 text-center">
                  <div className="text-xs text-amber-400 font-medium">WEAK_CRYPTO</div>
                  <div className="text-xl font-bold text-slate-100">{selectedBatch.weak_crypto_count}</div>
                  <div className="text-[10px] text-slate-500">Label Code: 1</div>
                </div>

                <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg p-3 text-center">
                  <div className="text-xs text-rose-400 font-medium">PLAINTEXT_LEAK</div>
                  <div className="text-xl font-bold text-slate-100">{selectedBatch.plaintext_leak_count}</div>
                  <div className="text-[10px] text-slate-500">Label Code: 2</div>
                </div>

                <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg p-3 text-center">
                  <div className="text-xs text-red-400 font-medium">DOWNGRADE_ATTACK</div>
                  <div className="text-xl font-bold text-slate-100">{selectedBatch.downgrade_attack_count}</div>
                  <div className="text-[10px] text-slate-500">Label Code: 3</div>
                </div>

                <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg p-3 text-center">
                  <div className="text-xs text-purple-400 font-medium">ANOMALOUS</div>
                  <div className="text-xl font-bold text-slate-100">{selectedBatch.anomalous_count}</div>
                  <div className="text-[10px] text-slate-500">Label Code: 4</div>
                </div>
              </div>
            </div>
          )}

          {/* Records Table */}
          {selectedBatch?.records && (
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-slate-300">Synthetic Session Records ({selectedBatch.records.length})</h3>
              <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950/40">
                <div className="max-h-64 overflow-y-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0">
                      <tr>
                        <th className="py-2.5 px-3 font-medium">#</th>
                        <th className="py-2.5 px-3 font-medium">Scenario Template</th>
                        <th className="py-2.5 px-3 font-medium">Protocol</th>
                        <th className="py-2.5 px-3 font-medium">TLS Version</th>
                        <th className="py-2.5 px-3 font-medium">Cipher Suite</th>
                        <th className="py-2.5 px-3 font-medium">Ground Truth Label</th>
                        <th className="py-2.5 px-3 font-medium">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {selectedBatch.records.map((r) => (
                        <tr
                          key={r.id}
                          className={`hover:bg-slate-800/40 cursor-pointer transition ${
                            selectedRecord?.id === r.id ? 'bg-indigo-500/10 border-l-2 border-indigo-500' : ''
                          }`}
                          onClick={() => setSelectedRecord(r)}
                        >
                          <td className="py-2 px-3 font-mono text-slate-400">{r.sample_index}</td>
                          <td className="py-2 px-3 font-mono text-indigo-300">{r.scenario_name}</td>
                          <td className="py-2 px-3">{r.protocol}</td>
                          <td className="py-2 px-3 font-mono">{r.tls_version || 'None'}</td>
                          <td className="py-2 px-3 font-mono text-[11px] truncate max-w-xs">{r.cipher_suite || 'None'}</td>
                          <td className="py-2 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                                r.ground_truth_label === 'SECURE'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : r.ground_truth_label === 'WEAK_CRYPTO'
                                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                  : r.ground_truth_label === 'PLAINTEXT_LEAK'
                                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                  : r.ground_truth_label === 'DOWNGRADE_ATTACK'
                                  ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                                  : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                              }`}
                            >
                              {r.ground_truth_label} ({r.label_code})
                            </span>
                          </td>
                          <td className="py-2 px-3">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedRecord(r);
                              }}
                              className="text-xs text-indigo-400 hover:text-indigo-300 underline"
                            >
                              Inspect Features
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* Selected Record Feature Vector & Rationale */}
          {selectedRecord && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-indigo-400" />
                  <h4 className="text-sm font-semibold text-slate-200">
                    Sample #{selectedRecord.sample_index}: {selectedRecord.scenario_name}
                  </h4>
                </div>
                <span className="text-xs font-mono text-slate-400">ID: {selectedRecord.id.substring(0, 8)}...</span>
              </div>

              {/* Rationale Banner */}
              <div className="p-3 bg-indigo-950/30 border border-indigo-500/20 rounded-lg text-xs text-indigo-200">
                <span className="font-semibold text-indigo-300">Ground Truth Rationale: </span>
                {selectedRecord.label_rationale}
              </div>

              {/* Extracted Feature JSON Grid */}
              <div>
                <h5 className="text-xs font-semibold text-slate-400 mb-2">Standardized ML Feature Vector (`features_json`)</h5>
                <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto">
                  {JSON.stringify(selectedRecord.features_json, null, 2)}
                </pre>
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
