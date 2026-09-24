import React, { useState, useEffect } from 'react';
import { X, Layers, Filter, ChevronLeft, ChevronRight, Activity } from 'lucide-react';
import { AnalysisJob, PacketItem, CaptureSummary, fetchJobPackets, fetchJobSummary } from '../services/api';

interface PacketsModalProps {
  job: AnalysisJob;
  onClose: () => void;
  initialStreamId?: number;
}

export const PacketsModal: React.FC<PacketsModalProps> = ({ job, onClose, initialStreamId }) => {
  const [packets, setPackets] = useState<PacketItem[]>([]);
  const [summary, setSummary] = useState<CaptureSummary | null>(null);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(0);
  const [protocolFilter, setProtocolFilter] = useState<string>('');
  const [streamFilter, setStreamFilter] = useState<string>(initialStreamId !== undefined ? String(initialStreamId) : '');
  const [loading, setLoading] = useState<boolean>(true);
  const limit = 25;

  const loadData = async () => {
    setLoading(true);
    const streamNum = streamFilter !== '' ? parseInt(streamFilter, 10) : undefined;
    const [packetsRes, summaryRes] = await Promise.all([
      fetchJobPackets(job.id, limit, page * limit, protocolFilter || undefined, undefined, isNaN(streamNum as number) ? undefined : streamNum),
      fetchJobSummary(job.id),
    ]);

    if (packetsRes.data) {
      setPackets(packetsRes.data.packets);
      setTotal(packetsRes.data.total);
    }
    if (summaryRes.data) {
      setSummary(summaryRes.data);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, [job.id, page, protocolFilter, streamFilter]);


  const getProtocolBadge = (proto: string) => {
    if (proto.startsWith('SMTP')) {
      return <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-semibold">SMTP</span>;
    }
    if (proto.startsWith('TLS')) {
      return <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-semibold">{proto}</span>;
    }
    if (proto.startsWith('IMAP')) {
      return <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px] font-semibold">IMAP</span>;
    }
    if (proto.startsWith('POP3')) {
      return <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-semibold">POP3</span>;
    }
    if (proto.startsWith('DNS')) {
      return <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-semibold">DNS</span>;
    }
    return <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px] font-semibold">{proto}</span>;
  };

  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#111827] border border-slate-800 rounded-2xl w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-blue-950 text-blue-400 border border-blue-800/40">
              <Layers className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center space-x-2">
                <span>Packet Frame Inspection</span>
                <span className="text-xs font-mono font-normal text-slate-400">({job.pcap_file?.original_filename})</span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">Job UUID: {job.id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Capture Summary Banner */}
        {summary && (
          <div className="px-6 py-3 bg-slate-950/60 border-b border-slate-800 text-xs grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono">
            <div>
              <span className="text-slate-500">Total Frames:</span>{' '}
              <span className="text-slate-200 font-semibold">{summary.total_packets}</span>
            </div>
            <div>
              <span className="text-slate-500">TCP Frames:</span>{' '}
              <span className="text-blue-400 font-semibold">{summary.tcp_packets}</span>
            </div>
            <div>
              <span className="text-slate-500">UDP Frames:</span>{' '}
              <span className="text-amber-400 font-semibold">{summary.udp_packets}</span>
            </div>
            <div>
              <span className="text-slate-500">Duration:</span>{' '}
              <span className="text-slate-200 font-semibold">{summary.duration_seconds.toFixed(2)}s</span>
            </div>
            <div>
              <span className="text-slate-500">Conversations:</span>{' '}
              <span className="text-emerald-400 font-semibold">{summary.distinct_conversations}</span>
            </div>
          </div>
        )}

        {/* Filter Toolbar */}
        <div className="px-6 py-2.5 bg-slate-900/40 border-b border-slate-800/80 flex items-center justify-between gap-4">
          <div className="flex items-center space-x-1.5 text-xs">
            <Filter className="h-3.5 w-3.5 text-slate-400" />
            <span className="text-slate-400 font-medium">Filter:</span>
            {['', 'SMTP', 'TLS', 'IMAP', 'POP3', 'DNS', 'TCP'].map((proto) => (
              <button
                key={proto}
                onClick={() => {
                  setProtocolFilter(proto);
                  setPage(0);
                }}
                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-colors ${
                  protocolFilter === proto
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}
              >
                {proto || 'All'}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Stream:</span>
              <input
                type="number"
                placeholder="All"
                value={streamFilter}
                onChange={(e) => {
                  setStreamFilter(e.target.value);
                  setPage(0);
                }}
                className="w-16 px-2 py-0.5 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500 text-xs"
              />
              {streamFilter && (
                <button
                  onClick={() => {
                    setStreamFilter('');
                    setPage(0);
                  }}
                  className="text-slate-500 hover:text-slate-300 text-[10px]"
                >
                  Clear
                </button>
              )}
            </div>
            <div className="text-slate-400">
              Showing {packets.length} of {total} frames
            </div>
          </div>
        </div>

        {/* Table Content */}
        <div className="flex-1 overflow-auto p-6">
          {loading ? (
            <div className="flex items-center justify-center py-20 text-slate-400 space-x-2">
              <Activity className="h-5 w-5 animate-spin text-blue-400" />
              <span className="text-xs">Loading forensic packet metadata...</span>
            </div>
          ) : packets.length === 0 ? (
            <div className="text-center py-16 text-slate-500 text-xs">
              No packet frames match the current filter criteria.
            </div>
          ) : (
            <table className="w-full text-left text-xs text-slate-300 font-mono">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Frame</th>
                  <th className="py-2.5 px-3">Time (Epoch)</th>
                  <th className="py-2.5 px-3">Source &rarr; Destination</th>
                  <th className="py-2.5 px-3">Protocol</th>
                  <th className="py-2.5 px-3">Stream</th>
                  <th className="py-2.5 px-3">TCP Flags</th>
                  <th className="py-2.5 px-3">Wire Len</th>
                  <th className="py-2.5 px-3">Payload Preview</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {packets.map((pkt) => (
                  <tr key={pkt.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-2.5 px-3 font-semibold text-blue-400">#{pkt.frame_number}</td>
                    <td className="py-2.5 px-3 text-slate-400">{pkt.timestamp.toFixed(4)}</td>
                    <td className="py-2.5 px-3 truncate max-w-[220px]">
                      {pkt.src_ip ? `${pkt.src_ip}:${pkt.src_port ?? '-'}` : 'L2'} &rarr;{' '}
                      {pkt.dst_ip ? `${pkt.dst_ip}:${pkt.dst_port ?? '-'}` : 'L2'}
                    </td>
                    <td className="py-2.5 px-3">{getProtocolBadge(pkt.detected_protocol)}</td>
                    <td className="py-2.5 px-3 text-slate-400">{pkt.tcp_stream !== null ? `Stream ${pkt.tcp_stream}` : '—'}</td>
                    <td className="py-2.5 px-3 text-[11px] text-amber-300/80">{pkt.tcp_flags || '—'}</td>
                    <td className="py-2.5 px-3 text-slate-400">{pkt.frame_length} B</td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono truncate max-w-[180px]" title={pkt.payload_preview || ''}>
                      {pkt.payload_preview || <span className="text-slate-600">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Modal Pagination Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <div className="text-xs text-slate-400 font-mono">
            Page {page + 1} of {totalPages}
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 disabled:opacity-30 text-slate-200 transition-colors"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 disabled:opacity-30 text-slate-200 transition-colors"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
