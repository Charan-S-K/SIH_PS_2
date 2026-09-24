import React, { useState, useRef } from 'react';
import { UploadCloud, CheckCircle2, AlertCircle, FileText, Hash, Key } from 'lucide-react';
import { uploadPcapFile, PcapUploadResult } from '../services/api';

interface PcapUploadCardProps {
  onUploadSuccess: () => void;
}

export const PcapUploadCard: React.FC<PcapUploadCardProps> = ({ onUploadSuccess }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadResult, setUploadResult] = useState<PcapUploadResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    setError(null);
    setUploadResult(null);

    // Client-side extension validation
    const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();
    if (!['.pcap', '.pcapng', '.cap'].includes(ext)) {
      setError(`Unsupported file extension '${ext}'. Only .pcap, .pcapng, and .cap are permitted.`);
      return;
    }

    // Size validation (100 MB max)
    const maxSize = 100 * 1024 * 1024;
    if (file.size > maxSize) {
      setError(`File size (${(file.size / (1024 * 1024)).toFixed(1)} MB) exceeds 100 MB limit.`);
      return;
    }

    if (file.size === 0) {
      setError('Cannot upload empty file (0 bytes).');
      return;
    }

    setIsUploading(true);
    const { data, error: uploadErr } = await uploadPcapFile(file);
    setIsUploading(false);

    if (uploadErr) {
      setError(uploadErr);
    } else if (data) {
      setUploadResult(data);
      onUploadSuccess();
    }
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = () => {
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  };

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 shadow-xl">
      <div className="pb-4 border-b border-slate-800/80">
        <h2 className="text-lg font-semibold text-slate-100 flex items-center space-x-2">
          <span>PCAP / PCAPNG Forensic Ingestion</span>
        </h2>
        <p className="text-sm text-slate-400">
          Upload passive network packet captures for cryptographic forensics. Files are validated via magic-byte sniffing and hashed with SHA-256.
        </p>
      </div>

      {/* Drag & Drop Upload Zone */}
      <div
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`mt-6 border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors duration-150 ${
          isDragging
            ? 'border-blue-500 bg-blue-950/20'
            : 'border-slate-700/80 hover:border-slate-500 bg-slate-900/40 hover:bg-slate-900/60'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={onFileChange}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-3">
          <div className="p-3 rounded-full bg-blue-950/80 border border-blue-800/50 text-blue-400">
            <UploadCloud className="h-8 w-8" />
          </div>
          <div>
            <p className="text-sm font-medium text-slate-200">
              {isUploading ? 'Streaming upload and validating capture...' : 'Drag and drop your capture file, or click to browse'}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Supports .pcap (microsecond/nanosecond) and .pcapng &bull; Max 100 MB &bull; Untrusted input sandbox
            </p>
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="mt-4 p-4 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 flex items-start space-x-2.5">
          <AlertCircle className="h-4 w-4 text-rose-400 flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold">Ingestion Error:</span> {error}
          </div>
        </div>
      )}

      {/* Upload Success Details */}
      {uploadResult && (
        <div className="mt-4 p-4 rounded-lg bg-emerald-950/30 border border-emerald-800/50 text-xs space-y-2">
          <div className="flex items-center text-emerald-400 font-medium space-x-1.5">
            <CheckCircle2 className="h-4 w-4" />
            <span>Capture ingested successfully and analysis job queued.</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 text-slate-300 font-mono">
            <div className="flex items-center space-x-1.5 truncate">
              <FileText className="h-3.5 w-3.5 text-blue-400 flex-shrink-0" />
              <span className="text-slate-400">File:</span> <span>{uploadResult.filename}</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="text-slate-400">Size:</span>{' '}
              <span>{(uploadResult.file_size_bytes / 1024).toFixed(1)} KB ({uploadResult.file_format.toUpperCase()})</span>
            </div>
            <div className="flex items-center space-x-1.5 truncate col-span-1 sm:col-span-2">
              <Hash className="h-3.5 w-3.5 text-purple-400 flex-shrink-0" />
              <span className="text-slate-400">SHA-256:</span>{' '}
              <span className="truncate">{uploadResult.sha256}</span>
            </div>
            <div className="flex items-center space-x-1.5 truncate col-span-1 sm:col-span-2">
              <Key className="h-3.5 w-3.5 text-amber-400 flex-shrink-0" />
              <span className="text-slate-400">Job UUID:</span>{' '}
              <span className="truncate">{uploadResult.job_id}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
