/**
 * API client service for communicating with the SecureMailScope FastAPI backend.
 */

export interface HealthResponse {
  status: string;
  version: string;
  environment: string;
  timestamp: string;
}

export interface ReadinessResponse {
  status: 'ready' | 'not_ready';
  database: {
    status: 'connected' | 'disconnected';
    error?: string | null;
  };
  timestamp: string;
}

export interface InfoResponse {
  project_name: string;
  project_description: string;
  version: string;
  environment: string;
  debug: boolean;
  api_prefix: string;
  supported_protocols: string[];
  cryptographic_standards: string[];
  current_stage: string;
}

export interface PcapFileMeta {
  id: string;
  original_filename: string;
  file_size_bytes: number;
  sha256: string;
  md5: string;
  file_format: string;
  is_valid: boolean;
  created_at: string;
}

export interface PcapUploadResult {
  job_id: string;
  file_id: string;
  filename: string;
  file_size_bytes: number;
  sha256: string;
  md5: string;
  file_format: string;
  status: string;
  created_at: string;
}

export interface AnalysisJob {
  id: string;
  pcap_file_id: string;
  status: 'PENDING' | 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | string;
  progress_percent: number;
  stage_message: string;
  error_message?: string | null;
  total_packets?: number;
  tcp_packets?: number;
  udp_packets?: number;
  other_packets?: number;
  duration_seconds?: number;
  detected_protocols?: string | null;
  created_at: string;
  updated_at: string;
  completed_at?: string | null;
  pcap_file?: PcapFileMeta | null;
}

export interface JobListResponse {
  total: number;
  limit: number;
  offset: number;
  jobs: AnalysisJob[];
}

export interface PacketItem {
  id: string;
  frame_number: number;
  timestamp: number;
  frame_length: number;
  ip_version: number;
  src_ip?: string | null;
  dst_ip?: string | null;
  transport_protocol: string;
  src_port?: number | null;
  dst_port?: number | null;
  detected_protocol: string;
  tcp_stream?: number | null;
  tcp_seq?: number | null;
  tcp_ack?: number | null;
  tcp_flags?: string | null;
  payload_size: number;
  payload_preview?: string | null;
}

export interface PacketListResponse {
  total: number;
  limit: number;
  offset: number;
  packets: PacketItem[];
}

export interface CaptureSummary {
  job_id: string;
  status: string;
  total_packets: number;
  tcp_packets: number;
  udp_packets: number;
  other_packets: number;
  duration_seconds: number;
  capture_start_time?: number | null;
  capture_end_time?: number | null;
  detected_protocols: string[];
  distinct_conversations: number;
}

const API_BASE = '/api/v1';

export async function checkLiveness(): Promise<{ data: HealthResponse | null; latencyMs: number; error: string | null }> {
  const start = performance.now();
  try {
    const res = await fetch(`${API_BASE}/health`, {
      headers: { 'Accept': 'application/json' },
    });
    const latencyMs = Math.round(performance.now() - start);
    if (!res.ok) {
      return { data: null, latencyMs, error: `HTTP ${res.status}: ${res.statusText}` };
    }
    const data = await res.json();
    return { data, latencyMs, error: null };
  } catch (err: any) {
    const latencyMs = Math.round(performance.now() - start);
    return { data: null, latencyMs, error: err.message || 'Network connection failed' };
  }
}

export async function checkReadiness(): Promise<{ data: ReadinessResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/health/ready`, {
      headers: { 'Accept': 'application/json' },
    });
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Unable to contact readiness probe' };
  }
}

export async function fetchSystemInfo(): Promise<{ data: InfoResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/health/info`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch system info' };
  }
}

export async function uploadPcapFile(file: File): Promise<{ data: PcapUploadResult | null; error: string | null }> {
  try {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/pcap/upload`, {
      method: 'POST',
      body: formData,
      headers: {
        'Accept': 'application/json',
      },
    });

    const body = await res.json();
    if (!res.ok) {
      return { data: null, error: body.detail || `Upload failed with HTTP ${res.status}` };
    }
    return { data: body, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Network error during upload' };
  }
}

export async function listJobs(limit: number = 20, offset: number = 0): Promise<{ data: JobListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs?limit=${limit}&offset=${offset}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch analysis jobs' };
  }
}

export async function processJob(jobId: string): Promise<{ data: AnalysisJob | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/process`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
    const body = await res.json();
    if (!res.ok) {
      return { data: null, error: body.detail || `Processing failed with HTTP ${res.status}` };
    }
    return { data: body, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Network error while triggering processing' };
  }
}

export async function fetchJobPackets(
  jobId: string,
  limit: number = 50,
  offset: number = 0,
  protocol?: string,
  port?: number,
  tcpStream?: number
): Promise<{ data: PacketListResponse | null; error: string | null }> {
  try {
    const params = new URLSearchParams({
      limit: limit.toString(),
      offset: offset.toString(),
    });
    if (protocol) params.append('protocol', protocol);
    if (port !== undefined) params.append('port', port.toString());
    if (tcpStream !== undefined) params.append('tcp_stream', tcpStream.toString());

    const res = await fetch(`${API_BASE}/jobs/${jobId}/packets?${params.toString()}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch packet metadata' };
  }
}

export async function fetchJobSummary(jobId: string): Promise<{ data: CaptureSummary | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/summary`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch capture summary' };
  }
}

export interface EvidenceFrame {
  frame_number: number;
  timestamp: number;
  direction: string;
  signature_matched: string;
  matched_text?: string | null;
}

export interface PortAnalysis {
  server_port?: number | null;
  standard_port_for?: string | null;
  matches_detected_protocol: boolean;
  notes?: string | null;
}

export interface ProtocolEvidence {
  matched_signatures: string[];
  evidence_frames: EvidenceFrame[];
  port_analysis?: PortAnalysis | null;
  insufficient_evidence_reason?: string | null;
  anomalies: string[];
  tshark_protocol?: string | null;
}

export interface ProtocolItem {
  id: string;
  job_id: string;
  tcp_stream?: number | null;
  protocol: string;
  confidence: number;
  confidence_level: string;
  classification_method: string;
  is_mail_protocol: boolean;
  client_ip?: string | null;
  server_ip?: string | null;
  client_port?: number | null;
  server_port?: number | null;
  summary?: string | null;
  evidence?: ProtocolEvidence | null;
  packet_count: number;
  total_bytes: number;
  created_at?: string | null;
}

export interface ProtocolListResponse {
  job_id: string;
  total_streams: number;
  mail_streams: number;
  protocols: ProtocolItem[];
}

export async function fetchJobProtocols(jobId: string): Promise<{ data: ProtocolListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/protocols`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to fetch protocols` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch protocols' };
  }
}

export async function fetchStreamProtocol(jobId: string, streamId: number): Promise<{ data: ProtocolItem | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/protocols/${streamId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Stream protocol not found` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch stream protocol' };
  }
}

export async function identifyJobProtocols(jobId: string): Promise<{ data: ProtocolListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/identify-protocols`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to trigger protocol identification` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to trigger protocol identification' };
  }
}

export interface ConversationTurn {
  direction: 'c2s' | 's2c';
  start_frame: number;
  end_frame: number;
  start_time: number;
  end_time: number;
  byte_length: number;
  text_preview: string;
}

export interface TcpSessionItem {
  id: string;
  job_id: string;
  tcp_stream: number;
  client_ip?: string | null;
  server_ip?: string | null;
  client_port?: number | null;
  server_port?: number | null;
  protocol: string;
  session_state: string;
  start_time: number;
  end_time: number;
  duration_seconds: number;
  first_frame_number: number;
  last_frame_number: number;
  packet_count: number;
  c2s_packet_count: number;
  s2c_packet_count: number;
  c2s_bytes: number;
  s2c_bytes: number;
  total_payload_bytes: number;
  retransmissions_count: number;
  out_of_order_count: number;
  gaps_count: number;
  syn_frame_number?: number | null;
  syn_ack_frame_number?: number | null;
  fin_frame_numbers?: number[] | null;
  rst_frame_numbers?: number[] | null;
  c2s_payload_preview?: string | null;
  s2c_payload_preview?: string | null;
  conversation_flow?: ConversationTurn[] | null;
  reconstruction_metadata?: {
    retransmissions?: any[];
    out_of_order_segments?: any[];
    gaps?: any[];
    syn_observed?: boolean;
    syn_ack_observed?: boolean;
    fin_observed?: boolean;
    rst_observed?: boolean;
  } | null;
  created_at?: string | null;
}

export interface TcpSessionListResponse {
  job_id: string;
  total_sessions: number;
  sessions: TcpSessionItem[];
}

export async function fetchJobSessions(jobId: string): Promise<{ data: TcpSessionListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/sessions`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to fetch sessions` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch sessions' };
  }
}

export async function fetchStreamSession(jobId: string, streamId: number): Promise<{ data: TcpSessionItem | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/sessions/${streamId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Stream session not found` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch stream session' };
  }
}

export async function reconstructJobSessions(jobId: string): Promise<{ data: TcpSessionListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/reconstruct-sessions`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to trigger session reconstruction` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to trigger session reconstruction' };
  }
}


