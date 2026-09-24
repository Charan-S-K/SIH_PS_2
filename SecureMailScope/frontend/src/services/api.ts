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

export interface EmailProtocolEvent {
  direction: 'c2s' | 's2c';
  event_type: string;
  command?: string | null;
  argument?: string | null;
  response_code?: string | null;
  raw_text: string;
  frame_number?: number | null;
  timestamp?: number | null;
}

export interface EmailSessionAnalysisItem {
  id: string;
  job_id: string;
  tcp_session_id?: string | null;
  tcp_stream: number;
  protocol: string;
  client_ip?: string | null;
  server_ip?: string | null;
  client_port?: number | null;
  server_port?: number | null;
  server_banner?: string | null;
  client_greeting?: string | null;
  session_state: string;
  capabilities?: string[] | null;
  starttls_advertised: boolean;
  starttls_requested: boolean;
  starttls_accepted: boolean;
  auth_mechanisms?: string[] | null;
  auth_attempted: boolean;
  auth_successful?: boolean | null;
  auth_usernames?: string[] | null;
  commands_count: number;
  events?: EmailProtocolEvent[] | null;
  security_warnings?: string[] | null;
  first_frame_number?: number | null;
  last_frame_number?: number | null;
  created_at?: string | null;
}

export interface EmailSessionAnalysisListResponse {
  job_id: string;
  total_email_sessions: number;
  sessions: EmailSessionAnalysisItem[];
}

export async function fetchJobEmailSessions(jobId: string): Promise<{ data: EmailSessionAnalysisListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/email-sessions`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to fetch email sessions` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch email sessions' };
  }
}

export async function fetchStreamEmailSession(jobId: string, streamId: number): Promise<{ data: EmailSessionAnalysisItem | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/email-sessions/${streamId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Stream email session not found` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch stream email session' };
  }
}

export async function analyzeJobEmailProtocols(jobId: string): Promise<{ data: EmailSessionAnalysisListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/analyze-email-protocols`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to trigger email protocol analysis` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to trigger email protocol analysis' };
  }
}

export interface StarttlsFinding {
  code: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  message: string;
  evidence_frame?: number | null;
}

export interface StarttlsAnalysisItem {
  id: string;
  job_id: string;
  tcp_session_id?: string | null;
  tcp_stream: number;
  protocol: string;
  client_ip?: string | null;
  server_ip?: string | null;
  client_port?: number | null;
  server_port?: number | null;
  advertised: boolean;
  advertised_frame?: number | null;
  advertised_command?: string | null;
  requested: boolean;
  requested_frame?: number | null;
  requested_command?: string | null;
  accepted: boolean;
  response_frame?: number | null;
  response_code?: string | null;
  response_text?: string | null;
  upgrade_status: string;
  tls_record_detected: boolean;
  tls_start_frame?: number | null;
  cleartext_auth_observed: boolean;
  cleartext_auth_frame?: number | null;
  cleartext_auth_command?: string | null;
  findings?: StarttlsFinding[] | null;
  created_at?: string | null;
}

export interface StarttlsAnalysisListResponse {
  job_id: string;
  total_streams: number;
  upgraded_count: number;
  downgrade_risk_count: number;
  critical_findings_count: number;
  analyses: StarttlsAnalysisItem[];
}

export async function fetchJobStarttls(jobId: string): Promise<{ data: StarttlsAnalysisListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/starttls`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to fetch STARTTLS analysis` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch STARTTLS analysis' };
  }
}

export async function fetchStreamStarttls(jobId: string, streamId: number): Promise<{ data: StarttlsAnalysisItem | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/starttls/${streamId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Stream STARTTLS analysis not found` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch stream STARTTLS analysis' };
  }
}

export async function analyzeJobStarttls(jobId: string): Promise<{ data: StarttlsAnalysisListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/analyze-starttls`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to trigger STARTTLS analysis` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to trigger STARTTLS analysis' };
  }
}

export interface TlsCipherSuiteItem {
  id: number;
  hex: string;
  name: string;
}

export interface TlsHandshakeMessageItem {
  message_type: string;
  frame_number?: number | null;
  timestamp?: number | null;
  length?: number | null;
  info?: string | null;
}

export interface TlsHandshakeAnalysisItem {
  id: string;
  job_id: string;
  tcp_session_id?: string | null;
  tcp_stream: number;
  protocol: string;
  client_ip?: string | null;
  server_ip?: string | null;
  client_port?: number | null;
  server_port?: number | null;
  handshake_status: string;
  is_starttls: boolean;
  negotiated_version: string;
  negotiated_version_raw?: number | null;
  negotiated_cipher_suite: string;
  negotiated_cipher_id?: number | null;
  key_exchange_group?: string | null;
  signature_scheme?: string | null;
  sni?: string | null;
  alpn_selected?: string | null;
  client_hello_frame?: number | null;
  client_hello_time?: number | null;
  client_hello_version?: string | null;
  client_random?: string | null;
  client_offered_ciphers?: TlsCipherSuiteItem[] | null;
  client_supported_versions?: string[] | null;
  client_supported_groups?: string[] | null;
  client_signature_algorithms?: string[] | null;
  client_alpn_protocols?: string[] | null;
  client_extensions_count: number;
  server_hello_frame?: number | null;
  server_hello_time?: number | null;
  server_hello_version?: string | null;
  server_random?: string | null;
  server_extensions_count: number;
  certificate_frame?: number | null;
  certificate_chain_length: number;
  has_alert: boolean;
  alert_level?: string | null;
  alert_description?: string | null;
  alert_frame?: number | null;
  handshake_messages?: TlsHandshakeMessageItem[] | null;
  handshake_duration_ms?: number | null;
  evidence?: any[] | null;
  created_at?: string | null;
}

export interface TlsHandshakeAnalysisListResponse {
  job_id: string;
  total_handshakes: number;
  completed_count: number;
  tls13_count: number;
  tls12_count: number;
  legacy_tls_count: number;
  alert_count: number;
  analyses: TlsHandshakeAnalysisItem[];
}

export async function fetchJobTlsHandshakes(jobId: string): Promise<{ data: TlsHandshakeAnalysisListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/tls-handshakes`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to fetch TLS handshakes` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch TLS handshakes' };
  }
}

export async function fetchStreamTlsHandshake(jobId: string, streamId: number): Promise<{ data: TlsHandshakeAnalysisItem | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/tls-handshakes/${streamId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Stream TLS handshake not found` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch stream TLS handshake' };
  }
}

export async function analyzeJobTlsHandshakes(jobId: string): Promise<{ data: TlsHandshakeAnalysisListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/analyze-tls-handshakes`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to trigger TLS handshake analysis` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to trigger TLS handshake analysis' };
  }
}

// -------------------------------------------------------------
// Stage 08: X.509 Certificate Forensic Analysis Types & Client
// -------------------------------------------------------------

export interface SanItem {
  type: string;
  value: string;
}

export interface X509Certificate {
  id: number;
  job_id: string;
  tcp_stream: number;
  tcp_session_id?: string | null;
  tls_handshake_id?: string | null;
  frame_number?: number | null;
  chain_index: number;
  chain_length: number;
  chain_status: string;
  subject_dn: string;
  subject_cn?: string | null;
  subject_org?: string | null;
  subject_ou?: string | null;
  subject_country?: string | null;
  subject_state?: string | null;
  subject_locality?: string | null;
  issuer_dn: string;
  issuer_cn?: string | null;
  issuer_org?: string | null;
  issuer_ou?: string | null;
  issuer_country?: string | null;
  issuer_state?: string | null;
  issuer_locality?: string | null;
  serial_number: string;
  not_before: string;
  not_after: string;
  validity_days: number;
  validity_status: string;
  days_until_expiration?: number | null;
  sans: SanItem[];
  public_key_algorithm: string;
  key_size_bits?: number | null;
  public_key_curve?: string | null;
  signature_algorithm: string;
  signature_digest?: string | null;
  is_self_signed: boolean;
  is_ca: boolean;
  path_length_constraint?: number | null;
  key_usage: string[];
  extended_key_usage: string[];
  fingerprint_sha256: string;
  fingerprint_sha1: string;
  raw_der_base64?: string | null;
  parsing_status: string;
  error_message?: string | null;
  created_at?: string;
}

export interface X509CertificateListResponse {
  job_id: string;
  total_certificates: number;
  valid_certificates: number;
  expired_certificates: number;
  not_yet_valid_certificates: number;
  self_signed_certificates: number;
  weak_keys_count: number;
  weak_signatures_count: number;
  certificates: X509Certificate[];
}

export async function fetchJobCertificates(jobId: string): Promise<{ data: X509CertificateListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/certificates`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to fetch certificates` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch certificates' };
  }
}

export async function fetchStreamCertificates(jobId: string, streamId: number): Promise<{ data: X509Certificate[] | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/certificates/${streamId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to fetch stream certificates` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to fetch stream certificates' };
  }
}

export async function analyzeJobCertificates(jobId: string): Promise<{ data: X509CertificateListResponse | null; error: string | null }> {
  try {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/analyze-certificates`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) {
      return { data: null, error: `HTTP ${res.status}: Failed to trigger certificate analysis` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err: any) {
    return { data: null, error: err.message || 'Failed to trigger certificate analysis' };
  }
}



