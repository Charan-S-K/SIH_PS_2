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
