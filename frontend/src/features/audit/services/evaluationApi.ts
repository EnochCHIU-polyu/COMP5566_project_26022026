import { API_BASE } from "../../../lib/apiConfig";

export interface RuntimeMetricsSummary {
  total_runs: number;
  completed_runs: number;
  failed_runs: number;
  avg_duration_seconds: number;
  avg_risk_score: number;
  total_other_findings: number;
  avg_other_findings_per_completed_run: number;
}

export interface RuntimeMetricsRecord {
  ts?: string;
  audit_id?: string;
  status?: string;
  model?: string;
  pipeline?: string;
  mode?: string;
  duration_seconds?: number;
  risk_score?: number;
  mapped_count?: number;
  other_count?: number;
  other_found_count?: number;
  llm_result_count?: number;
  error?: string;
}

export interface RuntimeMetricsResponse {
  summary: RuntimeMetricsSummary;
  records: RuntimeMetricsRecord[];
  source: string;
}

export async function getRuntimeMetrics(
  limit = 100,
): Promise<RuntimeMetricsResponse> {
  const res = await fetch(
    `${API_BASE}/api/v1/audits/metrics/runtime?limit=${limit}`,
  );
  if (!res.ok) {
    throw new Error(`Load runtime metrics failed: ${res.status}`);
  }
  return res.json() as Promise<RuntimeMetricsResponse>;
}
