import { API_BASE } from "../../../lib/apiConfig";

export type BenchmarkDataset = "smartbugs" | "solidifi";
export type BenchmarkMode = "binary" | "non_binary" | "cot";
export type BenchmarkPipeline = "standard" | "cascade" | "multi_llm";

export interface BenchmarkContractPreview {
  name: string;
  labels: string[];
  source_preview: string;
}

export interface BenchmarkLoadResponse {
  dataset: BenchmarkDataset;
  loaded: number;
  contracts: BenchmarkContractPreview[];
  vuln_types_under_test: string[];
}

export interface BenchmarkRunRequest {
  dataset: BenchmarkDataset;
  limit: number;
  prefer_shared_db: boolean;
  model: string;
  mode: BenchmarkMode;
  pipeline: BenchmarkPipeline;
  cascade_small: string;
  cascade_large: string;
  multi_models: string[];
  multi_parallel: boolean;
  multi_aggregation: "majority" | "consensus";
}

export interface BenchmarkRunResponse {
  dataset: BenchmarkDataset;
  loaded: number;
  vuln_types_under_test: string[];
  swe_mapping?: Array<{
    label: string;
    covered: boolean;
    swe_field_id: number | null;
    swe_field: string;
    swe_weakness: string;
  }>;
  scores: {
    aggregate?: {
      counts?: Record<string, number>;
      metrics?: Record<string, number>;
      skipped_unparseable?: number;
    };
    per_contract?: Array<{
      contract_name: string;
      counts?: Record<string, number>;
      metrics?: Record<string, number>;
      skipped_unparseable?: number;
    }>;
  };
  audit_results: Array<{
    contract_name: string;
    error?: string;
    vuln_results?: Array<{ vuln_name: string; response: string }>;
  }>;
}

export interface BenchmarkLlmCheckResponse {
  ok: boolean;
  model: string;
  latency_ms: number | null;
  preview: string;
  error: string | null;
}

export async function checkBackendHealth(): Promise<{ status: string }> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/healthz`);
  } catch (err) {
    throw new Error(
      `Cannot reach backend (${API_BASE}). Original error: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!res.ok) {
    throw new Error(`Backend health check failed: ${res.status}`);
  }
  return res.json() as Promise<{ status: string }>;
}

export async function checkBenchmarkLlm(
  model: string,
): Promise<BenchmarkLlmCheckResponse> {
  const params = new URLSearchParams({ model });

  let res: Response;
  try {
    res = await fetch(
      `${API_BASE}/api/v1/benchmark/llm-check?${params.toString()}`,
    );
  } catch (err) {
    throw new Error(
      `Cannot reach backend (${API_BASE}) during LLM check. Original error: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`LLM check failed: ${res.status} ${detail}`);
  }
  return res.json() as Promise<BenchmarkLlmCheckResponse>;
}

export async function loadBenchmarkContracts(
  dataset: BenchmarkDataset,
  limit: number,
  preferSharedDb: boolean,
): Promise<BenchmarkLoadResponse> {
  const params = new URLSearchParams({
    dataset,
    limit: String(limit),
    prefer_shared_db: String(preferSharedDb),
  });

  let res: Response;
  try {
    res = await fetch(
      `${API_BASE}/api/v1/benchmark/contracts?${params.toString()}`,
    );
  } catch (err) {
    throw new Error(
      `Cannot reach backend (${API_BASE}). Check backend server and VITE_API_URL. Original error: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!res.ok) {
    throw new Error(`Load benchmark failed: ${res.status}`);
  }
  return res.json() as Promise<BenchmarkLoadResponse>;
}

export async function runBenchmark(
  payload: BenchmarkRunRequest,
): Promise<BenchmarkRunResponse> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/v1/benchmark/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    throw new Error(
      `Cannot reach backend (${API_BASE}) while running benchmark. Check backend server and VITE_API_URL. Original error: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Run benchmark failed: ${res.status} ${detail}`);
  }
  return res.json() as Promise<BenchmarkRunResponse>;
}
