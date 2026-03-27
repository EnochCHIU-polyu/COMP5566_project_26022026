export type AuditStage = "queued" | "slither" | "llm" | "completed" | "failed";

export type AuditEventType =
  | "audit_started"
  | "slither_progress"
  | "slither_result"
  | "llm_progress"
  | "llm_chunk"
  | "audit_completed"
  | "audit_failed"
  | "ping";

export interface AuditEvent {
  audit_id: string;
  event: AuditEventType;
  stage: AuditStage;
  seq: number;
  ts?: string;
  payload: Record<string, unknown>;
}

export interface AuditVulnResult {
  vuln_name: string;
  response: string;
}

export interface AuditRunState {
  auditId: string | null;
  stage: AuditStage;
  events: AuditEvent[];
  slitherHits: Array<Record<string, unknown>>;
  slitherSummary: string;
  llmChunks: string[];
  finalSummary: string;
  finalResults: AuditVulnResult[];
  contractName: string;
  sourceCode: string;
  model: string;
  mode: string;
  pipeline: string;
  temperature: number;
  batchSize: number;
  isRunning: boolean;
  error: string | null;
}

export interface AuditCreateInput {
  contract_name: string;
  source_code: string;
  model: string;
  mode: string;
  pipeline: string;
  temperature: number;
  batch_size: number;
}
