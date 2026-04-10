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
  is_other?: boolean;
  mapped_from_db?: boolean;
}

export interface AuditMappingInfo {
  mapped_count: number;
  other_count: number;
  db_types?: string[];
  other_candidates?: Array<Record<string, unknown>>;
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
  finalMapping: AuditMappingInfo | null;
  contractName: string;
  sourceCode: string;
  model: string;
  mode: string;
  pipeline: string;
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
  batch_size: number;
}
