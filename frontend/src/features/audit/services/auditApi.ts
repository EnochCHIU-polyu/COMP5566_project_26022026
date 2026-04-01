import type { AuditCreateInput, AuditEvent } from "../types";
import { API_BASE } from "../../../lib/apiConfig";

export interface VulnerabilityCatalogResponse {
  count: number;
  names: string[];
  source?: string;
  raw_row_count?: number | null;
  table?: string;
  data_backend?: string;
}

export async function createAudit(
  input: AuditCreateInput,
): Promise<{ audit_id: string; status: string }> {
  const res = await fetch(`${API_BASE}/api/v1/audits`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    throw new Error(`Create audit failed: ${res.status}`);
  }
  return res.json();
}

export async function getVulnerabilityCatalog(): Promise<VulnerabilityCatalogResponse> {
  const res = await fetch(`${API_BASE}/api/v1/vulnerabilities/catalog`);
  if (!res.ok) {
    throw new Error(`Load vulnerability catalog failed: ${res.status}`);
  }
  return res.json() as Promise<VulnerabilityCatalogResponse>;
}

export function streamAudit(
  auditId: string,
  onEvent: (evt: AuditEvent) => void,
  onError: (err: unknown) => void,
): EventSource {
  const es = new EventSource(`${API_BASE}/api/v1/audits/${auditId}/stream`);

  const events = [
    "audit_started",
    "slither_progress",
    "slither_result",
    "llm_progress",
    "llm_chunk",
    "audit_completed",
    "audit_failed",
    "ping",
  ];

  events.forEach((name) => {
    es.addEventListener(name, (e) => {
      const msg = e as MessageEvent;
      onEvent(JSON.parse(msg.data) as AuditEvent);
    });
  });

  es.onerror = (err) => {
    onError(err);
  };

  return es;
}
