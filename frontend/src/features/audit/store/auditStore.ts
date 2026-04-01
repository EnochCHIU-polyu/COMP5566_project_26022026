import { create } from "zustand";

import type {
  AuditCreateInput,
  AuditEvent,
  AuditRunState,
  AuditVulnResult,
} from "../types";

interface AuditStore extends AuditRunState {
  reset: () => void;
  start: (auditId: string, input: AuditCreateInput) => void;
  applyEvent: (evt: AuditEvent) => void;
  setError: (message: string) => void;
}

const initialState: AuditRunState = {
  auditId: null,
  stage: "queued",
  events: [],
  slitherHits: [],
  slitherSummary: "",
  llmChunks: [],
  finalSummary: "",
  finalResults: [],
  finalMapping: null,
  contractName: "",
  sourceCode: "",
  model: "deepseek-v3.2",
  mode: "non_binary",
  pipeline: "standard",
  temperature: 0,
  batchSize: 8,
  isRunning: false,
  error: null,
};

export const useAuditStore = create<AuditStore>((set) => ({
  ...initialState,
  reset: () => set(initialState),
  start: (auditId, input) =>
    set({
      ...initialState,
      auditId,
      contractName: input.contract_name,
      sourceCode: input.source_code,
      model: input.model,
      mode: input.mode,
      pipeline: input.pipeline,
      temperature: input.temperature,
      batchSize: input.batch_size,
      isRunning: true,
      stage: "queued",
    }),
  applyEvent: (evt) =>
    set((state) => {
      const next = {
        ...state,
        events: [...state.events, evt],
        stage: evt.stage,
      };

      if (evt.event === "slither_result") {
        next.slitherHits =
          (evt.payload.hits as Array<Record<string, unknown>>) ?? [];
        next.slitherSummary = String(
          evt.payload.summary ?? "Slither stage completed",
        );
      }
      if (evt.event === "llm_chunk") {
        const text = String(evt.payload.text ?? "");
        next.llmChunks = [...state.llmChunks, text];
      }
      if (evt.event === "llm_progress") {
        const text = String(evt.payload.message ?? "LLM working...");
        next.llmChunks = [...state.llmChunks, `[progress] ${text}`];
      }
      if (evt.event === "audit_completed") {
        next.finalSummary = String(evt.payload.summary ?? "");
        next.finalResults = Array.isArray(evt.payload.results)
          ? (evt.payload.results as AuditVulnResult[])
          : [];
        next.finalMapping =
          evt.payload.mapping && typeof evt.payload.mapping === "object"
            ? (evt.payload.mapping as AuditRunState["finalMapping"])
            : null;
        next.isRunning = false;
      }
      if (evt.event === "audit_failed") {
        next.error = String(evt.payload.error ?? "Audit failed");
        next.isRunning = false;
      }

      return next;
    }),
  setError: (message) =>
    set({ error: message, isRunning: false, stage: "failed" }),
}));
