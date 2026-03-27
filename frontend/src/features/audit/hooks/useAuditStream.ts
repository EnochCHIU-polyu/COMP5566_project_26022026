import { useRef } from "react";

import { createAudit, streamAudit } from "../services/auditApi";
import { useAuditStore } from "../store/auditStore";
import type { AuditCreateInput } from "../types";

export function useAuditStream() {
  const esRef = useRef<EventSource | null>(null);
  const { start, applyEvent, setError, reset } = useAuditStore();

  const close = () => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
  };

  const runAudit = async (input: AuditCreateInput) => {
    close();
    reset();

    try {
      const created = await createAudit(input);
      start(created.audit_id, input);

      esRef.current = streamAudit(
        created.audit_id,
        (evt) => {
          applyEvent(evt);
          if (evt.event === "audit_completed" || evt.event === "audit_failed") {
            close();
          }
        },
        () => {
          const { stage } = useAuditStore.getState();
          if (stage !== "completed" && stage !== "failed") {
            setError("SSE connection dropped.");
          }
          close();
        },
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown audit error");
    }
  };

  return { runAudit, close };
}
