import { AuditInput } from "../features/audit/components/AuditInput";
import { FinalResultPanel } from "../features/audit/components/FinalResultPanel";
import { LLMStreamPanel } from "../features/audit/components/LLMStreamPanel";
import { SlitherPanel } from "../features/audit/components/SlitherPanel";
import { AppFrame } from "../components/AppFrame";
import { useAuditStream } from "../features/audit/hooks/useAuditStream";
import { useAuditStore } from "../features/audit/store/auditStore";

export function AuditPage() {
  const { runAudit } = useAuditStream();
  const {
    auditId,
    stage,
    slitherHits,
    slitherSummary,
    llmChunks,
    finalSummary,
    finalResults,
    finalMapping,
    model,
    mode,
    pipeline,
    temperature,
    batchSize,
    contractName,
    sourceCode,
    error,
    isRunning,
  } = useAuditStore();

  const steps = [
    { id: "queued", label: "Audit Created" },
    { id: "slither", label: "Slither Scan" },
    { id: "llm", label: "LLM Analysis" },
    { id: "completed", label: "Final Report" },
  ];

  const stageIndex = (() => {
    if (stage === "queued") return 0;
    if (stage === "slither") return 1;
    if (stage === "llm") return 2;
    if (stage === "completed" || stage === "failed") return 3;
    return -1;
  })();

  return (
    <AppFrame>
      <header className="aw-card backdrop-blur">
        <h1 className="aw-title text-2xl font-bold tracking-tight">
          Audit: Smart Contract Review
        </h1>
        <p className="aw-subtle mt-1 text-sm">
          Workflow aligned with phase2 pipeline: Slither pre-scan, then streamed
          LLM reasoning.
        </p>

        <div className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-4">
          {steps.map((step, idx) => {
            const active = idx <= stageIndex;
            return (
              <div
                key={step.id}
                className={`aw-step ${active ? "aw-step-active" : ""}`}
              >
                {idx + 1}. {step.label}
              </div>
            );
          })}
        </div>

        {auditId && (
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
            <span className="aw-chip">contract: {contractName || "-"}</span>
            <span className="aw-chip">model: {model}</span>
            <span className="aw-chip">mode: {mode}</span>
            <span className="aw-chip">pipeline: {pipeline}</span>
            <span className="aw-chip">temp: {temperature.toFixed(1)}</span>
            <span className="aw-chip">batch: {batchSize}</span>
          </div>
        )}
      </header>

      <section className="grid gap-4 xl:grid-cols-12">
        <div className="xl:col-span-7 2xl:col-span-8">
          <AuditInput onSubmit={runAudit} disabled={isRunning} />
        </div>
        <div className="flex flex-col gap-4 xl:col-span-5 2xl:col-span-4">
          <SlitherPanel
            hits={slitherHits}
            summary={slitherSummary}
            stage={stage}
          />
          <LLMStreamPanel chunks={llmChunks} isRunning={isRunning} />
        </div>
      </section>

      <section className="mt-4">
        <FinalResultPanel
          summary={finalSummary}
          results={finalResults}
          mapping={finalMapping}
          sourceCode={sourceCode}
          error={error}
          auditId={auditId}
          model={model}
          mode={mode}
          pipeline={pipeline}
        />
      </section>
    </AppFrame>
  );
}
