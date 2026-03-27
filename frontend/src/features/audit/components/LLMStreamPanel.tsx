interface Props {
  chunks: string[];
  isRunning: boolean;
}

export function LLMStreamPanel({ chunks, isRunning }: Props) {
  return (
    <section className="aw-card">
      <div className="flex items-center justify-between">
        <h2 className="aw-title text-lg font-semibold text-[#1E293B]">
          LLM Stream
        </h2>
        <span className="aw-subtle text-xs">chunks: {chunks.length}</span>
      </div>

      {isRunning && (
        <p className="mt-1 text-sm text-[#1E293B]/70">
          Streaming model response...
        </p>
      )}
      <div className="mt-3 max-h-80 space-y-2 overflow-y-auto pr-1">
        {chunks.length === 0 ? (
          <p className="aw-subtle text-sm">No LLM output yet.</p>
        ) : (
          chunks.map((chunk, idx) => (
            <div
              key={idx}
              className="rounded-md border px-3 py-2 text-sm text-[#1E293B]"
              style={{
                borderColor: "var(--aw-border)",
                background: "var(--aw-surface-soft)",
              }}
            >
              <p className="mb-1 text-xs text-[#1E293B]/70">chunk #{idx + 1}</p>
              <p>{chunk}</p>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
