interface Props {
  hits: Array<Record<string, unknown>>;
  stage: string;
  summary?: string;
}

export function SlitherPanel({ hits, stage, summary = "" }: Props) {
  return (
    <section className="aw-card">
      <div className="flex items-center justify-between">
        <h2 className="aw-title text-lg font-semibold">Slither Pre-Scan</h2>
        <span
          className="aw-chip rounded-full px-3"
          style={{ color: "#1E293B" }}
        >
          stage: {stage}
        </span>
      </div>

      {summary && (
        <p
          className="aw-subtle mt-3 rounded-md border px-3 py-2 text-sm break-words"
          style={{
            borderColor: "var(--aw-border)",
            background: "var(--aw-surface-soft)",
          }}
        >
          {summary}
        </p>
      )}

      {hits.length === 0 ? (
        <p className="aw-subtle mt-3 text-sm">Waiting for Slither output...</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {hits.map((hit, idx) => (
            <li
              key={idx}
              className="rounded-md border p-3 text-sm break-words"
              style={{
                borderColor: "var(--aw-border)",
                background: "var(--aw-surface-soft)",
              }}
            >
              <div className="font-semibold text-[#1E293B]">
                {idx + 1}. {String(hit.check ?? "-")}
              </div>
              <div className="aw-subtle mt-1">
                impact: {String(hit.impact ?? "-")}
              </div>
              <div className="max-h-28 overflow-y-auto text-xs text-slate-500 break-all pr-1">
                detail: {String(hit.detail ?? "-")}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
