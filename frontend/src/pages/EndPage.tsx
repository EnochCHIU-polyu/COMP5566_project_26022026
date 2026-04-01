import { useEffect, useMemo, useState } from "react";

import { AppFrame } from "../components/AppFrame";
import {
  getRuntimeMetrics,
  type RuntimeMetricsRecord,
  type RuntimeMetricsResponse,
} from "../features/audit/services/evaluationApi";

function fmt(value: number): string {
  return Number.isFinite(value) ? value.toFixed(2) : "0.00";
}

export function EndPage() {
  const [data, setData] = useState<RuntimeMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    getRuntimeMetrics(120)
      .then((res) => {
        if (!mounted) return;
        setData(res);
        setError(null);
      })
      .catch((err) => {
        if (!mounted) return;
        setError(err instanceof Error ? err.message : "Failed to load metrics");
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, []);

  const latest = useMemo(() => data?.records?.slice(0, 12) ?? [], [data]);

  return (
    <AppFrame>
      <section className="aw-card">
        <h1 className="aw-title text-2xl font-bold tracking-tight">
          Evaluation
        </h1>
        <p className="aw-subtle mt-2 text-sm">
          Runtime evaluation dashboard from cumulative audit records.
        </p>
        {data?.source && (
          <p className="aw-subtle mt-1 text-xs">source: {data.source}</p>
        )}
      </section>

      {error && (
        <section className="aw-card mt-4">
          <p className="text-sm text-rose-700">{error}</p>
        </section>
      )}

      <section className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <article className="aw-card">
          <p className="aw-subtle text-xs">Total Runs</p>
          <p className="aw-title mt-2 text-3xl font-bold">
            {loading ? "..." : (data?.summary.total_runs ?? 0)}
          </p>
        </article>
        <article className="aw-card">
          <p className="aw-subtle text-xs">Completed</p>
          <p className="aw-title mt-2 text-3xl font-bold text-emerald-700">
            {loading ? "..." : (data?.summary.completed_runs ?? 0)}
          </p>
        </article>
        <article className="aw-card">
          <p className="aw-subtle text-xs">Failed</p>
          <p className="aw-title mt-2 text-3xl font-bold text-rose-700">
            {loading ? "..." : (data?.summary.failed_runs ?? 0)}
          </p>
        </article>
        <article className="aw-card">
          <p className="aw-subtle text-xs">Avg Duration (s)</p>
          <p className="aw-title mt-2 text-3xl font-bold">
            {loading ? "..." : fmt(data?.summary.avg_duration_seconds ?? 0)}
          </p>
        </article>
        <article className="aw-card">
          <p className="aw-subtle text-xs">Avg Risk Score</p>
          <p className="aw-title mt-2 text-3xl font-bold">
            {loading ? "..." : fmt(data?.summary.avg_risk_score ?? 0)}
          </p>
        </article>
        <article className="aw-card">
          <p className="aw-subtle text-xs">DB Gap (OTHER total)</p>
          <p className="aw-title mt-2 text-3xl font-bold text-amber-700">
            {loading ? "..." : (data?.summary.total_other_findings ?? 0)}
          </p>
          <p className="aw-subtle mt-1 text-xs">
            +1 for each OTHER vulnerability found
          </p>
        </article>
      </section>

      <section className="aw-card mt-4">
        <h2 className="aw-title text-lg font-semibold">
          Recent Evaluation Records
        </h2>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left text-xs text-slate-500">
                <th className="px-2 py-2">Time</th>
                <th className="px-2 py-2">Status</th>
                <th className="px-2 py-2">Model</th>
                <th className="px-2 py-2">Pipeline</th>
                <th className="px-2 py-2">Duration</th>
                <th className="px-2 py-2">Risk</th>
                <th className="px-2 py-2">Mapped</th>
                <th className="px-2 py-2">Other</th>
                <th className="px-2 py-2">Results</th>
              </tr>
            </thead>
            <tbody>
              {latest.length === 0 && !loading && (
                <tr>
                  <td className="px-2 py-3 text-slate-500" colSpan={9}>
                    No runtime evaluation records yet.
                  </td>
                </tr>
              )}
              {loading && (
                <tr>
                  <td className="px-2 py-3 text-slate-500" colSpan={9}>
                    Loading evaluation records...
                  </td>
                </tr>
              )}
              {latest.map((row: RuntimeMetricsRecord, idx) => (
                <tr
                  key={`${row.audit_id ?? "noid"}-${idx}`}
                  className="border-b border-slate-100"
                >
                  <td className="px-2 py-2 text-slate-700">{row.ts ?? "-"}</td>
                  <td className="px-2 py-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        row.status === "completed"
                          ? "bg-emerald-100 text-emerald-700"
                          : row.status === "failed"
                            ? "bg-rose-100 text-rose-700"
                            : "bg-slate-100 text-slate-700"
                      }`}
                    >
                      {row.status ?? "-"}
                    </span>
                  </td>
                  <td className="px-2 py-2">{row.model ?? "-"}</td>
                  <td className="px-2 py-2">{row.pipeline ?? "-"}</td>
                  <td className="px-2 py-2">
                    {fmt(Number(row.duration_seconds ?? 0))}
                  </td>
                  <td className="px-2 py-2">
                    {fmt(Number(row.risk_score ?? 0))}
                  </td>
                  <td className="px-2 py-2">{Number(row.mapped_count ?? 0)}</td>
                  <td className="px-2 py-2">{Number(row.other_count ?? 0)}</td>
                  <td className="px-2 py-2">
                    {Number(row.llm_result_count ?? 0)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </AppFrame>
  );
}
