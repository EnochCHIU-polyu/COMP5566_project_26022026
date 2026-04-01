import { useMemo, useState } from "react";

import type { AuditMappingInfo, AuditVulnResult } from "../types";

type IssueFilter = "all" | "issue" | "no-issue";
type EvalLabel = "TP" | "TF" | "FP" | "FF";

interface EvidenceMark {
  auditId: string;
  vulnName: string;
  line: number;
  label: EvalLabel;
}

interface Props {
  summary: string;
  results: AuditVulnResult[];
  mapping?: AuditMappingInfo | null;
  sourceCode: string;
  error: string | null;
  auditId?: string | null;
  model?: string;
  mode?: string;
  pipeline?: string;
}

function extractEvidenceLines(response: string): number[] {
  const lines = new Set<number>();

  for (const m of response.matchAll(/\bL(\d+)(?:\s*[-–]\s*L?(\d+))?/g)) {
    const start = Number(m[1]);
    const end = m[2] ? Number(m[2]) : start;
    for (let n = start; n <= end; n += 1) {
      if (n > 0) lines.add(n);
    }
  }

  for (const m of response.matchAll(/\blines?\s+(\d+)(?:\s*[-–]\s*(\d+))?/gi)) {
    const start = Number(m[1]);
    const end = m[2] ? Number(m[2]) : start;
    for (let n = start; n <= end; n += 1) {
      if (n > 0) lines.add(n);
    }
  }

  return [...lines].sort((a, b) => a - b);
}

function isPositive(response: string): boolean {
  const t = response.trim().toUpperCase();
  return t.startsWith("YES") || t.includes("YES");
}

function buildSnippet(sourceCode: string, evidenceLines: number[]): string {
  const srcLines = sourceCode.split("\n");
  if (!srcLines.length || evidenceLines.length === 0) {
    return "No evidence lines extracted.";
  }

  const view = new Set<number>();
  evidenceLines.forEach((line) => {
    for (
      let n = Math.max(1, line - 1);
      n <= Math.min(srcLines.length, line + 1);
      n += 1
    ) {
      view.add(n);
    }
  });

  const ordered = [...view].sort((a, b) => a - b);
  return ordered
    .map((line) => {
      const marker = evidenceLines.includes(line) ? ">" : " ";
      return `${marker} ${String(line).padStart(4, " ")} | ${srcLines[line - 1]}`;
    })
    .join("\n");
}

function markKey(
  auditId: string | null | undefined,
  vulnName: string,
  line: number,
): string {
  return `${auditId || "no-audit"}::${vulnName}::${line}`;
}

export function FinalResultPanel({
  summary,
  results,
  mapping,
  sourceCode,
  error,
  auditId,
  model,
  mode,
  pipeline,
}: Props) {
  const [issueFilter, setIssueFilter] = useState<IssueFilter>("issue");
  const [markMenuKey, setMarkMenuKey] = useState<string | null>(null);
  const [marks, setMarks] = useState<Record<string, EvidenceMark>>({});

  const filteredResults = useMemo(() => {
    return results.filter((item) => {
      const positive = isPositive(item.response || "");
      if (issueFilter === "issue") return positive;
      if (issueFilter === "no-issue") return !positive;
      return true;
    });
  }, [results, issueFilter]);

  const markCounts = useMemo(() => {
    const counts: Record<EvalLabel, number> = { TP: 0, TF: 0, FP: 0, FF: 0 };
    Object.values(marks)
      .filter((m) => (auditId ? m.auditId === auditId : true))
      .forEach((m) => {
        counts[m.label] += 1;
      });
    return counts;
  }, [marks, auditId]);

  const setLineMark = (
    vulnName: string,
    line: number,
    label: EvalLabel,
  ): void => {
    const key = markKey(auditId, vulnName, line);
    setMarks((prev) => ({
      ...prev,
      [key]: {
        auditId: auditId || "no-audit",
        vulnName,
        line,
        label,
      },
    }));
    setMarkMenuKey(null);
  };

  return (
    <section className="aw-card">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="aw-title text-lg font-semibold text-[#1E293B]">
          Final Result
        </h2>
        <div className="flex flex-wrap gap-2 text-xs">
          {model && <span className="aw-chip">{model}</span>}
          {mode && <span className="aw-chip">{mode}</span>}
          {pipeline && <span className="aw-chip">{pipeline}</span>}
        </div>
      </div>

      {auditId && <p className="aw-subtle mt-2 text-xs">Run ID: {auditId}</p>}

      {error ? (
        <p className="mt-3 rounded-md border border-rose-700/40 bg-rose-950/60 px-3 py-2 text-sm text-rose-200">
          {error}
        </p>
      ) : summary || results.length > 0 ? (
        <div className="mt-3 space-y-3">
          {mapping && (
            <div className="rounded-md border border-slate-200 bg-slate-50 p-2 text-xs text-slate-700">
              <div>
                Mapping summary: mapped findings {mapping.mapped_count},
                not-in-DB {mapping.other_count}
              </div>
              {!!mapping.db_types?.length && (
                <div className="mt-1">
                  DB types audited: {mapping.db_types.join(", ")}
                </div>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-slate-200 bg-slate-50 p-2">
            <div className="flex items-center gap-2 text-sm">
              <label htmlFor="issue-filter" className="text-slate-600">
                Filter:
              </label>
              <select
                id="issue-filter"
                value={issueFilter}
                onChange={(e) => setIssueFilter(e.target.value as IssueFilter)}
                className="rounded border border-slate-300 bg-white px-2 py-1 text-sm"
              >
                <option value="all">All</option>
                <option value="issue">Issue</option>
                <option value="no-issue">No Issue</option>
              </select>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="rounded bg-slate-200 px-2 py-1 text-slate-700">
                TP: {markCounts.TP}
              </span>
              <span className="rounded bg-slate-200 px-2 py-1 text-slate-700">
                TF: {markCounts.TF}
              </span>
              <span className="rounded bg-slate-200 px-2 py-1 text-slate-700">
                FP: {markCounts.FP}
              </span>
              <span className="rounded bg-slate-200 px-2 py-1 text-slate-700">
                FF: {markCounts.FF}
              </span>
            </div>
          </div>

          <pre
            className="max-h-64 overflow-x-auto overflow-y-auto rounded-md border p-3 text-sm text-[#1E293B] whitespace-pre-wrap"
            style={{
              borderColor: "var(--aw-border)",
              background: "var(--aw-surface-soft)",
            }}
          >
            {summary}
          </pre>

          {filteredResults.length > 0 ? (
            <div className="space-y-3">
              {filteredResults.map((item) => {
                const evidenceLines = extractEvidenceLines(item.response || "");
                const positive = isPositive(item.response || "");
                const isOther =
                  item.is_other || item.vuln_name.startsWith("OTHER::");
                const resultMarkKey = markKey(auditId, item.vuln_name, 0);
                const resultMark = marks[resultMarkKey]?.label;
                const isResultMenuOpen = markMenuKey === resultMarkKey;

                return (
                  <article
                    key={item.vuln_name}
                    className="rounded-md border p-3"
                    style={{
                      borderColor: "var(--aw-border)",
                      background: "#fff",
                    }}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h3 className="font-semibold text-[#1E293B]">
                        {item.vuln_name}
                      </h3>
                      <div className="relative flex items-center gap-2">
                        <span
                          className={`rounded-full px-2 py-1 text-xs font-semibold ${
                            positive
                              ? "bg-rose-100 text-rose-700"
                              : "bg-emerald-100 text-emerald-700"
                          }`}
                        >
                          {positive ? "Potential Issue" : "No Clear Issue"}
                        </span>
                        {isOther && (
                          <span className="rounded-full bg-amber-100 px-2 py-1 text-xs font-semibold text-amber-800">
                            Not in DB (OTHER)
                          </span>
                        )}
                        {resultMark && (
                          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-700">
                            {resultMark}
                          </span>
                        )}
                        <button
                          type="button"
                          className="inline-flex items-center gap-1 rounded bg-[#1E293B] px-2 py-1 text-xs font-semibold text-white"
                          onClick={() =>
                            setMarkMenuKey(
                              isResultMenuOpen ? null : resultMarkKey,
                            )
                          }
                          title="Report this result"
                        >
                          <span>Report</span>
                        </button>
                        {isResultMenuOpen && (
                          <div className="absolute right-0 top-8 z-10 flex gap-1 rounded border border-slate-300 bg-white p-1 shadow">
                            {(["TP", "TF", "FP", "FF"] as EvalLabel[]).map(
                              (label) => (
                                <button
                                  key={label}
                                  type="button"
                                  className="rounded border border-slate-300 px-1.5 py-0.5 text-[11px] text-slate-700 hover:bg-slate-100"
                                  onClick={() =>
                                    setLineMark(item.vuln_name, 0, label)
                                  }
                                >
                                  {label}
                                </button>
                              ),
                            )}
                          </div>
                        )}
                      </div>
                    </div>

                    <pre className="mt-2 max-h-44 overflow-auto rounded border border-slate-200 bg-slate-50 p-2 text-xs whitespace-pre-wrap text-[#1E293B]">
                      {item.response}
                    </pre>

                    <p className="mt-2 text-xs text-slate-600">
                      Evidence lines:{" "}
                      {evidenceLines.length ? evidenceLines.join(", ") : "none"}
                    </p>

                    {evidenceLines.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {evidenceLines.map((line) => {
                          const key = markKey(auditId, item.vuln_name, line);
                          const currentMark = marks[key]?.label;

                          return (
                            <div
                              key={line}
                              className="relative flex items-center gap-1 rounded border border-slate-300 bg-white px-2 py-1 text-xs"
                            >
                              <span className="text-slate-700">L{line}</span>
                              {currentMark && (
                                <span className="rounded bg-slate-100 px-1 text-slate-700">
                                  {currentMark}
                                </span>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}

                    <pre className="mt-2 max-h-52 overflow-auto rounded border border-slate-200 bg-slate-950 p-2 text-xs text-slate-100 whitespace-pre">
                      {buildSnippet(sourceCode, evidenceLines)}
                    </pre>
                  </article>
                );
              })}
            </div>
          ) : (
            <p className="text-sm text-slate-500">
              No results match current filter.
            </p>
          )}
        </div>
      ) : (
        <p className="aw-subtle mt-3 text-sm">No final result yet.</p>
      )}
    </section>
  );
}
