import { useEffect, useMemo, useState } from "react";

import { AppFrame } from "../components/AppFrame";
import {
  checkBackendHealth,
  checkBenchmarkLlm,
  loadBenchmarkContracts,
  runBenchmark,
  type BenchmarkContractPreview,
  type BenchmarkDataset,
  type BenchmarkMode,
  type BenchmarkPipeline,
  type BenchmarkRunResponse,
} from "../features/benchmark/services/benchmarkApi";

const KNOWN_MODELS = ["deepseek-v3.2", "gpt-4o", "gpt-4o-mini"];

export function BenchmarkPage() {
  const [dataset, setDataset] = useState<BenchmarkDataset>("smartbugs");
  const [limit, setLimit] = useState(3);
  const [preferSharedDb, setPreferSharedDb] = useState(false);

  const [pipeline, setPipeline] = useState<BenchmarkPipeline>("standard");
  const [mode, setMode] = useState<BenchmarkMode>("non_binary");
  const [model, setModel] = useState("deepseek-v3.2");

  const [cascadeSmall, setCascadeSmall] = useState("deepseek-v3.2");
  const [cascadeLarge, setCascadeLarge] = useState("deepseek-v3.2");
  const [multiModelsCsv, setMultiModelsCsv] = useState(
    "deepseek-v3.2,gpt-4o-mini",
  );
  const [multiParallel, setMultiParallel] = useState(false);
  const [multiAggregation, setMultiAggregation] = useState<
    "majority" | "consensus"
  >("majority");

  const [contracts, setContracts] = useState<BenchmarkContractPreview[]>([]);
  const [vulnTypes, setVulnTypes] = useState<string[]>([]);
  const [runResult, setRunResult] = useState<BenchmarkRunResponse | null>(null);

  const [isLoadingContracts, setIsLoadingContracts] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [elapsedSec, setElapsedSec] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [backendDiag, setBackendDiag] = useState<string>("unknown");
  const [llmDiag, setLlmDiag] = useState<string>("unknown");
  const [diagBusy, setDiagBusy] = useState<"none" | "backend" | "llm">("none");

  const multiModels = useMemo(
    () =>
      multiModelsCsv
        .split(",")
        .map((m) => m.trim())
        .filter(Boolean),
    [multiModelsCsv],
  );

  const aggregateCounts = runResult?.scores?.aggregate?.counts ?? {};
  const aggregateMetrics = runResult?.scores?.aggregate?.metrics ?? {};
  const skipped = runResult?.scores?.aggregate?.skipped_unparseable ?? 0;

  const runDisabled = contracts.length === 0 || isRunning;

  useEffect(() => {
    if (!isRunning) {
      setElapsedSec(0);
      return;
    }

    const timer = window.setInterval(() => {
      setElapsedSec((prev) => prev + 1);
    }, 1000);

    return () => window.clearInterval(timer);
  }, [isRunning]);

  const onLoadContracts = async () => {
    setError(null);
    setRunResult(null);
    setIsLoadingContracts(true);

    try {
      const data = await loadBenchmarkContracts(dataset, limit, preferSharedDb);
      setContracts(data.contracts);
      setVulnTypes(data.vuln_types_under_test);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load benchmark");
    } finally {
      setIsLoadingContracts(false);
    }
  };

  const onRunBenchmark = async () => {
    setError(null);
    setIsRunning(true);

    try {
      const result = await runBenchmark({
        dataset,
        limit,
        prefer_shared_db: preferSharedDb,
        model,
        mode,
        pipeline,
        cascade_small: cascadeSmall,
        cascade_large: cascadeLarge,
        multi_models: multiModels,
        multi_parallel: multiParallel,
        multi_aggregation: multiAggregation,
      });
      setRunResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run benchmark");
    } finally {
      setIsRunning(false);
    }
  };

  const onCheckBackend = async () => {
    setDiagBusy("backend");
    try {
      const health = await checkBackendHealth();
      setBackendDiag(`ok (${health.status})`);
    } catch (err) {
      setBackendDiag(err instanceof Error ? err.message : String(err));
    } finally {
      setDiagBusy("none");
    }
  };

  const onCheckLlm = async () => {
    setDiagBusy("llm");
    try {
      const check = await checkBenchmarkLlm(model);
      if (check.ok) {
        const latency = check.latency_ms ?? 0;
        setLlmDiag(
          `ok (${latency} ms): ${check.preview || "response received"}`,
        );
      } else {
        setLlmDiag(`failed: ${check.error || "unknown"}`);
      }
    } catch (err) {
      setLlmDiag(err instanceof Error ? err.message : String(err));
    } finally {
      setDiagBusy("none");
    }
  };

  return (
    <AppFrame>
      <div className="space-y-4">
        <header className="aw-card">
          <h1 className="aw-title text-2xl font-bold tracking-tight">
            Benchmark
          </h1>
          <p className="aw-subtle mt-1 text-sm">
            Uses benchmark dataset ground truth to evaluate audit results with
            TP, FP, TN, FN, precision, recall, and F1.
          </p>
        </header>

        <section className="aw-card space-y-4">
          <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-[#1E293B]">
                Diagnostics
              </span>
              <button
                type="button"
                className="rounded-md border border-slate-300 px-3 py-1 text-xs"
                onClick={onCheckBackend}
                disabled={diagBusy !== "none"}
              >
                {diagBusy === "backend"
                  ? "Checking backend..."
                  : "Check Backend"}
              </button>
              <button
                type="button"
                className="rounded-md border border-slate-300 px-3 py-1 text-xs"
                onClick={onCheckLlm}
                disabled={diagBusy !== "none"}
              >
                {diagBusy === "llm" ? "Checking LLM..." : "Check LLM"}
              </button>
              {isRunning && (
                <span className="rounded bg-amber-100 px-2 py-1 text-xs text-amber-800">
                  Benchmark running for {elapsedSec}s
                </span>
              )}
            </div>
            <p className="aw-subtle mt-2 text-xs">Backend: {backendDiag}</p>
            <p className="aw-subtle mt-1 text-xs">LLM: {llmDiag}</p>
          </div>

          <div className="grid gap-3 md:grid-cols-4">
            <label className="text-sm aw-subtle">
              Dataset
              <select
                className="aw-input mt-1"
                value={dataset}
                onChange={(e) => setDataset(e.target.value as BenchmarkDataset)}
              >
                <option value="smartbugs">smartbugs</option>
                <option value="solidifi">solidifi</option>
              </select>
            </label>

            <label className="text-sm aw-subtle">
              Limit
              <input
                className="aw-input mt-1"
                type="number"
                min={1}
                max={200}
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value || 1))}
              />
            </label>

            <label className="text-sm aw-subtle">
              Mode
              <select
                className="aw-input mt-1"
                value={mode}
                onChange={(e) => setMode(e.target.value as BenchmarkMode)}
              >
                <option value="binary">binary</option>
                <option value="non_binary">non_binary</option>
                <option value="cot">cot</option>
              </select>
            </label>

            <label className="text-sm aw-subtle">
              Pipeline
              <select
                className="aw-input mt-1"
                value={pipeline}
                onChange={(e) =>
                  setPipeline(e.target.value as BenchmarkPipeline)
                }
              >
                <option value="standard">standard</option>
                <option value="cascade">cascade</option>
                <option value="multi_llm">multi_llm</option>
              </select>
            </label>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <label className="text-sm aw-subtle">
              Model
              <select
                className="aw-input mt-1"
                value={model}
                onChange={(e) => setModel(e.target.value)}
              >
                {KNOWN_MODELS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>

            <label className="text-sm aw-subtle flex items-center gap-2 pt-7">
              <input
                type="checkbox"
                checked={preferSharedDb}
                onChange={(e) => setPreferSharedDb(e.target.checked)}
              />
              Prefer shared Supabase dataset
            </label>
          </div>

          {pipeline === "cascade" && (
            <div className="grid gap-3 md:grid-cols-2">
              <label className="text-sm aw-subtle">
                Cascade small model
                <select
                  className="aw-input mt-1"
                  value={cascadeSmall}
                  onChange={(e) => setCascadeSmall(e.target.value)}
                >
                  {KNOWN_MODELS.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-sm aw-subtle">
                Cascade large model
                <select
                  className="aw-input mt-1"
                  value={cascadeLarge}
                  onChange={(e) => setCascadeLarge(e.target.value)}
                >
                  {KNOWN_MODELS.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}

          {pipeline === "multi_llm" && (
            <div className="grid gap-3 md:grid-cols-3">
              <label className="text-sm aw-subtle md:col-span-2">
                Multi models (comma separated)
                <input
                  className="aw-input mt-1"
                  value={multiModelsCsv}
                  onChange={(e) => setMultiModelsCsv(e.target.value)}
                  placeholder="deepseek-v3.2,gpt-4o-mini"
                />
              </label>

              <label className="text-sm aw-subtle">
                Aggregation
                <select
                  className="aw-input mt-1"
                  value={multiAggregation}
                  onChange={(e) =>
                    setMultiAggregation(
                      e.target.value as "majority" | "consensus",
                    )
                  }
                >
                  <option value="majority">majority</option>
                  <option value="consensus">consensus</option>
                </select>
              </label>

              <label className="text-sm aw-subtle flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={multiParallel}
                  onChange={(e) => setMultiParallel(e.target.checked)}
                />
                Run models in parallel
              </label>
            </div>
          )}

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              className="aw-button w-auto px-4"
              onClick={onLoadContracts}
              disabled={isLoadingContracts}
            >
              {isLoadingContracts ? "Loading..." : "Load Benchmark"}
            </button>
            <button
              type="button"
              className="rounded-md border border-slate-300 px-4 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-50"
              onClick={onRunBenchmark}
              disabled={runDisabled}
            >
              {isRunning ? "Running..." : "Run Benchmark Audit"}
            </button>
          </div>

          {error && (
            <p className="rounded-md border border-rose-300 bg-rose-50 px-3 py-2 text-sm text-rose-700">
              {error}
            </p>
          )}
        </section>

        {contracts.length > 0 && (
          <section className="aw-card space-y-3">
            <h2 className="aw-title text-lg font-semibold">
              Loaded Contracts ({contracts.length})
            </h2>
            <p className="aw-subtle text-sm">
              Vulnerability types under test: {vulnTypes.join(", ") || "none"}
            </p>
            <div className="space-y-2">
              {contracts.map((c) => (
                <article
                  key={c.name}
                  className="rounded-md border border-slate-200 bg-slate-50 p-3"
                >
                  <h3 className="font-semibold text-[#1E293B]">{c.name}</h3>
                  <p className="aw-subtle mt-1 text-xs">
                    Labels: {c.labels.join(", ") || "none"}
                  </p>
                  <pre className="mt-2 max-h-28 overflow-auto rounded border border-slate-200 bg-white p-2 text-xs whitespace-pre-wrap">
                    {c.source_preview}
                  </pre>
                </article>
              ))}
            </div>
          </section>
        )}

        <section className="aw-card">
          <h2 className="aw-title text-lg font-semibold">Aggregate Metrics</h2>
          <div className="mt-3 grid gap-3 grid-cols-2 md:grid-cols-4">
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm">
              TP: {aggregateCounts.TP ?? 0}
            </div>
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm">
              FP: {aggregateCounts.FP ?? 0}
            </div>
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm">
              TN: {aggregateCounts.TN ?? 0}
            </div>
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm">
              FN: {aggregateCounts.FN ?? 0}
            </div>
          </div>

          <div className="mt-3 grid gap-3 grid-cols-2 md:grid-cols-4">
            <div className="rounded-md border border-slate-200 bg-white p-3 text-sm">
              F1: {(aggregateMetrics.f1 ?? 0).toFixed(4)}
            </div>
            <div className="rounded-md border border-slate-200 bg-white p-3 text-sm">
              Precision: {(aggregateMetrics.precision ?? 0).toFixed(4)}
            </div>
            <div className="rounded-md border border-slate-200 bg-white p-3 text-sm">
              Recall: {(aggregateMetrics.recall ?? 0).toFixed(4)}
            </div>
            <div className="rounded-md border border-slate-200 bg-white p-3 text-sm">
              Accuracy: {(aggregateMetrics.accuracy ?? 0).toFixed(4)}
            </div>
          </div>

          <p className="aw-subtle mt-3 text-xs">
            Skipped unparseable responses: {skipped}
          </p>
        </section>

        {runResult?.scores?.per_contract &&
          runResult.scores.per_contract.length > 0 && (
            <section className="aw-card">
              <h2 className="aw-title text-lg font-semibold">Per Contract</h2>
              <div className="mt-3 overflow-auto">
                <table className="w-full border-collapse text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-left">
                      <th className="px-2 py-2">Contract</th>
                      <th className="px-2 py-2">TP</th>
                      <th className="px-2 py-2">FP</th>
                      <th className="px-2 py-2">TN</th>
                      <th className="px-2 py-2">FN</th>
                      <th className="px-2 py-2">F1</th>
                      <th className="px-2 py-2">Skipped</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runResult.scores.per_contract.map((row) => (
                      <tr
                        key={row.contract_name}
                        className="border-b border-slate-100"
                      >
                        <td className="px-2 py-2 font-medium">
                          {row.contract_name}
                        </td>
                        <td className="px-2 py-2">{row.counts?.TP ?? 0}</td>
                        <td className="px-2 py-2">{row.counts?.FP ?? 0}</td>
                        <td className="px-2 py-2">{row.counts?.TN ?? 0}</td>
                        <td className="px-2 py-2">{row.counts?.FN ?? 0}</td>
                        <td className="px-2 py-2">
                          {(row.metrics?.f1 ?? 0).toFixed(4)}
                        </td>
                        <td className="px-2 py-2">
                          {row.skipped_unparseable ?? 0}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
      </div>
    </AppFrame>
  );
}
