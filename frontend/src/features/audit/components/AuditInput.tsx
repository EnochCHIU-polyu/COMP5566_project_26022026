import { useEffect, useState } from "react";
import type { AuditCreateInput } from "../types";
import { getVulnerabilityCatalog } from "../services/auditApi";

interface Props {
  onSubmit: (input: AuditCreateInput) => void;
  disabled?: boolean;
}

export function AuditInput({ onSubmit, disabled = false }: Props) {
  const [contractName, setContractName] = useState("SampleContract");
  const [model, setModel] = useState("deepseek-v3.2");
  const [mode, setMode] = useState("non_binary");
  const [pipeline, setPipeline] = useState("standard");
  const [batchSize, setBatchSize] = useState(8);
  const [maxBatchSize, setMaxBatchSize] = useState(38);
  const [sourceCode, setSourceCode] = useState(
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n",
  );

  useEffect(() => {
    let mounted = true;

    getVulnerabilityCatalog()
      .then((catalog) => {
        if (!mounted) return;
        const nextMax = Math.max(1, Number(catalog.count) || 1);
        setMaxBatchSize(nextMax);
        setBatchSize((prev) => Math.min(prev, nextMax));
      })
      .catch(() => {
        // Keep default fallback when backend catalog endpoint is unavailable.
      });

    return () => {
      mounted = false;
    };
  }, []);

  const submit = () => {
    onSubmit({
      contract_name: contractName,
      source_code: sourceCode,
      model,
      mode,
      pipeline,
      batch_size: batchSize,
    });
  };

  return (
    <section className="aw-card">
      <div className="flex items-center justify-between">
        <h2 className="aw-title text-lg font-semibold">Audit Setup</h2>
        <span className="aw-chip aw-chip-accent rounded-full px-3">
          Slither → LLM
        </span>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
        <input
          className="aw-input"
          value={contractName}
          onChange={(e) => setContractName(e.target.value)}
          placeholder="Contract name"
        />
        <select
          className="aw-input"
          value={model}
          onChange={(e) => setModel(e.target.value)}
        >
          <option value="deepseek-v3.2">deepseek-v3.2</option>
          <option value="gpt-4o-mini">gpt-4o-mini</option>
          <option value="gpt-4o">gpt-4o</option>
        </select>
        <select
          className="aw-input"
          value={mode}
          onChange={(e) => setMode(e.target.value)}
        >
          <option value="binary">binary</option>
          <option value="non_binary">non_binary</option>
          <option value="cot">cot</option>
          <option value="multi_vuln">multi_vuln</option>
        </select>
        <select
          className="aw-input"
          value={pipeline}
          onChange={(e) => setPipeline(e.target.value)}
        >
          <option value="standard">standard</option>
          <option value="cascade">cascade</option>
          <option value="multi_llm">multi_llm</option>
        </select>
      </div>

      <div className="mt-4 space-y-3">
        <textarea
          className="aw-input h-64 font-mono"
          value={sourceCode}
          onChange={(e) => setSourceCode(e.target.value)}
          placeholder="Paste Solidity source"
        />
        <button
          type="button"
          disabled={disabled || !sourceCode.trim()}
          onClick={submit}
          className="aw-button"
        >
          Run Audit
        </button>
      </div>
    </section>
  );
}
