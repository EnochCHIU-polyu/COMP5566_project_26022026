from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase1_data_pipeline.benchmark_datasets import load_benchmark
from phase1_data_pipeline.contract_preprocessor import preprocess_contract
from phase2_llm_engine.cot_analyzer import (
    analyze_contract,
    analyze_contract_cascade,
    run_multi_llm_audit,
)
from phase2_llm_engine.llm_client import query_llm
from phase4_evaluation.scorer import evaluate_batch

from app.schemas.benchmark import (
    BenchmarkContractPreview,
    BenchmarkLlmCheckResponse,
    BenchmarkLoadResponse,
    BenchmarkRunRequest,
    BenchmarkRunResponse,
)
from app.utils.async_compat import to_thread


class BenchmarkService:
    async def check_llm(self, model: str) -> BenchmarkLlmCheckResponse:
        started = time.perf_counter()
        try:
            messages = [
                {
                    "role": "system",
                    "content": "You are a connectivity check assistant.",
                },
                {
                    "role": "user",
                    "content": "Reply with one short line: LLM connectivity OK",
                },
            ]
            response = await asyncio.wait_for(
                to_thread(query_llm, messages, model, 0.0),
                timeout=30,
            )
            latency_ms = int((time.perf_counter() - started) * 1000)
            return BenchmarkLlmCheckResponse(
                ok=True,
                model=model,
                latency_ms=latency_ms,
                preview=response.strip()[:200],
            )
        except Exception as exc:  # noqa: BLE001
            latency_ms = int((time.perf_counter() - started) * 1000)
            return BenchmarkLlmCheckResponse(
                ok=False,
                model=model,
                latency_ms=latency_ms,
                error=str(exc),
            )

    async def load_contract_previews(
        self,
        dataset: str,
        limit: int,
        prefer_shared_db: bool,
    ) -> BenchmarkLoadResponse:
        contracts = await to_thread(
            load_benchmark,
            dataset,
            prefer_shared_db,
        )
        subset = contracts[:limit]

        previews = [
            BenchmarkContractPreview(
                name=str(c.get("name", "Unknown")),
                labels=[
                    str(lb.get("vuln_type", ""))
                    for lb in (c.get("labels", []) or [])
                    if str(lb.get("vuln_type", "")).strip()
                ],
                source_preview=str(c.get("source_code", ""))[:2000],
            )
            for c in subset
        ]

        vuln_types = sorted(
            {
                str(lb.get("vuln_type", ""))
                for c in subset
                for lb in (c.get("labels", []) or [])
                if str(lb.get("vuln_type", "")).strip()
            }
        )

        return BenchmarkLoadResponse(
            dataset=dataset,
            loaded=len(subset),
            contracts=previews,
            vuln_types_under_test=vuln_types,
        )

    async def run_benchmark(self, req: BenchmarkRunRequest) -> BenchmarkRunResponse:
        if req.mode == "multi_vuln":
            raise ValueError("multi_vuln mode is not supported for benchmark scoring")

        contracts = await to_thread(
            load_benchmark,
            req.dataset,
            req.prefer_shared_db,
        )
        subset = contracts[: req.limit]

        ground_truth = {
            str(c.get("name", "Unknown")): [
                str(lb.get("vuln_type", ""))
                for lb in (c.get("labels", []) or [])
                if str(lb.get("vuln_type", "")).strip()
            ]
            for c in subset
        }

        bench_vulns = sorted({v for vulns in ground_truth.values() for v in vulns})

        # Vulnerability scoring uses ``vuln_filter=bench_vulns``; ``analyze_contract`` /
        # ``analyze_contract_cascade`` (filtered) / ``run_multi_llm_audit`` all resolve types
        # via ``run_batched_vulnerability_audit`` (chunked JSON, ``vuln_name``-keyed parse).

        audit_results: list[dict[str, Any]] = []
        for contract in subset:
            name = str(contract.get("name", "Unknown"))
            raw_source = str(contract.get("source_code", ""))

            try:
                preprocessed = await to_thread(
                    preprocess_contract,
                    raw_source,
                    model=req.model,
                )
                source_code = str(preprocessed.get("source_code", ""))

                if req.pipeline == "cascade":
                    result = await to_thread(
                        analyze_contract_cascade,
                        source_code,
                        name,
                        req.cascade_small,
                        req.cascade_large,
                        req.temperature,
                        False,
                        False,
                        None,
                        bench_vulns,
                        "",
                    )
                elif req.pipeline == "multi_llm":
                    models = req.multi_models or [req.model]
                    result = await to_thread(
                        run_multi_llm_audit,
                        source_code,
                        name,
                        models,
                        req.mode,
                        req.temperature,
                        req.multi_aggregation,
                        None,
                        bench_vulns,
                        False,
                        None,
                        req.multi_parallel,
                        "",
                    )
                else:
                    result = await to_thread(
                        analyze_contract,
                        source_code,
                        name,
                        req.mode,
                        req.model,
                        req.temperature,
                        False,
                        False,
                        None,
                        False,
                        None,
                        bench_vulns,
                        "",
                    )

                audit_results.append(
                    {
                        "contract_name": name,
                        "vuln_results": result.get("vuln_results", []),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                audit_results.append(
                    {
                        "contract_name": name,
                        "vuln_results": [],
                        "error": str(exc),
                    }
                )

        scores = await to_thread(evaluate_batch, audit_results, ground_truth)

        return BenchmarkRunResponse(
            dataset=req.dataset,
            loaded=len(subset),
            vuln_types_under_test=bench_vulns,
            scores=scores,
            audit_results=audit_results,
        )


benchmark_service = BenchmarkService()
