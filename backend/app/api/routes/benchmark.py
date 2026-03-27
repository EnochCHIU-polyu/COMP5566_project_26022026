from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.schemas.benchmark import (
    BenchmarkDataset,
    BenchmarkLlmCheckResponse,
    BenchmarkLoadResponse,
    BenchmarkRunRequest,
    BenchmarkRunResponse,
)
from app.services.benchmark_service import benchmark_service

router = APIRouter(prefix="/api/v1/benchmark", tags=["benchmark"])


@router.get("/contracts", response_model=BenchmarkLoadResponse)
async def load_benchmark_contracts(
    dataset: BenchmarkDataset = Query(default="smartbugs"),
    limit: int = Query(default=3, ge=1, le=200),
    prefer_shared_db: bool = Query(default=False),
) -> BenchmarkLoadResponse:
    return await benchmark_service.load_contract_previews(dataset, limit, prefer_shared_db)


@router.get("/llm-check", response_model=BenchmarkLlmCheckResponse)
async def benchmark_llm_check(
    model: str = Query(default="deepseek-v3.2"),
) -> BenchmarkLlmCheckResponse:
    return await benchmark_service.check_llm(model)


@router.post("/run", response_model=BenchmarkRunResponse)
async def run_benchmark(req: BenchmarkRunRequest) -> BenchmarkRunResponse:
    try:
        return await benchmark_service.run_benchmark(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Benchmark run failed: {exc}") from exc
