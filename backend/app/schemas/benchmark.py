from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


BenchmarkDataset = Literal["smartbugs", "solidifi"]
BenchmarkPipeline = Literal["standard", "cascade", "multi_llm"]
BenchmarkMode = Literal["binary", "non_binary", "cot", "multi_vuln"]


class BenchmarkContractPreview(BaseModel):
    name: str
    labels: list[str] = Field(default_factory=list)
    source_preview: str = ""


class BenchmarkLoadResponse(BaseModel):
    dataset: BenchmarkDataset
    loaded: int
    contracts: list[BenchmarkContractPreview] = Field(default_factory=list)
    vuln_types_under_test: list[str] = Field(default_factory=list)


class BenchmarkRunRequest(BaseModel):
    dataset: BenchmarkDataset = "smartbugs"
    limit: int = Field(default=3, ge=1, le=200)
    prefer_shared_db: bool = False

    model: str = "deepseek-v3.2"
    mode: BenchmarkMode = "non_binary"
    temperature: float = 0.0

    pipeline: BenchmarkPipeline = "standard"
    cascade_small: str = "deepseek-v3.2"
    cascade_large: str = "deepseek-v3.2"
    multi_models: list[str] = Field(default_factory=lambda: ["deepseek-v3.2", "gpt-4o-mini"])
    multi_parallel: bool = False
    multi_aggregation: Literal["majority", "consensus"] = "majority"


class BenchmarkRunResponse(BaseModel):
    dataset: BenchmarkDataset
    loaded: int
    vuln_types_under_test: list[str] = Field(default_factory=list)
    scores: dict[str, Any] = Field(default_factory=dict)
    audit_results: list[dict[str, Any]] = Field(default_factory=list)


class BenchmarkLlmCheckResponse(BaseModel):
    ok: bool
    model: str
    latency_ms: int | None = None
    preview: str = ""
    error: str | None = None
