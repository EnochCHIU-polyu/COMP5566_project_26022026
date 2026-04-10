from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


BenchmarkDataset = Literal["smartbugs", "solidifi"]
BenchmarkPipeline = Literal["standard", "multi_llm"]
BenchmarkMode = Literal["binary", "non_binary", "cot", "multi_vuln"]


class BenchmarkContractPreview(BaseModel):
    name: str
    labels: List[str] = Field(default_factory=list)
    source_preview: str = ""


class BenchmarkLoadResponse(BaseModel):
    dataset: BenchmarkDataset
    loaded: int
    contracts: List[BenchmarkContractPreview] = Field(default_factory=list)
    vuln_types_under_test: List[str] = Field(default_factory=list)


class BenchmarkRunRequest(BaseModel):
    dataset: BenchmarkDataset = "smartbugs"
    limit: int = Field(default=3, ge=1, le=200)
    prefer_shared_db: bool = False

    model: str = "deepseek-v3.2"
    mode: BenchmarkMode = "non_binary"

    pipeline: BenchmarkPipeline = "standard"
    multi_models: List[str] = Field(default_factory=lambda: ["deepseek-v3.2", "gpt-4o-mini"])
    multi_parallel: bool = False
    multi_aggregation: Literal["majority", "consensus"] = "majority"


class BenchmarkRunResponse(BaseModel):
    dataset: BenchmarkDataset
    loaded: int
    vuln_types_under_test: List[str] = Field(default_factory=list)
    scores: Dict[str, Any] = Field(default_factory=dict)
    audit_results: List[Dict[str, Any]] = Field(default_factory=list)


class BenchmarkLlmCheckResponse(BaseModel):
    ok: bool
    model: str
    latency_ms: Optional[int] = None
    preview: str = ""
    error: Optional[str] = None
