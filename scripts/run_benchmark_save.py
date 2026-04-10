#!/usr/bin/env python3
"""
Run benchmark from project root and write full JSON result to a file.

Progress goes to stderr so you always see activity; final aggregate JSON also on stdout.

Usage (from repo root):
  PYTHONPATH=".:backend" python3 scripts/run_benchmark_save.py -o results/benchmark_run.json
  PYTHONPATH=".:backend" python3 scripts/run_benchmark_save.py -v -o results/out.json  # LLM INFO logs
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.schemas.benchmark import BenchmarkRunRequest  # noqa: E402
from app.services.benchmark_service import benchmark_service  # noqa: E402


def _info(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


async def _run(args: argparse.Namespace) -> None:
    multi_models = [m.strip() for m in args.multi_models.split(",") if m.strip()]
    _info(
        f"[benchmark] 开始: dataset={args.dataset} limit={args.limit} "
        f"pipeline={args.pipeline} model={args.model} multi_models={multi_models}"
    )
    req = BenchmarkRunRequest(
        dataset=args.dataset,
        limit=args.limit,
        prefer_shared_db=args.prefer_shared_db,
        model=args.model,
        mode=args.mode,
        temperature=args.temperature,
        pipeline=args.pipeline,
        cascade_small=args.cascade_small,
        cascade_large=args.cascade_large,
        multi_models=multi_models,
        multi_parallel=args.multi_parallel,
        multi_aggregation=args.multi_aggregation,
    )
    _info("[benchmark] 正在跑 LLM（可能较久，期间可能无新行）…")
    t0 = time.perf_counter()
    resp = await benchmark_service.run_benchmark(req)
    _info(f"[benchmark] LLM 与计分完成，耗时 {time.perf_counter() - t0:.1f}s")

    payload = resp.model_dump()
    out_path = Path(args.output).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    nbytes = out_path.stat().st_size
    _info(f"[benchmark] 已写入: {out_path.resolve()} ({nbytes} bytes)")

    agg = payload.get("scores", {}).get("aggregate", {})
    counts = agg.get("counts", {})
    _info(f"[benchmark] aggregate counts TP/FP/TN/FN: {counts}")
    _info("[benchmark] 下面 stdout 为 aggregate 摘要 JSON；完整结果见上述文件")
    print(json.dumps(agg, ensure_ascii=False, indent=2), flush=True)


def main() -> None:
    p = argparse.ArgumentParser(description="Run benchmark and save JSON result.")
    p.add_argument("--dataset", default="smartbugs", choices=["smartbugs", "solidifi"])
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--output", "-o", default="benchmark_result.json")
    p.add_argument(
        "--pipeline",
        default="multi_llm",
        choices=["standard", "cascade", "multi_llm"],
    )
    p.add_argument("--model", default="deepseek-v3.2")
    p.add_argument(
        "--mode",
        default="non_binary",
        choices=["binary", "non_binary", "cot"],
        help="multi_vuln is not supported by benchmark scoring",
    )
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--multi-models", default="deepseek-v3.2,gpt-4o", help="Comma-separated; used when pipeline=multi_llm")
    p.add_argument("--multi-parallel", action="store_true")
    p.add_argument("--multi-aggregation", default="majority", choices=["majority", "consensus"])
    p.add_argument("--cascade-small", default="deepseek-v3.2")
    p.add_argument("--cascade-large", default="gpt-4o")
    p.add_argument("--prefer-shared-db", action="store_true")
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="打印 phase2/app 的 INFO 日志（含每次 LLM 请求）到 stderr",
    )
    args = p.parse_args()
    if args.verbose:
        logging.basicConfig(
            level=logging.INFO,
            format="%(levelname)s %(name)s: %(message)s",
            stream=sys.stderr,
        )
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        _info("[benchmark] 已中断（KeyboardInterrupt）")
        raise SystemExit(130) from None
    except Exception as exc:  # noqa: BLE001
        _info(f"[benchmark] 失败: {exc}")
        raise


if __name__ == "__main__":
    main()
