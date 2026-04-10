"""
data_pipeline.batch_fetcher
============================
Batch Etherscan ingestor — reads a list of contract addresses from a CSV file,
fetches their verified source code via the Etherscan API at a controlled rate,
flattens multi-file Solidity responses into single ``.sol`` files, saves them
into a timestamped output directory, and maintains a ``manifest.json`` tracking
the fetch status of every address.

Design goals
------------
* **Rate limiting** — the Etherscan free-tier allows 5 API calls per second.
  A token-bucket rate limiter enforces this without `time.sleep` busy-waiting
  for the full 0.2s between every call.
* **Error resilience** — transient HTTP errors and non-verified contracts are
  recorded in the manifest rather than crashing the whole batch.
* **Resumable runs** — if a manifest already exists in the output directory,
  addresses already marked ``success`` are skipped automatically.
* **Flattening** — Etherscan's ``getsourcecode`` returns Solidity source in two
  forms:
    1. A plain string (single-file or already-flattened contract).
    2. A JSON-encoded object with a ``"sources"`` key (Hardhat/Truffle
       multi-source format, identified by the leading ``{{``).
  The flattener reassembles these into a single ``.sol`` file with comment
  banners separating each source unit.

CSV format
----------
The input CSV must have at minimum one column named ``address``.  Additional
columns (e.g. ``label``, ``note``) are preserved in the manifest.

    address,label
    0xdAC17F958D2ee523a2206206994597C13D831ec7,USDT
    0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D,UniswapV2Router

Usage
-----
    # Batch-fetch all addresses in the default CSV:
    python -m data_pipeline.batch_fetcher

    # Custom CSV, output dir, and rate limit:
    python -m data_pipeline.batch_fetcher \\
        --input data/input_addresses.csv \\
        --output-base data/raw/batch_audit \\
        --rate 5

    # Dry-run (validate CSV and skip API calls):
    python -m data_pipeline.batch_fetcher --dry-run

Requirements
------------
    pip install requests>=2.28.0 pandas>=2.0.0 python-dotenv>=1.0.0
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import requests

from config import DATA_DIR, ETHERSCAN_API_KEY

logger = logging.getLogger("batch_fetcher")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_INPUT_CSV = _PROJECT_ROOT / "data" / "input_addresses.csv"
_DEFAULT_OUTPUT_BASE = _PROJECT_ROOT / "data" / "raw" / "batch_audit"

# ---------------------------------------------------------------------------
# Etherscan constants
# ---------------------------------------------------------------------------

ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"
_NOT_VERIFIED_MSG = "Contract source code not verified"


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------


class _TokenBucket:
    """
    Thread-safe token-bucket rate limiter.

    Allows up to ``rate`` tokens per second.  Each ``acquire()`` call blocks
    until a token is available, ensuring we never exceed the configured rate.
    """

    def __init__(self, rate: float) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be positive; got {rate!r}")
        self._rate = rate          # tokens per second
        self._tokens = rate        # start full
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until one token is available, then consume it."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_for = (1.0 - self._tokens) / self._rate
            time.sleep(wait_for)


# ---------------------------------------------------------------------------
# Etherscan helpers
# ---------------------------------------------------------------------------


def _fetch_source(address: str, api_key: str, timeout: int = 30) -> dict[str, Any]:
    """
    Call Etherscan ``getsourcecode`` for *address*.

    Returns
    -------
    dict
        The first element of ``result[]`` from the Etherscan response, or an
        empty dict on API error / non-verified contract.  The caller can
        detect non-verification by checking ``result["SourceCode"] == ""``.
    """
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }
    resp = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    if data.get("status") != "1" or not data.get("result"):
        # Etherscan always sets message="NOTOK" on errors; the *result* field
        # carries the human-readable reason (e.g. "Contract source code not
        # verified", "Missing/Invalid API Key").  Prefer result over message.
        raw_result = data.get("result")
        result_str = str(raw_result) if isinstance(raw_result, str) and raw_result else ""
        msg = result_str or data.get("message") or "unknown API error"
        return {"_error": msg}

    return data["result"][0]


# ---------------------------------------------------------------------------
# Multi-file flattener
# ---------------------------------------------------------------------------


def _flatten_source(raw_source: str, contract_name: str = "") -> str:
    """
    Convert an Etherscan source-code payload to a single Solidity string.

    Etherscan stores multi-file projects as a JSON object embedded inside
    an *extra* pair of curly braces (``{{...}}``).  The inner JSON has a
    ``"sources"`` key mapping file paths to ``{"content": "..."}`` objects.

    If the payload is a plain Solidity string it is returned as-is.

    Parameters
    ----------
    raw_source : str
        The ``SourceCode`` field from the Etherscan API response.
    contract_name : str
        Used only in the file-level comment banners.

    Returns
    -------
    str
        A single ``.sol`` file containing all source units in dependency order
        (alphabetical by path as a reasonable approximation).
    """
    raw_source = (raw_source or "").strip()

    # Multi-file detection: Etherscan wraps the inner JSON with an extra {{ }}
    if raw_source.startswith("{{"):
        # Strip the outer extra braces to get valid JSON
        inner = raw_source[1:-1].strip()
        try:
            parsed = json.loads(inner)
        except json.JSONDecodeError:
            # Malformed; fall through to plain-string handling
            logger.warning(
                "Could not parse multi-file JSON for '%s'; treating as plain source.",
                contract_name,
            )
            return raw_source

        sources: dict[str, Any] = parsed.get("sources", {})
        if not sources:
            # Some responses use a top-level ``language`` / ``settings`` object
            # without a ``sources`` key — extract any content we can find.
            return _extract_content_values(parsed) or raw_source

        parts: list[str] = []
        for file_path in sorted(sources.keys()):
            content = sources[file_path].get("content", "")
            parts.append(
                f"// ── Source: {file_path} ─────────────────────────────\n"
                + content
            )
        return "\n\n".join(parts)

    # Standard JSON (no double-brace wrapping) — less common but possible
    if raw_source.startswith("{"):
        try:
            parsed = json.loads(raw_source)
            sources = parsed.get("sources", {})
            if sources:
                parts = []
                for file_path in sorted(sources.keys()):
                    content = sources[file_path].get("content", "")
                    parts.append(
                        f"// ── Source: {file_path} ─────────────────────────────\n"
                        + content
                    )
                return "\n\n".join(parts)
        except json.JSONDecodeError:
            pass

    # Plain single-file Solidity — return unchanged
    return raw_source


def _extract_content_values(obj: Any, depth: int = 0) -> str:
    """Recursively harvest ``content`` string values from a nested dict."""
    if depth > 5:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        if "content" in obj and isinstance(obj["content"], str):
            return obj["content"]
        return "\n\n".join(
            _extract_content_values(v, depth + 1)
            for v in obj.values()
            if isinstance(v, (str, dict))
        )
    return ""


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    """Load an existing manifest, returning empty structure if missing."""
    if manifest_path.exists():
        try:
            with manifest_path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load manifest at %s: %s", manifest_path, exc)
    return {"created_at": "", "entries": {}}


def _save_manifest(manifest: dict[str, Any], manifest_path: Path) -> None:
    """Atomically write the manifest JSON."""
    tmp = manifest_path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    tmp.replace(manifest_path)


# ---------------------------------------------------------------------------
# Address-level processing
# ---------------------------------------------------------------------------


def _process_address(
    address: str,
    extra_fields: dict[str, str],
    output_dir: Path,
    api_key: str,
    limiter: _TokenBucket,
    dry_run: bool,
) -> dict[str, Any]:
    """
    Fetch, flatten, and save a single contract.

    Returns a manifest entry dict describing the result.
    """
    entry: dict[str, Any] = {
        "address": address,
        "status": "pending",
        "filename": None,
        "contract_name": None,
        "compiler_version": None,
        "error": None,
        "fetched_at": None,
        **extra_fields,
    }

    if dry_run:
        entry["status"] = "dry_run"
        return entry

    limiter.acquire()

    try:
        result = _fetch_source(address, api_key)
    except requests.Timeout:
        entry["status"] = "error"
        entry["error"] = "timeout"
        logger.warning("[%s] Timeout", address)
        return entry
    except requests.RequestException as exc:
        entry["status"] = "error"
        entry["error"] = f"http_error: {exc}"
        logger.warning("[%s] HTTP error: %s", address, exc)
        return entry

    entry["fetched_at"] = datetime.now(timezone.utc).isoformat()

    if "_error" in result:
        error_msg = result["_error"]
        # Classify "Contract source code not verified" separately so the caller
        # knows this is expected (unverified contract), not an API misconfiguration.
        if "not verified" in error_msg.lower() or "source code not verified" in error_msg.lower():
            entry["status"] = "not_verified"
            entry["error"] = error_msg
            logger.info("[%s] Not verified: %s", address, error_msg)
        else:
            entry["status"] = "api_error"
            entry["error"] = error_msg
            logger.warning("[%s] API error: %s", address, error_msg)
        return entry

    source_code = result.get("SourceCode", "")
    if not source_code or source_code.strip() == "":
        entry["status"] = "not_verified"
        entry["error"] = _NOT_VERIFIED_MSG
        logger.info("[%s] Not verified", address)
        return entry

    contract_name = result.get("ContractName", "") or f"Contract_{address[:8]}"
    compiler_version = result.get("CompilerVersion", "unknown")

    # Flatten multi-file source into a single .sol
    flat_source = _flatten_source(source_code, contract_name)

    # Safe filename: address without 0x prefix, first 20 hex chars
    addr_stem = re.sub(r"[^0-9a-fA-F]", "", address.removeprefix("0x"))[:20]
    filename = f"{addr_stem}_{contract_name[:40]}.sol"
    sol_path = output_dir / filename

    # Avoid collisions (same address, different run)
    suffix = 0
    while sol_path.exists():
        suffix += 1
        sol_path = output_dir / f"{addr_stem}_{contract_name[:40]}_{suffix}.sol"
        filename = sol_path.name

    sol_path.write_text(flat_source, encoding="utf-8")
    logger.info("[%s] Saved → %s", address, filename)

    entry["status"] = "success"
    entry["filename"] = filename
    entry["contract_name"] = contract_name
    entry["compiler_version"] = compiler_version
    return entry


# ---------------------------------------------------------------------------
# Main batch pipeline
# ---------------------------------------------------------------------------


def run_batch(
    input_csv: str | Path = _DEFAULT_INPUT_CSV,
    output_base: str | Path = _DEFAULT_OUTPUT_BASE,
    api_key: str = "",
    rate: float = 5.0,
    dry_run: bool = False,
    batch_tag: str = "",
) -> dict[str, Any]:
    """
    Run the full batch-fetch pipeline.

    Parameters
    ----------
    input_csv : str | Path
        CSV file with at least an ``address`` column.
    output_base : str | Path
        Parent directory; a timestamped sub-directory is created for each run.
    api_key : str
        Etherscan API key.  Defaults to ``ETHERSCAN_API_KEY`` from environment.
    rate : float
        Maximum API calls per second (Etherscan free tier: 5).
    dry_run : bool
        If True, validate the CSV and simulate the run without calling APIs.
    batch_tag : str
        Optional label appended to the timestamped directory name.

    Returns
    -------
    dict
        Summary with keys ``output_dir``, ``manifest_file``, ``total``,
        ``success``, ``not_verified``, ``error``, ``skipped``.
    """
    input_csv = Path(input_csv)
    output_base = Path(output_base)

    if not api_key:
        api_key = ETHERSCAN_API_KEY
    if not api_key and not dry_run:
        raise ValueError(
            "Etherscan API key is required.  Set ETHERSCAN_API_KEY in .env "
            "or pass --api-key on the command line."
        )

    # ── Read the CSV ─────────────────────────────────────────────────────────
    if not input_csv.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    df = pd.read_csv(input_csv, dtype=str).fillna("")
    if "address" not in df.columns:
        raise ValueError(
            f"CSV must have an 'address' column; found: {list(df.columns)}"
        )

    extra_cols = [c for c in df.columns if c != "address"]
    logger.info("Loaded %d addresses from %s", len(df), input_csv)

    # ── Create timestamped output directory ──────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dir_name = f"{ts}_{batch_tag}" if batch_tag else ts
    output_dir = output_base / dir_name
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = output_dir / "manifest.json"
    manifest = _load_manifest(manifest_path)
    if not manifest["created_at"]:
        manifest["created_at"] = datetime.now(timezone.utc).isoformat()

    # ── Rate limiter ─────────────────────────────────────────────────────────
    limiter = _TokenBucket(rate)

    # ── Process each address ─────────────────────────────────────────────────
    stats = {"success": 0, "not_verified": 0, "error": 0, "api_error": 0, "skipped": 0}

    for _, row in df.iterrows():
        address = str(row["address"]).strip()
        if not address:
            continue

        extra_fields = {col: str(row[col]) for col in extra_cols}

        # Resume: skip already-successful addresses
        existing = manifest["entries"].get(address, {})
        if existing.get("status") == "success":
            logger.debug("[%s] Already fetched — skipping", address)
            stats["skipped"] += 1
            continue

        entry = _process_address(
            address=address,
            extra_fields=extra_fields,
            output_dir=output_dir,
            api_key=api_key,
            limiter=limiter,
            dry_run=dry_run,
        )
        manifest["entries"][address] = entry

        status = entry["status"]
        if status in stats:
            stats[status] += 1
        else:
            stats["error"] += 1  # unknown status bucket

        # Flush manifest after each address so a crash loses minimal progress
        _save_manifest(manifest, manifest_path)

    total = len(df)
    summary = {
        "output_dir": str(output_dir.resolve()),
        "manifest_file": str(manifest_path.resolve()),
        "total": total,
        **stats,
    }
    logger.info(
        "Batch complete. total=%d success=%d not_verified=%d error=%d skipped=%d",
        total, stats["success"], stats["not_verified"],
        stats.get("error", 0) + stats.get("api_error", 0), stats["skipped"],
    )
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="batch_fetcher",
        description=(
            "Batch-fetch verified Solidity source code from Etherscan for a "
            "list of contract addresses."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--input",
        default=str(_DEFAULT_INPUT_CSV),
        metavar="CSV",
        help="CSV file with an 'address' column.",
    )
    parser.add_argument(
        "--output-base",
        default=str(_DEFAULT_OUTPUT_BASE),
        metavar="DIR",
        help="Base directory; a timestamped sub-directory is created per run.",
    )
    parser.add_argument(
        "--api-key",
        default="",
        metavar="KEY",
        help="Etherscan API key (overrides ETHERSCAN_API_KEY env var).",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=5.0,
        metavar="N",
        help="API calls per second (Etherscan free tier: 5).",
    )
    parser.add_argument(
        "--batch-tag",
        default="",
        metavar="TAG",
        help="Optional label appended to the timestamped output directory.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate CSV and simulate without making API calls.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO,
        stream=sys.stdout,
    )

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    summary = run_batch(
        input_csv=args.input,
        output_base=args.output_base,
        api_key=args.api_key,
        rate=args.rate,
        dry_run=args.dry_run,
        batch_tag=args.batch_tag,
    )

    print("\n=== Batch Fetcher Summary ===")
    print(f"  Output dir    : {summary['output_dir']}")
    print(f"  Manifest      : {summary['manifest_file']}")
    print(f"  Total addresses: {summary['total']}")
    print(f"  Success       : {summary['success']}")
    print(f"  Not verified  : {summary['not_verified']}")
    print(f"  Errors        : {summary.get('error', 0) + summary.get('api_error', 0)}")
    print(f"  Skipped       : {summary['skipped']}")


if __name__ == "__main__":
    main()
