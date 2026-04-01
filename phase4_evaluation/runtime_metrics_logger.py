"""Runtime audit metrics logger (append-only JSONL)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def append_runtime_metric(record: dict[str, Any], file_path: str) -> None:
    """Append one runtime metric row to a local jsonl file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        **record,
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
