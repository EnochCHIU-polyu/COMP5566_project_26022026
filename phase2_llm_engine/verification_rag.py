"""
Lightweight RAG for the verification / reflection pass only.

Uses TF-IDF + cosine similarity (sklearn, no FAISS dependency) over a corpus built from
``vulnerability_types`` plus optional JSONL files under ``data/rag_corpus/*.jsonl``.

For larger corpora you can swap this module to use FAISS + embedding models later.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)

_CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "rag_corpus")


@lru_cache(maxsize=1)
def _build_corpus_texts() -> tuple[list[str], list[str]]:
    """Return (list of document strings, parallel list of short labels)."""
    from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES

    docs: list[str] = []
    labels: list[str] = []
    for v in VULNERABILITY_TYPES:
        parts = [
            v.get("name", ""),
            v.get("description", ""),
            v.get("example_vulnerable", ""),
            v.get("example_fixed", ""),
        ]
        text = "\n".join(p for p in parts if p).strip()
        if text:
            docs.append(text)
            labels.append(v["name"])

    extra_dir = os.path.normpath(_CORPUS_DIR)
    if os.path.isdir(extra_dir):
        for fn in os.listdir(extra_dir):
            if not fn.endswith(".jsonl"):
                continue
            path = os.path.join(extra_dir, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            chunk = obj.get("text") or obj.get("content") or ""
                            lab = obj.get("vuln_type") or obj.get("label") or "extra"
                            if chunk:
                                docs.append(chunk[:8000])
                                labels.append(str(lab))
                        except json.JSONDecodeError:
                            continue
                logger.info("Loaded RAG chunks from %s", path)
            except OSError as exc:
                logger.warning("Could not read RAG corpus %s: %s", path, exc)

    return docs, labels


def retrieve_verification_context(
    vuln_type: str,
    finding_description: str,
    source_code_snippet: str,
    top_k: int = 3,
) -> str:
    """
    Retrieve top-k text chunks relevant to verifying a finding.

    Parameters
    ----------
    vuln_type : str
        Vulnerability type name (e.g. Reentrancy).
    finding_description : str
        Auditor's short description.
    source_code_snippet : str
        Truncated contract source (avoid huge prompts).
    top_k : int
        Number of chunks to include.

    Returns
    -------
    str
        Formatted block to inject into the verification user message, or empty if unavailable.
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        logger.warning("sklearn not available; skipping verification RAG")
        return ""

    docs, labels = _build_corpus_texts()
    if not docs:
        return ""

    query = f"{vuln_type}\n{finding_description}\n{source_code_snippet[:4000]}"
    try:
        vectorizer = TfidfVectorizer(max_features=8192, ngram_range=(1, 2), min_df=1)
        tfidf = vectorizer.fit_transform(docs + [query])
        sims = cosine_similarity(tfidf[-1], tfidf[:-1]).ravel()
    except Exception as exc:  # noqa: BLE001
        logger.warning("RAG retrieval failed: %s", exc)
        return ""

    top_idx = sims.argsort()[::-1][:top_k]
    lines = ["--- Retrieved reference knowledge (RAG, verification-only) ---"]
    for rank, i in enumerate(top_idx, 1):
        if i < 0 or i >= len(docs):
            continue
        lab = labels[i] if i < len(labels) else "?"
        snippet = docs[i][:1200].replace("\n", " ")
        lines.append(f"[{rank}] {lab}: {snippet}...")
    lines.append("--- End retrieved context ---\n")
    return "\n".join(lines)
