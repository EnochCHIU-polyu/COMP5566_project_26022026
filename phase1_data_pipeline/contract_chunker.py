"""
Phase 1 – Data Pipeline: Smart contract chunker.

Splits large contracts into manageable chunks for LLM analysis,
preserving context (pragma, imports, state variables).
"""

from __future__ import annotations
import re
from typing import Optional


def extract_pragma_and_imports(source_code: str) -> str:
    """Extract pragma statement and import declarations."""
    lines = source_code.splitlines()
    header_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('pragma ') or stripped.startswith('import '):
            header_lines.append(line)
        elif header_lines and stripped == '':
            header_lines.append(line)
    return '\n'.join(header_lines)


def extract_state_variables(source_code: str) -> str:
    """Extract state variable declarations (lines before first function)."""
    func_match = re.search(r'\bfunction\s+\w+', source_code)
    if not func_match:
        return ''

    before_funcs = source_code[:func_match.start()]
    lines = before_funcs.splitlines()
    state_vars = []
    in_contract = False
    for line in lines:
        stripped = line.strip()
        if re.match(r'contract\s+\w+', stripped):
            in_contract = True
            continue
        if in_contract and stripped and not stripped.startswith('//'):
            if not any(stripped.startswith(kw) for kw in [
                'function', 'event', 'modifier', 'constructor', 'receive', 'fallback'
            ]):
                state_vars.append(line)
    return '\n'.join(state_vars)


def extract_functions(source_code: str) -> list[dict]:
    """
    Extract individual functions with their full bodies using brace matching.

    Returns list of {"name": str, "signature": str, "body": str, "start_line": int}
    """
    functions = []
    lines = source_code.splitlines()
    func_pattern = re.compile(
        r'\b(function|constructor|receive|fallback)\s*(\w*)\s*\('
    )

    i = 0
    while i < len(lines):
        line = lines[i]
        match = func_pattern.search(line)
        if match:
            start_line = i + 1
            func_name = match.group(2) or match.group(1)

            brace_count = 0
            func_lines = []
            found_open = False
            j = i
            while j < len(lines):
                func_lines.append(lines[j])
                for ch in lines[j]:
                    if ch == '{':
                        brace_count += 1
                        found_open = True
                    elif ch == '}':
                        brace_count -= 1
                if found_open and brace_count == 0:
                    functions.append({
                        "name": func_name,
                        "signature": line.strip(),
                        "body": '\n'.join(func_lines),
                        "start_line": start_line,
                    })
                    i = j + 1
                    break
                j += 1
            else:
                i += 1
        else:
            i += 1

    return functions


def chunk_by_function(
    source_code: str,
    max_tokens: int = 4000,
    count_tokens_fn=None,
) -> list[dict]:
    """
    Split contract into function-level chunks.

    Each chunk contains:
    - Pragma and imports
    - State variables
    - One or more functions

    Parameters
    ----------
    source_code : str
        Full contract source.
    max_tokens : int
        Maximum tokens per chunk.
    count_tokens_fn : callable, optional
        Function to count tokens. If None, estimates by character count.

    Returns
    -------
    list[dict]
        List of chunk dicts with "source_code", "functions", "chunk_index".
    """
    if count_tokens_fn is None:
        count_tokens_fn = lambda x: len(x) // 4  # rough estimate

    header = extract_pragma_and_imports(source_code)
    state_vars = extract_state_variables(source_code)
    functions = extract_functions(source_code)

    context = header + '\n\n' + state_vars if state_vars else header

    if not functions:
        return [{"source_code": source_code, "functions": [], "chunk_index": 0}]

    chunks = []
    current_funcs = []
    current_body = context

    for func in functions:
        candidate = current_body + '\n\n' + func["body"]
        if count_tokens_fn(candidate) > max_tokens and current_funcs:
            chunks.append({
                "source_code": current_body,
                "functions": current_funcs[:],
                "chunk_index": len(chunks),
            })
            current_funcs = [func["name"]]
            current_body = context + '\n\n' + func["body"]
        else:
            current_funcs.append(func["name"])
            current_body = candidate

    if current_funcs:
        chunks.append({
            "source_code": current_body,
            "functions": current_funcs,
            "chunk_index": len(chunks),
        })

    return chunks if chunks else [{"source_code": source_code, "functions": [], "chunk_index": 0}]


def sliding_window_chunks(
    source_code: str,
    chunk_size: int = 3000,
    overlap: int = 500,
    count_tokens_fn=None,
) -> list[dict]:
    """
    Create overlapping sliding window chunks.

    Parameters
    ----------
    source_code : str
        Contract source.
    chunk_size : int
        Target tokens per chunk.
    overlap : int
        Overlapping tokens between chunks.
    count_tokens_fn : callable, optional
        Token counting function.

    Returns
    -------
    list[dict]
        List of chunk dicts.
    """
    if count_tokens_fn is None:
        count_tokens_fn = lambda x: len(x) // 4

    lines = source_code.splitlines()
    chunks = []
    chunk_index = 0
    start = 0

    while start < len(lines):
        end = start
        current_text = ''
        while end < len(lines):
            candidate = '\n'.join(lines[start:end + 1])
            if count_tokens_fn(candidate) > chunk_size and end > start:
                break
            current_text = candidate
            end += 1

        if not current_text:
            current_text = '\n'.join(lines[start:start + 1])
            end = start + 1

        chunks.append({
            "source_code": current_text,
            "functions": [],
            "chunk_index": chunk_index,
        })
        chunk_index += 1

        overlap_chars = overlap * 4
        overlap_lines = max(1, overlap_chars // (len(current_text) // max(1, end - start) + 1))
        start = max(start + 1, end - overlap_lines)

        if start >= len(lines):
            break

    return chunks
