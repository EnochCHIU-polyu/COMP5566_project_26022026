"""
Phase 1 – Data Pipeline: Contract source code normalizer.

Normalizes Solidity source code for consistent LLM input.
"""

from __future__ import annotations
import re


def strip_comments(source_code: str, keep_natspec: bool = True) -> str:
    """
    Strip comments from Solidity source code.

    Parameters
    ----------
    source_code : str
        Raw Solidity source.
    keep_natspec : bool
        If True, preserve NatSpec comments (/// and /** */).

    Returns
    -------
    str
        Source with comments removed.
    """
    result = []
    i = 0
    n = len(source_code)

    while i < n:
        # Check for string literals
        if source_code[i] in ('"', "'"):
            quote = source_code[i]
            end = source_code.find(quote, i + 1)
            while end != -1 and source_code[end - 1] == '\\':
                end = source_code.find(quote, end + 1)
            if end == -1:
                result.append(source_code[i:])
                break
            result.append(source_code[i:end + 1])
            i = end + 1
        # Block comment
        elif source_code[i:i + 2] == '/*':
            end = source_code.find('*/', i + 2)
            if end == -1:
                break
            comment = source_code[i:end + 2]
            if keep_natspec and source_code[i:i + 3] == '/**':
                result.append(comment)
            i = end + 2
        # Line comment
        elif source_code[i:i + 2] == '//':
            end = source_code.find('\n', i)
            if end == -1:
                if keep_natspec and source_code[i:i + 3] == '///':
                    result.append(source_code[i:])
                break
            comment = source_code[i:end]
            if keep_natspec and source_code[i:i + 3] == '///':
                result.append(comment)
            result.append('\n')
            i = end + 1
        else:
            result.append(source_code[i])
            i += 1

    return ''.join(result)


def normalize_whitespace(source_code: str) -> str:
    """Collapse multiple consecutive blank lines into a single blank line."""
    return re.sub(r'\n{3,}', '\n\n', source_code).strip()


def standardize_pragma(source_code: str) -> str:
    """Ensure pragma statement is on its own line with consistent format."""
    return re.sub(
        r'pragma\s+solidity\s+([^;]+);',
        lambda m: f'pragma solidity {m.group(1).strip()};',
        source_code,
    )


def add_line_numbers(source_code: str) -> str:
    """Add /* L{n} */ annotation at the start of each line."""
    lines = source_code.splitlines()
    annotated = [f"/* L{i + 1} */ {line}" for i, line in enumerate(lines)]
    return '\n'.join(annotated)


def normalize_contract(
    source_code: str,
    strip_comments_flag: bool = False,
    keep_natspec: bool = True,
    add_line_nums: bool = False,
) -> str:
    """
    Apply all normalization steps to a Solidity contract.

    Parameters
    ----------
    source_code : str
        Raw Solidity source.
    strip_comments_flag : bool
        If True, strip non-NatSpec comments.
    keep_natspec : bool
        If True, preserve NatSpec comments when stripping.
    add_line_nums : bool
        If True, add line number annotations.

    Returns
    -------
    str
        Normalized source code.
    """
    result = source_code
    if strip_comments_flag:
        result = strip_comments(result, keep_natspec=keep_natspec)
    result = normalize_whitespace(result)
    result = standardize_pragma(result)
    if add_line_nums:
        result = add_line_numbers(result)
    return result
