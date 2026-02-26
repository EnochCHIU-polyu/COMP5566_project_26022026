"""
Phase 1 – Data Pipeline: Token counting utility.

Uses tiktoken to count tokens and to truncate or compress contracts that
exceed the model's context window.  Falls back to a character-based estimator
(~4 chars per token) when the tiktoken encoding cannot be downloaded.
"""

import tiktoken

# Approximate characters-per-token ratio used as a lightweight fallback
_CHARS_PER_TOKEN = 4


def _simple_encode(text: str):
    """Minimal fallback tokenizer: split on whitespace and punctuation boundaries."""
    # Return a list-like object with len() = estimated token count
    # Rough estimate: 1 token ≈ 4 characters
    count = max(1, len(text) // _CHARS_PER_TOKEN) if text else 0
    return list(range(count))


def _simple_decode(tokens) -> str:
    """Not meaningful for the fallback – returns empty string."""
    return ""


class _FallbackEncoding:
    """Mimics the tiktoken Encoding interface with a character-based estimator."""

    def encode(self, text: str):
        if not text:
            return []
        # Return a minimal object whose len() equals the estimated token count
        return range(max(1, len(text) // _CHARS_PER_TOKEN))

    def decode(self, tokens) -> str:
        # Cannot reverse the estimator; callers that need decode use tiktoken directly
        return ""


def get_encoding(model: str = "gpt-4o"):
    """
    Return the tiktoken encoding for *model*, falling back to cl100k_base,
    and ultimately to a lightweight character-based estimator if network
    access is unavailable.
    """
    try:
        return tiktoken.encoding_for_model(model)
    except Exception:
        pass
    try:
        return tiktoken.get_encoding("cl100k_base")
    except Exception:
        return _FallbackEncoding()


def count_tokens(text: str, model: str = "gpt-4o") -> int:
    """
    Count the number of tokens in *text* for the given *model*.

    Parameters
    ----------
    text : str
        The text to tokenize.
    model : str
        Model name used to select the correct tokenizer.

    Returns
    -------
    int
        Token count.
    """
    enc = get_encoding(model)
    return len(enc.encode(text))


def truncate_to_token_limit(text: str, max_tokens: int, model: str = "gpt-4o") -> str:
    """
    Truncate *text* so that it fits within *max_tokens*.

    Parameters
    ----------
    text : str
        Source text (e.g. Solidity contract code).
    max_tokens : int
        Maximum number of tokens allowed.
    model : str
        Model name used to select the tokenizer.

    Returns
    -------
    str
        Possibly truncated text.  A truncation notice is appended when the
        text is actually shortened.
    """
    enc = get_encoding(model)
    tokens = enc.encode(text)
    if len(tokens) <= max_tokens:
        return text

    notice = "\n\n[TRUNCATED: contract exceeded context window]"

    # For the real tiktoken encodings, round-trip through tokens
    if hasattr(enc, "decode") and not isinstance(enc, _FallbackEncoding):
        notice_tokens = enc.encode(notice)
        truncated_tokens = tokens[: max_tokens - len(notice_tokens)]
        return enc.decode(truncated_tokens) + notice

    # Fallback: truncate by character count
    char_limit = max_tokens * _CHARS_PER_TOKEN - len(notice)
    return text[:char_limit] + notice
