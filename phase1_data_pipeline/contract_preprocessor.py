"""
Phase 1 – Data Pipeline: Contract pre-processor.

Combines loading, token counting, and truncation into a single pipeline step.
"""

from config import MAX_CONTEXT_TOKENS, DEFAULT_MODEL
from phase1_data_pipeline.token_counter import count_tokens, truncate_to_token_limit


def preprocess_contract(
    source_code: str,
    max_tokens: int = MAX_CONTEXT_TOKENS,
    model: str = DEFAULT_MODEL,
    reserve_tokens: int = 2000,
) -> dict:
    """
    Prepare a contract's source code for LLM analysis.

    Steps:
    1. Count tokens.
    2. Truncate if the count exceeds ``max_tokens - reserve_tokens``
       (reserve space is left for the prompt wrapper and model output).

    Parameters
    ----------
    source_code : str
        Raw Solidity source.
    max_tokens : int
        Hard token limit for the model.
    model : str
        Model name used for tokenization.
    reserve_tokens : int
        Tokens to reserve for the prompt template and LLM response.

    Returns
    -------
    dict
        ``{"source_code": str, "token_count": int, "truncated": bool}``
    """
    effective_limit = max_tokens - reserve_tokens
    token_count = count_tokens(source_code, model)
    truncated = False

    if token_count > effective_limit:
        source_code = truncate_to_token_limit(source_code, effective_limit, model)
        token_count = count_tokens(source_code, model)
        truncated = True

    return {
        "source_code": source_code,
        "token_count": token_count,
        "truncated": truncated,
    }
