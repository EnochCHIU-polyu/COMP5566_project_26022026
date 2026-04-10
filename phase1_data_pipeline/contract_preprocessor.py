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
    normalize: bool = False,
) -> dict:
    """
    Prepare a contract's source code for LLM analysis.

    Steps:
    1. Optionally normalize the source (whitespace, comments, line numbers).
    2. Count tokens.
    3. Truncate if the count exceeds ``max_tokens - reserve_tokens``
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
    normalize : bool
        If True, apply basic normalization (whitespace collapsing, pragma
        standardisation) before tokenizing.

    Returns
    -------
    dict
        ``{"source_code": str, "token_count": int, "truncated": bool}``
    """
    if normalize:
        from phase1_data_pipeline.contract_normalizer import normalize_contract
        source_code = normalize_contract(source_code)

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
