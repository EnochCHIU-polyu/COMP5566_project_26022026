"""
Phase 2 – LLM Engine: LLM API client.

Wraps the OpenAI and Anthropic APIs with:
  - A configurable temperature.
  - An artificial pause of ≥13 seconds between calls to respect rate limits.
  - Support for binary and non-binary classification modes.
  - Exponential backoff retry logic (up to 3 retries: 2/4/8 seconds).
"""

from __future__ import annotations

import time
import logging
from typing import Optional

from config import (
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    ANTHROPIC_API_KEY,
    GITHUB_TOKEN,
    DEFAULT_MODEL,
    GITHUB_FALLBACK_MODEL,
    TEMPERATURE,
    API_PAUSE_SECONDS,
)

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 2  # seconds (doubles each retry: 2, 4, 8)

# ---------------------------------------------------------------------------
# Lazy imports – only import what the user actually needs, cached per process
# ---------------------------------------------------------------------------

_openai_client = None
_anthropic_client = None
_github_client = None


def _get_openai_client():
    """Return a cached, configured openai.OpenAI client."""
    global _openai_client
    if _openai_client is None:
        import openai  # noqa: PLC0415
        client_kwargs = {"api_key": OPENAI_API_KEY}
        if OPENAI_BASE_URL:
            client_kwargs["base_url"] = OPENAI_BASE_URL
        _openai_client = openai.OpenAI(**client_kwargs)
    return _openai_client


def _get_anthropic_client():
    """Return a cached, configured anthropic.Anthropic client."""
    global _anthropic_client
    if _anthropic_client is None:
        import anthropic  # noqa: PLC0415
        _anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return _anthropic_client


def _get_github_client():
    """Return a cached, configured openai.OpenAI client pointing to GitHub Models."""
    global _github_client
    if _github_client is None:
        token = GITHUB_TOKEN or OPENAI_API_KEY
        if not token:
            raise ValueError("GITHUB_TOKEN (or OPENAI_API_KEY) is required for GitHub Models requests")

        import openai  # noqa: PLC0415
        _github_client = openai.OpenAI(
            base_url="https://models.github.ai/inference",
            api_key=token,
        )
    return _github_client


# ---------------------------------------------------------------------------
# Internal state for rate-limit pausing
# ---------------------------------------------------------------------------

_last_call_time: float = 0.0


def _enforce_pause() -> None:
    """Sleep until at least API_PAUSE_SECONDS have elapsed since the last call."""
    global _last_call_time
    elapsed = time.time() - _last_call_time
    remaining = API_PAUSE_SECONDS - elapsed
    if remaining > 0:
        logger.debug("Rate-limit pause: sleeping %.1f s", remaining)
        time.sleep(remaining)
    _last_call_time = time.time()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def query_llm(
    messages: list[dict],
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    max_tokens: int = 2048,
) -> str:
    """
    Send *messages* to the specified LLM and return the text response.

    Supports OpenAI models (``gpt-*``), Anthropic models (``claude-*``),
    and GitHub Models (e.g., ``deepseek/*``).
    An artificial pause is enforced before each call.
    Retries up to 3 times with exponential backoff (2/4/8 s) on transient errors.

    Parameters
    ----------
    messages : list[dict]
        List of ``{"role": ..., "content": ...}`` dicts.
    model : str, optional
        Override the default model from config.
    temperature : float, optional
        Override the default temperature from config.
    max_tokens : int
        Maximum tokens in the model's response.

    Returns
    -------
    str
        The model's text response.
    """
    _enforce_pause()

    model = _normalize_model_name(model or DEFAULT_MODEL)
    temperature = temperature if temperature is not None else TEMPERATURE
    logger.info(
        "LLM request started: model=%s temperature=%.2f max_tokens=%d messages=%d",
        model,
        temperature,
        max_tokens,
        len(messages),
    )

    last_exc: Optional[Exception] = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            # When OPENAI_BASE_URL is set (e.g. Poe), use OpenAI-compatible client for all models
            if OPENAI_BASE_URL and OPENAI_API_KEY:
                logger.info("LLM provider selected: openai-compatible (base_url=%s, model=%s)", OPENAI_BASE_URL, model)
                return _query_openai(messages, model, temperature, max_tokens)

            if model.startswith("claude"):
                logger.info("LLM provider selected: anthropic (model=%s)", model)
                return _query_anthropic(messages, model, temperature, max_tokens)

            if _should_use_github_models(model):
                logger.info("LLM provider selected: github-models (model=%s)", model)
                return _query_github(messages, model, temperature, max_tokens)

            try:
                logger.info("LLM provider selected: openai (model=%s)", model)
                return _query_openai(messages, model, temperature, max_tokens)
            except Exception as openai_exc:  # noqa: BLE001
                if (GITHUB_TOKEN or OPENAI_API_KEY) and _is_region_block_error(openai_exc):
                    fallback_model = _normalize_model_name(GITHUB_FALLBACK_MODEL)
                    logger.warning(
                        "OpenAI request blocked by region policy; retrying via GitHub Models with %s",
                        fallback_model,
                    )
                    return _query_github(messages, fallback_model, temperature, max_tokens)
                raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < _MAX_RETRIES:
                delay = _RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "LLM call failed (attempt %d/%d): %s – retrying in %ds",
                    attempt + 1, _MAX_RETRIES, exc, delay,
                )
                time.sleep(delay)
            else:
                logger.error("LLM call failed after %d retries: %s", _MAX_RETRIES, exc)

    raise RuntimeError(f"LLM query failed after {_MAX_RETRIES} retries") from last_exc


def _is_region_block_error(exc: Exception) -> bool:
    """Return True when the API error indicates unsupported country/region."""
    err_text = str(exc).lower()
    return (
        "unsupported_country_region_territory" in err_text
        or "country, region, or territory not supported" in err_text
    )


def _normalize_model_name(model: str) -> str:
    """Map UI-friendly aliases to provider-specific model identifiers."""
    # When using Poe/OpenAI-compatible API, pass model name as-is
    if OPENAI_BASE_URL:
        return (model or "").strip()
    alias_map = {
        "gpt-4o": "openai/gpt-4o",
        "gpt-4o-mini": "openai/gpt-4o-mini",
        "o4-mini": "openai/o4-mini",
    }
    normalized = (model or "").strip()
    return alias_map.get(normalized.lower(), normalized)


def _should_use_github_models(model: str) -> bool:
    """Return True if this model should be called via GitHub Models endpoint."""
    if OPENAI_BASE_URL and "models.github.ai" not in OPENAI_BASE_URL.lower():
        return False

    lowered = model.lower()
    if model.startswith("openai/") or model.startswith("deepseek/"):
        return True
    if lowered in {"openai/o4-mini", "openai/gpt-4o", "openai/gpt-4o-mini"}:
        return True
    if (GITHUB_TOKEN or OPENAI_API_KEY) and lowered in {"gpt-4o", "gpt-4o-mini", "o4-mini"}:
        return True
    return False


def _query_openai(
    messages: list[dict],
    model: str,
    temperature: float,
    max_tokens: int,
) -> str:
    logger.info("Sending request to OpenAI Chat Completions (model=%s)", model)
    client = _get_openai_client()
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    logger.info("Received response from OpenAI (model=%s)", model)
    return response.choices[0].message.content or ""


def _query_github(
    messages: list[dict],
    model: str,
    temperature: float,
    max_tokens: int,
) -> str:
    logger.info("Sending request to GitHub Models (model=%s)", model)
    client = _get_github_client()
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    logger.info("Received response from GitHub Models (model=%s)", model)
    return response.choices[0].message.content or ""


def _query_anthropic(
    messages: list[dict],
    model: str,
    temperature: float,
    max_tokens: int,
) -> str:
    logger.info("Sending request to Anthropic Messages API (model=%s)", model)
    client = _get_anthropic_client()
    # Anthropic separates system prompt from user messages
    system_content = ""
    chat_messages = []
    for msg in messages:
        if msg["role"] == "system":
            system_content = msg["content"]
        else:
            chat_messages.append(msg)

    response = client.messages.create(
        model=model,
        system=system_content,
        messages=chat_messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    logger.info("Received response from Anthropic (model=%s)", model)
    return response.content[0].text if response.content else ""
