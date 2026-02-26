"""
Phase 2 – LLM Engine: LLM API client.

Wraps the OpenAI and Anthropic APIs with:
  - A configurable temperature.
  - An artificial pause of ≥13 seconds between calls to respect rate limits.
  - Support for binary and non-binary classification modes.
"""

from __future__ import annotations

import time
import logging
from typing import Optional

from config import (
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    DEFAULT_MODEL,
    TEMPERATURE,
    API_PAUSE_SECONDS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy imports – only import what the user actually needs, cached per process
# ---------------------------------------------------------------------------

_openai_client = None
_anthropic_client = None


def _get_openai_client():
    """Return a cached, configured openai.OpenAI client."""
    global _openai_client
    if _openai_client is None:
        import openai  # noqa: PLC0415
        _openai_client = openai.OpenAI(api_key=OPENAI_API_KEY)
    return _openai_client


def _get_anthropic_client():
    """Return a cached, configured anthropic.Anthropic client."""
    global _anthropic_client
    if _anthropic_client is None:
        import anthropic  # noqa: PLC0415
        _anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return _anthropic_client


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

    Supports OpenAI models (``gpt-*``) and Anthropic models (``claude-*``).
    An artificial pause is enforced before each call.

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

    model = model or DEFAULT_MODEL
    temperature = temperature if temperature is not None else TEMPERATURE

    if model.startswith("claude"):
        return _query_anthropic(messages, model, temperature, max_tokens)
    return _query_openai(messages, model, temperature, max_tokens)


def _query_openai(
    messages: list[dict],
    model: str,
    temperature: float,
    max_tokens: int,
) -> str:
    client = _get_openai_client()
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content or ""


def _query_anthropic(
    messages: list[dict],
    model: str,
    temperature: float,
    max_tokens: int,
) -> str:
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
    return response.content[0].text if response.content else ""
