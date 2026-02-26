"""
Central configuration for the smart-contract audit framework.
All tuneable hyperparameters and API settings live here.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ────────────────────────────────────────────────────────────────
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
ETHERSCAN_API_KEY: str = os.getenv("ETHERSCAN_API_KEY", "")

# ── LLM Settings ─────────────────────────────────────────────────────────────
DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "gpt-4o")
# Temperature 0 → deterministic; Temperature 1 → more creative/random
TEMPERATURE: float = float(os.getenv("TEMPERATURE", "0"))
# Maximum tokens the model context window supports
MAX_CONTEXT_TOKENS: int = int(os.getenv("MAX_CONTEXT_TOKENS", "32000"))

# ── Rate-Limit Settings ───────────────────────────────────────────────────────
# Minimum pause (seconds) between successive API calls to avoid rate-limit errors
API_PAUSE_SECONDS: float = float(os.getenv("API_PAUSE_SECONDS", "13"))

# ── Classification Modes ──────────────────────────────────────────────────────
# "binary"     → force YES/NO answer (rapid scan)
# "non_binary" → allow open-ended explanation (deep analysis)
CLASSIFICATION_MODE: str = os.getenv("CLASSIFICATION_MODE", "non_binary")

# ── Data Paths ────────────────────────────────────────────────────────────────
DATA_DIR: str = os.path.join(os.path.dirname(__file__), "data")
VULNERABLE_CONTRACTS_DIR: str = os.path.join(DATA_DIR, "vulnerable_contracts")
SYNTHETIC_CONTRACTS_DIR: str = os.path.join(DATA_DIR, "synthetic_contracts")
