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
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
ETHERSCAN_API_KEY: str = os.getenv("ETHERSCAN_API_KEY", "")

# ── LLM Settings ─────────────────────────────────────────────────────────────
DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "gpt-4o")
GITHUB_FALLBACK_MODEL: str = os.getenv(
	"GITHUB_FALLBACK_MODEL",
	"deepseek/DeepSeek-V3-0324",
)
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
BATCH_VULNS_PER_PROMPT: int = int(os.getenv("BATCH_VULNS_PER_PROMPT", "8"))

# ── Keyword Pre-filter ────────────────────────────────────────────────────────
# If True, skip vulnerability checks with no matching keywords in the contract
# (reduces API calls by ~60-80%)
KEYWORD_PREFILTER_ENABLED: bool = os.getenv("KEYWORD_PREFILTER_ENABLED", "true").lower() in ("true", "1", "yes")

# ── Data Paths ────────────────────────────────────────────────────────────────
DATA_DIR: str = os.path.join(os.path.dirname(__file__), "data")
VULNERABLE_CONTRACTS_DIR: str = os.path.join(DATA_DIR, "vulnerable_contracts")
SYNTHETIC_CONTRACTS_DIR: str = os.path.join(DATA_DIR, "synthetic_contracts")
