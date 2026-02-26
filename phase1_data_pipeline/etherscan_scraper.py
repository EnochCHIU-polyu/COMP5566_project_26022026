"""
Phase 1 – Data Pipeline: Etherscan scraper.

Fetches verified smart-contract source code via the Etherscan API.
"""

import time
import requests
from config import ETHERSCAN_API_KEY

ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"


def fetch_contract_source(address: str) -> dict:
    """
    Fetch the verified source code of a contract from Etherscan.

    Parameters
    ----------
    address : str
        Ethereum contract address (checksummed or lowercase).

    Returns
    -------
    dict
        Parsed JSON response from Etherscan including 'SourceCode', 'ContractName', etc.
        Returns an empty dict on failure.
    """
    if not ETHERSCAN_API_KEY:
        raise ValueError("ETHERSCAN_API_KEY is not set. Add it to your .env file.")

    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_API_KEY,
    }
    response = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=30)
    response.raise_for_status()
    data = response.json()

    if data.get("status") != "1" or not data.get("result"):
        return {}

    return data["result"][0]


def scrape_contracts(addresses: list[str], pause: float = 0.3) -> list[dict]:
    """
    Scrape source code for a list of contract addresses.

    Parameters
    ----------
    addresses : list[str]
        List of Ethereum contract addresses.
    pause : float
        Seconds to sleep between requests (Etherscan free tier: 5 req/s).

    Returns
    -------
    list[dict]
        List of source-code records.
    """
    results = []
    for addr in addresses:
        try:
            record = fetch_contract_source(addr)
            if record:
                record["address"] = addr
                results.append(record)
        except Exception as exc:  # noqa: BLE001
            print(f"[scraper] Failed for {addr}: {exc}")
        time.sleep(pause)
    return results
