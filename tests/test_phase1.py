"""Tests for Phase 1 – Data Pipeline components."""

import os
import json
import tempfile
import pytest

from phase1_data_pipeline.token_counter import count_tokens, truncate_to_token_limit
from phase1_data_pipeline.contract_preprocessor import preprocess_contract
from phase1_data_pipeline.dataset_loader import load_contracts_from_dir
from phase1_data_pipeline.synthetic_contracts import (
    generate_synthetic_contracts,
    save_synthetic_contracts,
    _SECURE_TEMPLATES,
    _VULN_PATCHES,
)


class TestTokenCounter:
    def test_count_tokens_returns_positive_int(self):
        text = "pragma solidity ^0.8.0;"
        count = count_tokens(text)
        assert isinstance(count, int)
        assert count > 0

    def test_count_tokens_empty_string(self):
        assert count_tokens("") == 0

    def test_truncate_short_text_unchanged(self):
        text = "short text"
        result = truncate_to_token_limit(text, max_tokens=1000)
        assert result == text

    def test_truncate_long_text(self):
        text = "hello world " * 5000  # very long
        result = truncate_to_token_limit(text, max_tokens=100)
        count = count_tokens(result)
        assert count <= 100

    def test_truncate_adds_notice(self):
        text = "hello world " * 5000
        result = truncate_to_token_limit(text, max_tokens=100)
        assert "TRUNCATED" in result


class TestContractPreprocessor:
    def test_short_contract_not_truncated(self):
        src = "// short\npragma solidity ^0.8.0;\ncontract A {}"
        result = preprocess_contract(src, max_tokens=32000, reserve_tokens=2000)
        assert result["truncated"] is False
        assert result["token_count"] > 0
        assert result["source_code"] == src

    def test_long_contract_truncated(self):
        src = "// x\n" * 50000  # definitely exceeds any reasonable limit
        result = preprocess_contract(src, max_tokens=500, reserve_tokens=100)
        assert result["truncated"] is True
        assert result["token_count"] <= 400


class TestDatasetLoader:
    def test_load_from_empty_dir(self, tmp_path):
        contracts = load_contracts_from_dir(str(tmp_path))
        assert contracts == []

    def test_load_sol_file(self, tmp_path):
        sol_file = tmp_path / "Test.sol"
        sol_file.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;")
        contracts = load_contracts_from_dir(str(tmp_path))
        assert len(contracts) == 1
        assert contracts[0]["name"] == "Test"
        assert "pragma solidity" in contracts[0]["source_code"]

    def test_load_json_file(self, tmp_path):
        data = {
            "name": "MyContract",
            "source_code": "pragma solidity ^0.8.0;",
            "labels": ["Reentrancy"],
        }
        json_file = tmp_path / "MyContract.json"
        json_file.write_text(json.dumps(data))
        contracts = load_contracts_from_dir(str(tmp_path))
        assert len(contracts) == 1
        assert contracts[0]["labels"] == ["Reentrancy"]

    def test_load_nonexistent_dir(self):
        contracts = load_contracts_from_dir("/nonexistent/path")
        assert contracts == []


class TestSyntheticContracts:
    def test_generate_5_contracts(self):
        contracts = generate_synthetic_contracts(num_vulns=2)
        assert len(contracts) == 5

    def test_generate_with_2_vulns_injects_labels(self):
        contracts = generate_synthetic_contracts(num_vulns=2)
        # At least some contracts should have labels injected
        all_labels = [label for c in contracts for label in c["labels"]]
        assert len(all_labels) > 0

    def test_generate_with_15_vulns(self):
        contracts = generate_synthetic_contracts(num_vulns=15)
        assert len(contracts) == 5
        all_labels = [label for c in contracts for label in c["labels"]]
        assert len(all_labels) >= 5  # at least one per contract

    def test_invalid_num_vulns_raises(self):
        with pytest.raises(ValueError):
            generate_synthetic_contracts(num_vulns=7)

    def test_save_and_reload(self, tmp_path):
        contracts = generate_synthetic_contracts(num_vulns=2)
        save_synthetic_contracts(contracts, directory=str(tmp_path))
        saved_files = list(tmp_path.glob("*.json"))
        assert len(saved_files) == 5

    def test_secure_templates_not_modified(self):
        # The base templates should be unchanged after generation
        original_sources = [t["source_code"] for t in _SECURE_TEMPLATES]
        generate_synthetic_contracts(num_vulns=15)
        for i, t in enumerate(_SECURE_TEMPLATES):
            assert t["source_code"] == original_sources[i]
