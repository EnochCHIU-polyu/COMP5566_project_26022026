"""Tests for Phase 2 – LLM Engine components (no live API calls)."""

import pytest
from unittest.mock import patch, MagicMock

from vulnerability_types import VULNERABILITY_TYPES
import phase2_llm_engine.vulnerability_store as vulnerability_store
from phase2_llm_engine.prompt_builder import (
    build_prompt,
    build_cot_function_prompt,
    extract_function_names,
    build_batch_audit_prompt,
)
from phase2_llm_engine.slither_runner import format_slither_reference


class TestVulnerabilityTypes:
    def test_38_vulnerability_types(self):
        assert len(VULNERABILITY_TYPES) == 38

    def test_each_has_name_and_description(self):
        for vt in VULNERABILITY_TYPES:
            assert "name" in vt, f"Missing 'name' in {vt}"
            assert "description" in vt, f"Missing 'description' in {vt}"
            assert len(vt["name"]) > 0
            assert len(vt["description"]) > 0

    def test_no_duplicate_names(self):
        names = [vt["name"] for vt in VULNERABILITY_TYPES]
        assert len(names) == len(set(names))


class TestPromptBuilder:
    def test_build_prompt_non_binary(self):
        messages = build_prompt(
            source_code="pragma solidity ^0.8.0;",
            vuln_name="Reentrancy",
            vuln_description="External call before state update.",
            mode="non_binary",
        )
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert "Reentrancy" in messages[1]["content"]
        assert "pragma solidity" in messages[1]["content"]

    def test_build_prompt_binary_has_yes_no_instruction(self):
        messages = build_prompt(
            source_code="pragma solidity ^0.8.0;",
            vuln_name="Reentrancy",
            vuln_description="External call before state update.",
            mode="binary",
        )
        user_content = messages[1]["content"]
        assert "YES" in user_content or "NO" in user_content

    def test_build_prompt_contains_vuln_description(self):
        desc = "A very specific description used as a marker."
        messages = build_prompt(
            source_code="contract A {}",
            vuln_name="TestVuln",
            vuln_description=desc,
            mode="non_binary",
        )
        assert desc in messages[1]["content"]

    def test_extract_function_names(self):
        source = """
        contract A {
            function deposit() external payable {}
            function withdraw(uint256 amount) external {}
            function _internal() private {}
        }
        """
        names = extract_function_names(source)
        assert "deposit" in names
        assert "withdraw" in names
        assert "_internal" in names

    def test_extract_function_names_empty(self):
        assert extract_function_names("// no functions here") == []

    def test_build_cot_function_prompt(self):
        messages = build_cot_function_prompt("contract A { function foo() {} }", "foo")
        assert len(messages) == 2
        assert "foo" in messages[1]["content"]

    def test_system_instruction_present(self):
        messages = build_prompt("src", "Reentrancy", "desc")
        system_content = messages[0]["content"]
        assert "smart contract auditor" in system_content.lower()

    def test_build_prompt_includes_slither_reference(self):
        messages = build_prompt(
            source_code="contract A {}",
            vuln_name="Reentrancy",
            vuln_description="desc",
            slither_reference="- detector=reentrancy lines=L12",
        )
        assert "Slither" in messages[1]["content"]
        assert "detector=reentrancy" in messages[1]["content"]

    def test_build_batch_prompt_includes_slither_reference(self):
        vulns = [{"name": "Reentrancy", "description": "desc"}]
        messages = build_batch_audit_prompt(
            source_code="contract A {}",
            vulns=vulns,
            mode="binary",
            slither_reference="- detector=reentrancy lines=L3",
        )
        assert "Static analysis reference" in messages[1]["content"]
        assert "detector=reentrancy" in messages[1]["content"]


class _FakeResponse:
    def __init__(self, data):
        self.data = data


class _FakeQuery:
    def __init__(self, data):
        self._data = data

    def select(self, *_args, **_kwargs):
        return self

    def order(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def execute(self):
        return _FakeResponse(self._data)


class _FakeClient:
    def __init__(self, data):
        self._data = data

    def table(self, _name):
        return _FakeQuery(self._data)


class TestVulnerabilityStore:
    def test_get_vulnerability_types_local_fallback(self, monkeypatch):
        monkeypatch.setattr(vulnerability_store, "_get_db_client", lambda: None)
        loaded = vulnerability_store.get_vulnerability_types()
        assert len(loaded) == len(VULNERABILITY_TYPES)
        assert loaded[0]["name"]

    def test_get_vulnerability_types_from_db(self, monkeypatch):
        fake_rows = [
            {
                "name": "Reentrancy",
                "description": "desc",
                "swc_id": "SWC-107",
                "severity_default": "critical",
                "example_vulnerable": "bad",
                "example_fixed": "good",
                "detection_keywords": [".call{"],
                "cwe_id": "CWE-841",
            }
        ]
        monkeypatch.setattr(vulnerability_store, "_seed_from_local_if_empty", lambda _client: None)
        monkeypatch.setattr(vulnerability_store, "_get_db_client", lambda: _FakeClient(fake_rows))
        loaded = vulnerability_store.get_vulnerability_types()
        assert len(loaded) == 1
        assert loaded[0]["name"] == "Reentrancy"


class TestSlitherRunner:
    def test_format_slither_reference_empty(self):
        assert format_slither_reference(None) == ""

    def test_format_slither_reference_with_findings(self):
        slither_result = {
            "ok": True,
            "findings": [
                {
                    "check": "timestamp",
                    "impact": "Medium",
                    "confidence": "High",
                    "description": "timestamp dependence detected",
                    "lines": [8, 10],
                }
            ],
        }
        text = format_slither_reference(slither_result)
        assert "Slither pre-scan findings" in text
        assert "timestamp" in text
        assert "L8" in text
