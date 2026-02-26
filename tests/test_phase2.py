"""Tests for Phase 2 – LLM Engine components (no live API calls)."""

import pytest
from unittest.mock import patch, MagicMock

from phase2_llm_engine.vulnerability_types import VULNERABILITY_TYPES
from phase2_llm_engine.prompt_builder import (
    build_prompt,
    build_cot_function_prompt,
    extract_function_names,
)


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
