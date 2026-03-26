"""Tests for Phase 4 – Evaluation and Scoring."""

import pytest
from phase4_evaluation.scorer import (
    infer_verdict_for_scoring,
    _parse_binary_response,
    score_binary_result,
    compute_metrics,
    evaluate_batch,
)


class TestParseBinaryResponse:
    def test_alias_matches_infer(self):
        assert infer_verdict_for_scoring is _parse_binary_response

    def test_yes_response(self):
        assert _parse_binary_response("YES, this contract is vulnerable") is True

    def test_no_response(self):
        assert _parse_binary_response("NO, this contract is safe") is False

    def test_yes_case_insensitive(self):
        assert _parse_binary_response("yes it is vulnerable") is True

    def test_no_case_insensitive(self):
        assert _parse_binary_response("no it is not") is False

    def test_unparseable_returns_none(self):
        assert _parse_binary_response("I am not sure about this contract") is None

    def test_yes_embedded(self):
        assert _parse_binary_response("YES – the withdraw() function...") is True

    def test_chinese_verdict_lines(self):
        assert infer_verdict_for_scoring("结论：否\n经分析该合约...") is False
        assert infer_verdict_for_scoring("结论：是\n存在重入") is True

    def test_english_yes_after_preamble(self):
        assert infer_verdict_for_scoring("Here is my analysis.\nYES\nmore text") is True


class TestScoreBinaryResult:
    def test_tp(self):
        assert score_binary_result(True, True) == "TP"

    def test_fp(self):
        assert score_binary_result(True, False) == "FP"

    def test_tn(self):
        assert score_binary_result(False, False) == "TN"

    def test_fn(self):
        assert score_binary_result(False, True) == "FN"


class TestComputeMetrics:
    def test_perfect_precision_and_recall(self):
        m = compute_metrics(tp=10, fp=0, tn=10, fn=0)
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0
        assert m["accuracy"] == 1.0

    def test_zero_division_handled(self):
        m = compute_metrics(tp=0, fp=0, tn=0, fn=0)
        assert m["precision"] == 0.0
        assert m["recall"] == 0.0
        assert m["f1"] == 0.0

    def test_known_values(self):
        # precision = 2/(2+1) = 0.6667, recall = 2/(2+1) = 0.6667
        m = compute_metrics(tp=2, fp=1, tn=5, fn=1)
        assert abs(m["precision"] - 0.6667) < 0.001
        assert abs(m["recall"] - 0.6667) < 0.001

    def test_accuracy(self):
        m = compute_metrics(tp=8, fp=2, tn=7, fn=3)
        assert m["accuracy"] == pytest.approx(0.75, abs=0.01)


class TestEvaluateBatch:
    def _make_result(self, contract_name, vuln_responses):
        """Helper to build an audit result dict."""
        return {
            "contract_name": contract_name,
            "vuln_results": [
                {"vuln_name": vn, "response": resp}
                for vn, resp in vuln_responses.items()
            ],
            "function_results": [],
        }

    def test_empty_batch(self):
        result = evaluate_batch([], {})
        assert result["aggregate"]["counts"]["TP"] == 0

    def test_all_true_positives(self):
        audit = self._make_result(
            "ContractA",
            {"Reentrancy": "YES, vulnerable", "Flash Loan Attack": "YES, vulnerable"},
        )
        ground_truth = {"ContractA": ["Reentrancy", "Flash Loan Attack"]}
        result = evaluate_batch([audit], ground_truth)
        agg = result["aggregate"]["counts"]
        assert agg["TP"] == 2
        assert agg["FP"] == 0

    def test_false_positive_detection(self):
        audit = self._make_result(
            "ContractA",
            {"Reentrancy": "YES, vulnerable"},
        )
        ground_truth = {"ContractA": []}  # no actual vulnerabilities
        result = evaluate_batch([audit], ground_truth)
        agg = result["aggregate"]["counts"]
        assert agg["FP"] == 1
        assert agg["TP"] == 0

    def test_per_contract_breakdown(self):
        audit = self._make_result(
            "ContractA",
            {"Reentrancy": "YES, vulnerable"},
        )
        ground_truth = {"ContractA": ["Reentrancy"]}
        result = evaluate_batch([audit], ground_truth)
        assert len(result["per_contract"]) == 1
        assert result["per_contract"][0]["contract_name"] == "ContractA"
        assert result["per_contract"][0]["counts"]["TP"] == 1
        assert result["aggregate"].get("skipped_unparseable") == 0

    def test_skipped_unparseable(self):
        audit = self._make_result("ContractA", {"Reentrancy": "Maybe."})
        result = evaluate_batch([audit], {"ContractA": ["Reentrancy"]})
        assert result["aggregate"]["skipped_unparseable"] >= 1
        assert result["aggregate"]["counts"]["TP"] == 0
