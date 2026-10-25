"""Regression gate over the labeled evaluation sets (tests/eval/*.jsonl).

* ``known_miss`` cases are documented gaps: they must STILL fail (strict). If one starts passing the test fails,
  telling you to remove the flag - so improvements are recorded and gaps cannot quietly disappear.
* Every other case must pass.
* The metric floors stop silent regressions. They are floors on the author-written tuning set, NOT estimates of
  real-world performance (see docs/DETECTION_EVALUATION.md).
"""
import pytest

import tests.eval.runner as runner
from app.orchestrator import SecurityOrchestrator

ORCH = SecurityOrchestrator()


def _results(filename):
    original = runner.CASES_PATH
    runner.CASES_PATH = original.replace("detection_cases.jsonl", filename)
    try:
        return runner.evaluate(ORCH)
    finally:
        runner.CASES_PATH = original


RESULTS = {name: _results(name) for name in ("detection_cases.jsonl", "detection_holdout.jsonl")}
ALL = [(name, r) for name, rs in RESULTS.items() for r in rs]


@pytest.mark.parametrize("name, result", ALL, ids=[r["case"]["id"] for _, r in ALL])
def test_case(name, result):
    case = result["case"]
    detail = f'{case["id"]}: expected {case["expect"]} pii={case["pii"]}, got {result["decision"]} pii={result["categories"]}'
    if case["known_miss"]:
        assert not result["ok"], f"{detail} - this documented gap now passes; remove known_miss ({case['note']})"
    else:
        assert result["ok"], detail


def test_metric_floors_on_the_tuning_set():
    s = runner.summarise(RESULTS["detection_cases.jsonl"])
    assert s["attack_recall"] >= 0.85
    assert s["benign_false_positive_rate"] <= 0.075
    assert s["pii_accuracy"] >= 0.97


def test_metric_floors_on_the_formerly_held_out_set():
    # Tuned-on after its first evaluation (35% recall before tuning), so this is a regression floor, not an estimate.
    s = runner.summarise(RESULTS["detection_holdout.jsonl"])
    assert s["attack_recall"] >= 0.65
    assert s["benign_false_positive_rate"] == 0.0
