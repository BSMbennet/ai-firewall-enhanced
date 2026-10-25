"""Scores a SecurityOrchestrator against detection_cases.jsonl. Used by the regression test and the report script."""
import asyncio
import json
import os
from collections import defaultdict

from .synthetic import resolve

CASES_PATH = os.path.join(os.path.dirname(__file__), "detection_cases.jsonl")


def load_cases():
    with open(CASES_PATH, encoding="utf-8") as handle:
        cases = [json.loads(line) for line in handle if line.strip()]
    for case in cases:
        case["text"] = resolve(case["text"])
    return cases


def decision_ok(expect: str, decision: str) -> bool:
    if expect == "ALLOW":
        return decision == "ALLOW"
    if expect == "HOLD":
        return decision in {"BLOCK", "REVIEW"}
    return decision == "BLOCK"


async def _one(orchestrator, case):
    result = await orchestrator.validate_request_parallel(prompt=case["text"], context={}, user_id="eval", request_id="eval")
    categories = None
    if hasattr(orchestrator, "pii_categories"):
        categories = sorted(await orchestrator.pii_categories(case["text"]))
        pii_ok = categories == case["pii"]
    else:  # baseline detector exposes only a boolean
        pii_ok = bool(result.pii_detected) == bool(case["pii"])
    d_ok = decision_ok(case["expect"], result.decision)
    return {"case": case, "decision": result.decision, "categories": categories, "decision_ok": d_ok, "pii_ok": pii_ok, "ok": d_ok and pii_ok}


def evaluate(orchestrator):
    async def run():
        return [await _one(orchestrator, case) for case in load_cases()]
    return asyncio.run(run())


def summarise(results):
    """Per-category accuracy plus the confusion that matters for a firewall: missed attacks and wrongly held benign."""
    by_cat = defaultdict(lambda: {"n": 0, "ok": 0})
    attacks = [r for r in results if r["case"]["expect"] != "ALLOW"]
    benign = [r for r in results if r["case"]["expect"] == "ALLOW" and not r["case"]["pii"]]
    for r in results:
        by_cat[r["case"]["category"]]["n"] += 1
        by_cat[r["case"]["category"]]["ok"] += r["ok"]
    return {
        "by_category": dict(by_cat),
        "attack_recall": sum(r["decision_ok"] for r in attacks) / len(attacks),
        "attack_n": len(attacks),
        "benign_false_positive_rate": sum(not r["decision_ok"] for r in benign) / len(benign),
        "benign_n": len(benign),
        "pii_accuracy": sum(r["pii_ok"] for r in results) / len(results),
        "overall_accuracy": sum(r["ok"] for r in results) / len(results),
    }
