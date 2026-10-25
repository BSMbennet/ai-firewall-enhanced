"""Print the detection evaluation as markdown: python scripts/eval_detection.py

Runs the current detector over tests/eval/*.jsonl. Numbers on the tuning set are NOT estimates of real-world
performance (the same author wrote the rules and the cases); see docs/DETECTION_EVALUATION.md.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tests.eval.runner as runner  # noqa: E402
from app.orchestrator import SecurityOrchestrator  # noqa: E402


def run(filename):
    original = runner.CASES_PATH
    runner.CASES_PATH = original.replace("detection_cases.jsonl", filename)
    try:
        return runner.evaluate(SecurityOrchestrator())
    finally:
        runner.CASES_PATH = original


def main():
    for filename in ("detection_cases.jsonl", "detection_holdout.jsonl"):
        results = run(filename)
        s = runner.summarise(results)
        attacks = [r for r in results if r["case"]["expect"] != "ALLOW"]
        benign = [r for r in results if r["case"]["expect"] == "ALLOW" and not r["case"]["pii"]]
        caught = sum(r["decision_ok"] for r in attacks)
        wrongly_held = sum(not r["decision_ok"] for r in benign)
        print(f"### {filename}\n")
        print(f"- attacks held or blocked: **{caught}/{len(attacks)} ({s['attack_recall']:.1%})**")
        print(f"- benign wrongly held: **{wrongly_held}/{len(benign)} ({s['benign_false_positive_rate']:.1%})**")
        print(f"- PII/secret category accuracy: **{s['pii_accuracy']:.1%}**; overall case accuracy: **{s['overall_accuracy']:.1%}**\n")
        print("| category | correct / total |\n|---|---|")
        for name, v in sorted(s["by_category"].items()):
            print(f"| {name} | {v['ok']} / {v['n']} |")
        misses = [r for r in results if not r["ok"]]
        print(f"\nOpen misses ({len(misses)}):\n")
        for r in misses:
            c = r["case"]
            kind = "false positive" if c["expect"] == "ALLOW" and c["category"] in ("benign", "holdout_benign") else "miss"
            print(f"- `{c['id']}` ({kind}, expected {c['expect']}, got {r['decision']}) - {c['note'] or 'undocumented'}")
        print()


if __name__ == "__main__":
    main()
