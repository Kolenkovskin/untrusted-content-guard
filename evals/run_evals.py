#!/usr/bin/env python3
"""Measure sanitize_hook detector quality against evals/cases.json.

An alert is any finding at HIGH or CRITICAL - the two severities that reach the
model. MEDIUM (canary) is a silent quarantine and is reported separately, since
it never interrupts anyone.

Run:  python evals/run_evals.py
Exit: 0 always. This harness reports, it does not gate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sanitize_hook import scan  # noqa: E402

ALERTING = {"CRITICAL", "HIGH"}


def main() -> int:
    data = json.loads((ROOT / "evals" / "cases.json").read_text(encoding="utf-8"))
    cases = data["cases"]

    tp = fp = tn = fn = 0
    rows: list[tuple[str, str, str, str, str]] = []

    for case in cases:
        findings = scan(case["content"])
        alerting = [f for f in findings if f["severity"] in ALERTING]
        silent = [f for f in findings if f["severity"] not in ALERTING]

        alerted = bool(alerting)
        hostile = case["label"] == "hostile"

        if hostile and alerted:
            outcome, tp = "TP", tp + 1
        elif hostile and not alerted:
            outcome, fn = "FN", fn + 1
        elif not hostile and alerted:
            outcome, fp = "FP", fp + 1
        else:
            outcome, tn = "TN", tn + 1

        patterns = ",".join(sorted({f["pattern"] for f in alerting})) or "-"
        note = f"(+{len(silent)} silent MEDIUM)" if silent else ""
        rows.append((case["id"], case["label"], outcome, patterns, note))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print()
    print(f"{'ID':<5} {'TRUTH':<8} {'RESULT':<7} {'PATTERNS':<34} NOTE")
    print("-" * 78)
    for row in rows:
        print(f"{row[0]:<5} {row[1]:<8} {row[2]:<7} {row[3]:<34} {row[4]}")

    print("-" * 78)
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}   (n={len(cases)})")
    print(f"precision = {precision:.3f}    recall = {recall:.3f}    f1 = {f1:.3f}")
    print()
    print("Read these numbers together with the base-rate note in EVALS.md.")
    print("Recall is what this hook is tuned for. Precision is not, and cannot be,")
    print("the reason the output is advisory rather than blocking.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
