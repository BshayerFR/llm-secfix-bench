import argparse
import random
import sys
from collections import defaultdict

import evaluate

PROMPT = """Fix this security issue found by {scanner}.
Rule: {rule_id}
File: {file}, line {line}

Code:
{code}

Edit only the affected lines. Return only the complete fixed code, no explanation."""

SEED = 42
original_load_cases = evaluate.load_cases
per_scanner = 27


def build_prompt(case):
    return PROMPT.format(
        scanner=case["scanner"],
        rule_id=case["rule_id"],
        file=case["file"],
        line=case.get("line", "?"),
        code=case["vulnerable_code"],
    )


def load_sample(folder):
    groups = defaultdict(list)
    for case in original_load_cases(folder):
        groups[case["scanner"]].append(case)
    picked = []
    for scanner in sorted(groups):
        cases = sorted(groups[scanner], key=lambda c: c["case_id"])
        k = min(per_scanner, len(cases))
        picked += random.Random(SEED).sample(cases, k)
    return sorted(picked, key=lambda c: c["case_id"])


def main():
    global per_scanner
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-scanner", type=int, default=27)
    known, rest = ap.parse_known_args()
    per_scanner = known.per_scanner
    sys.argv = [sys.argv[0]] + rest
    evaluate.build_prompt = build_prompt
    evaluate.load_cases = load_sample
    evaluate.main()


if __name__ == "__main__":
    main()
