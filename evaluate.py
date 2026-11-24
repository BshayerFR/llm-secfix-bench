import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import Counter
from pathlib import Path

import adapters

OLLAMA_URL = "http://localhost:11434/api/generate"

PROMPT = """Fix this security issue found by {scanner}.
Rule: {rule_id} - {rule_name}
Description: {rule_description}
File: {file}, line {line}

Code:
{code}

Edit only the affected lines. Return only the complete fixed code, no explanation."""


OPTIONS = {"temperature": 0.2, "num_ctx": 8192, "num_predict": 4096}


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout


def scan_bandit(path):
    out = run(["bandit", "-f", "json", "-q", str(path)])
    data = json.loads(out) if out.strip() else {}
    return [
        (r["test_id"], r["issue_severity"] in ("MEDIUM", "HIGH"))
        for r in data.get("results", [])
    ]


def scan_semgrep(path):
    out = run(["semgrep", "--config", "auto", "--json", "--quiet", str(path)])
    data = json.loads(out) if out.strip() else {}
    return [
        (r["check_id"], r["extra"].get("severity") in ("WARNING", "ERROR"))
        for r in data.get("results", [])
    ]


def scan_checkov(path):
    out = run(["checkov", "-f", str(path), "--output", "json", "--quiet"])
    data = json.loads(out) if out.strip() else []
    if isinstance(data, dict):
        data = [data]
    found = []
    for block in data:
        for c in block.get("results", {}).get("failed_checks", []):
            found.append((c["check_id"], True))
    return found


def scan_hadolint(path):
    out = run(["hadolint", "--format", "json", str(path)])
    data = json.loads(out) if out.strip() else []
    return [(r["code"], r["level"] in ("error", "warning")) for r in data]


SCANNERS = {
    "bandit": scan_bandit,
    "semgrep": scan_semgrep,
    "checkov": scan_checkov,
    "hadolint": scan_hadolint,
}


SCANNERS.update({t: adapters.make_scanner(t) for t in adapters.RAW_DIR})


def ask_model(model, prompt, seed):
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": dict(OPTIONS, seed=seed),
        }
    ).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.loads(r.read())["response"]


def extract_code(answer):
    m = re.search(r"```[\w+-]*\n(.*?)```", answer, re.S)
    return (m.group(1) if m else answer).strip("\n") + "\n"


def build_prompt(case):
    return PROMPT.format(
        scanner=case["scanner"],
        rule_id=case["rule_id"],
        rule_name=case["rule_name"],
        rule_description=case["rule_description"],
        file=case["file"],
        line=case.get("line", "?"),
        code=case["vulnerable_code"],
    )


def generate(case, model, run_no):
    prompt = build_prompt(case)
    t0 = time.time()
    answer = ask_model(model, prompt, run_no)
    seconds = round(time.time() - t0, 1)
    return {
        "case_id": case["case_id"],
        "model": model,
        "scanner": case["scanner"],
        "rule_id": case["rule_id"],
        "run": run_no,
        "status": "generated",
        "seconds": seconds,
        "prompt": prompt,
        "raw_answer": answer,
        "fixed_code": extract_code(answer),
    }


def judge(case, rec, workdir):
    scan = SCANNERS[case["scanner"].lower()]
    target = Path(workdir) / case["file"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(case["vulnerable_code"])
    found = scan(target)
    before = Counter(r for r, _ in found)
    before_sig = Counter(r for r, sig in found if sig)
    if before[case["rule_id"]] == 0:
        return dict(rec, status="invalid_case", before=dict(before))
    fixed = rec["fixed_code"]
    target.write_text(fixed)
    found_after = scan(target)
    after = Counter(r for r, _ in found_after)
    after_sig = Counter(r for r, sig in found_after if sig)
    gone = after[case["rule_id"]] < before[case["rule_id"]]
    new = after_sig - before_sig
    new.pop(case["rule_id"], None)
    orig_lines = max(1, len(case["vulnerable_code"].strip().splitlines()))
    shrunk = len(fixed.strip().splitlines()) < 0.5 * orig_lines
    ok = gone and not new and not shrunk
    return dict(
        rec,
        status="pass" if ok else "fail",
        target_gone=gone,
        new_findings=dict(new),
        too_short=shrunk,
        before=dict(before),
        after=dict(after),
    )


def evaluate_once(case, model, workdir, run_no):
    return judge(case, generate(case, model, run_no), workdir)


def load_cases(folder):
    return [
        json.loads(p.read_text())
        for p in sorted(Path(folder).rglob("*.json"))
        if p.name != "manifest.json"
    ]


def summary(path):
    rows = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    models = sorted({r["model"] for r in rows})
    print(f"{'model':32} {'pass':>5} {'fail':>5} {'invalid':>8} {'rate':>7} {'avg sec':>8}")
    for m in models:
        mr = [r for r in rows if r["model"] == m]
        p = sum(r["status"] == "pass" for r in mr)
        f = sum(r["status"] == "fail" for r in mr)
        inv = sum(r["status"] == "invalid_case" for r in mr)
        times = [r["seconds"] for r in mr if "seconds" in r]
        rate = f"{100 * p / max(1, p + f):.0f}%"
        avg = f"{sum(times) / len(times):.1f}" if times else "-"
        print(f"{m:32} {p:>5} {f:>5} {inv:>8} {rate:>7} {avg:>8}")


def read_rows(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def append_row(path, rec):
    with open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")


def error_row(case, model, run_no, err):
    return {
        "case_id": case["case_id"],
        "model": model,
        "scanner": case["scanner"],
        "status": "error",
        "run": run_no,
        "error": str(err),
    }


def run_judge(a):
    cases = {c["case_id"]: c for c in load_cases(a.cases)}
    done = {(r["model"], r["case_id"], r.get("run")) for r in read_rows(a.out)}
    todo = []
    for path in a.results:
        for r in read_rows(path):
            if r.get("status") != "generated" or r["case_id"] not in cases:
                continue
            if a.scanner and r["scanner"].lower() != a.scanner.lower():
                continue
            if (r["model"], r["case_id"], r.get("run")) not in done:
                todo.append(r)
    print(f"{len(todo)} generated attempts to judge")
    for r in todo:
        case = cases[r["case_id"]]
        with tempfile.TemporaryDirectory() as d:
            try:
                rec = judge(case, r, d)
            except Exception as e:
                rec = dict(error_row(case, r["model"], r.get("run"), e), prompt=None)
        append_row(a.out, rec)
        print(rec["model"], rec["case_id"], rec.get("run"), rec["status"])
    if Path(a.out).exists():
        summary(a.out)


def run_generate(a, judge_too):
    cases = load_cases(a.cases)
    done = {
        (r["model"], r["case_id"], r.get("run"))
        for r in read_rows(a.out)
        if r.get("status") != "error"
    }
    print(
        f"{len(cases)} cases, {len(a.models)} models, {a.runs} runs each, {len(done)} already done"
    )
    for model in a.models:
        for case in cases:
            for run_no in range(1, a.runs + 1):
                if (model, case["case_id"], run_no) in done:
                    continue
                with tempfile.TemporaryDirectory() as d:
                    try:
                        if judge_too:
                            rec = evaluate_once(case, model, d, run_no)
                        else:
                            rec = generate(case, model, run_no)
                    except Exception as e:
                        rec = error_row(case, model, run_no, e)
                append_row(a.out, rec)
                print(model, case["case_id"], run_no, rec["status"], rec.get("seconds", ""))
                if rec["status"] == "invalid_case":
                    break
    if judge_too:
        summary(a.out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="test_cases_v6")
    ap.add_argument("--models", nargs="+")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", default="results.jsonl")
    ap.add_argument("--mode", choices=["both", "generate", "judge"], default="both")
    ap.add_argument("--results", nargs="+", default=[])
    ap.add_argument("--scanner")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()
    if a.summary:
        summary(a.out)
    elif a.mode == "judge":
        run_judge(a)
    else:
        run_generate(a, a.mode == "both")


if __name__ == "__main__":
    main()
