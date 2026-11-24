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


def evaluate_once(case, model, workdir, run_no):
    scan = SCANNERS[case["scanner"].lower()]
    target = Path(workdir) / case["file"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(case["vulnerable_code"])
    found = scan(target)
    before = Counter(r for r, _ in found)
    before_sig = Counter(r for r, sig in found if sig)
    rec = {
        "case_id": case["case_id"],
        "model": model,
        "scanner": case["scanner"],
        "rule_id": case["rule_id"],
    }
    if before[case["rule_id"]] == 0:
        rec.update(status="invalid_case", before=dict(before))
        return rec
    prompt = PROMPT.format(
        scanner=case["scanner"],
        rule_id=case["rule_id"],
        rule_name=case["rule_name"],
        rule_description=case["rule_description"],
        file=case["file"],
        line=case.get("line", "?"),
        code=case["vulnerable_code"],
    )
    t0 = time.time()
    answer = ask_model(model, prompt, run_no)
    seconds = round(time.time() - t0, 1)
    fixed = extract_code(answer)
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
    rec.update(
        status="pass" if ok else "fail",
        target_gone=gone,
        new_findings=dict(new),
        too_short=shrunk,
        seconds=seconds,
        before=dict(before),
        after=dict(after),
        prompt=prompt,
        raw_answer=answer,
        fixed_code=fixed,
    )
    return rec


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="test_cases_v6")
    ap.add_argument("--models", nargs="+")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", default="results.jsonl")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()
    if a.summary:
        summary(a.out)
        return
    cases = load_cases(a.cases)
    done = set()
    if Path(a.out).exists():
        for l in Path(a.out).read_text().splitlines():
            if l.strip():
                r = json.loads(l)
                if r.get("status") != "error":
                    done.add((r["model"], r["case_id"], r.get("run")))
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
                        rec = evaluate_once(case, model, d, run_no)
                    except Exception as e:
                        rec = {
                            "case_id": case["case_id"],
                            "model": model,
                            "status": "error",
                            "error": str(e),
                        }
                rec["run"] = run_no
                with open(a.out, "a") as f:
                    f.write(json.dumps(rec) + "\n")
                print(model, case["case_id"], run_no, rec["status"], rec.get("seconds", ""))
                if rec["status"] == "invalid_case":
                    break
    summary(a.out)


if __name__ == "__main__":
    main()
