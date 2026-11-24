import argparse
import hashlib
import json
import random
import re
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

import evaluate

CORPORA = {
    "semgrep-rules": {
        "url": "https://github.com/semgrep/semgrep-rules",
        "license": "Semgrep Rules License v1.0",
    },
    "kics": {"url": "https://github.com/Checkmarx/kics", "license": "Apache-2.0"},
    "bandit": {"url": "https://github.com/PyCQA/bandit", "license": "Apache-2.0"},
    "OWASP-BenchmarkPython": {
        "url": "https://github.com/AppSec-Tool-Benchmarking/OWASP-BenchmarkPython",
        "license": "see repository LICENSE",
    },
}

SEMGREP_LANGS = [
    ("python", ".py"),
    ("javascript", ".js"),
    ("typescript", ".ts"),
    ("java", ".java"),
    ("go", ".go"),
    ("csharp", ".cs"),
]

SOURCES = {
    "bandit": [
        ("bandit", "examples/*.py", None),
        ("semgrep-rules", "python/**/*.py", "ruleid:"),
        ("OWASP-BenchmarkPython", "testcode/*.py", None),
    ],
    "semgrep": [("semgrep-rules", f"{d}/**/*{e}", "ruleid:") for d, e in SEMGREP_LANGS],
    "checkov": [
        ("kics", "assets/queries/terraform/**/test/positive*.tf", None),
        ("kics", "assets/queries/k8s/**/test/positive*.yaml", None),
        ("semgrep-rules", "terraform/**/*.tf", "ruleid:"),
    ],
    "hadolint": [
        ("kics", "assets/queries/dockerfile/**/test/positive*.dockerfile", None),
        ("semgrep-rules", "dockerfile/**/*.dockerfile", "ruleid:"),
    ],
}

NEUTRAL = {
    ".py": "app.py",
    ".js": "app.js",
    ".ts": "app.ts",
    ".java": "Main.java",
    ".go": "main.go",
    ".cs": "Program.cs",
    ".tf": "main.tf",
    ".yaml": "manifest.yaml",
    ".dockerfile": "Dockerfile",
}

LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".cs": "csharp",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".dockerfile": "dockerfile",
}

ANNOTATION = re.compile(r"\s*(#|//|--)\s*(todo|deep)?(ruleid|ok)\s*:.*$", re.I)
MAX_LINES = 150


def sh(cmd, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


def clone(name, work):
    dest = (Path(work) / name).resolve()
    if not dest.exists():
        r = sh(["git", "clone", "--depth", "1", CORPORA[name]["url"], str(dest)])
        if r.returncode != 0:
            raise RuntimeError(r.stderr)
    commit = sh(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
    return dest, commit


def strip_annotations(code):
    lines = []
    for line in code.splitlines():
        lines.append(ANNOTATION.sub("", line))
    return "\n".join(lines).rstrip("\n") + "\n"


def load_json(text, default):
    text = text.strip()
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = min([i for i in (text.find("{"), text.find("[")) if i >= 0] or [0])
        return json.loads(text[start:])


def raw_bandit(root):
    out = sh(["bandit", "-r", str(root), "-f", "json", "-q"]).stdout
    data = load_json(out, {})
    return [
        {
            "path": r["filename"],
            "line": r["line_number"],
            "rule_id": r["test_id"],
            "rule_name": r["test_name"],
            "description": r["issue_text"],
            "significant": r["issue_severity"] in ("MEDIUM", "HIGH"),
        }
        for r in data.get("results", [])
    ]


def raw_semgrep(root):
    cmd = ["semgrep", "--config", "auto", "--json", "--quiet", str(root)]
    data = load_json(sh(cmd).stdout, {})
    out = []
    for r in data.get("results", []):
        path = r["path"]
        if not Path(path).is_absolute():
            path = str(Path(root) / path)
        out.append(
            {
                "path": path,
                "line": r["start"]["line"],
                "rule_id": r["check_id"],
                "rule_name": r["check_id"].split(".")[-1],
                "description": r["extra"].get("message", ""),
                "significant": r["extra"].get("severity") in ("WARNING", "ERROR"),
            }
        )
    return out


def raw_checkov(root):
    out = sh(["checkov", "-d", str(root), "--output", "json", "--quiet"]).stdout
    data = load_json(out, [])
    if isinstance(data, dict):
        data = [data]
    found = []
    for block in data:
        for c in block.get("results", {}).get("failed_checks", []):
            if str(c["check_id"]).startswith("CKV_SECRET"):
                continue
            rng = c.get("file_line_range") or [1, 1]
            found.append(
                {
                    "path": str(Path(root) / c["file_path"].lstrip("/")),
                    "line": rng[0],
                    "rule_id": c["check_id"],
                    "rule_name": c["check_name"],
                    "description": c["check_name"],
                    "significant": True,
                }
            )
    return found


def raw_hadolint(root):
    found = []
    for p in sorted(Path(root).glob("*.dockerfile")):
        data = load_json(sh(["hadolint", "--format", "json", str(p)]).stdout, [])
        for r in data:
            found.append(
                {
                    "path": str(p),
                    "line": r["line"],
                    "rule_id": r["code"],
                    "rule_name": r["code"],
                    "description": r["message"],
                    "significant": r["level"] in ("error", "warning"),
                }
            )
    return found


RAW = {
    "bandit": raw_bandit,
    "semgrep": raw_semgrep,
    "checkov": raw_checkov,
    "hadolint": raw_hadolint,
}
DISPLAY = {
    "bandit": "Bandit",
    "semgrep": "Semgrep",
    "checkov": "Checkov",
    "hadolint": "Hadolint",
}


def stage(scanner, work, stage_dir):
    meta = {}
    commits = {}
    idx = 0
    for corpus, pattern, must_have in SOURCES[scanner]:
        root, commit = clone(corpus, work)
        commits[corpus] = commit
        for p in sorted(root.glob(pattern)):
            if not p.is_file() or ".fixed." in p.name:
                continue
            ext = ".dockerfile" if p.name.endswith(".dockerfile") else p.suffix
            if ext not in NEUTRAL:
                continue
            try:
                text = p.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            if must_have and must_have not in text:
                continue
            code = strip_annotations(text)
            if not 0 < len(code.strip().splitlines()) <= MAX_LINES:
                continue
            idx += 1
            (Path(stage_dir) / f"{idx:05d}{ext}").write_text(code)
            meta[idx] = {
                "corpus": corpus,
                "path": str(p.relative_to(root)),
                "ext": ext,
                "code": code,
            }
    return meta, commits


def still_found(scanner, name, code, rule_id):
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / name
        t.write_text(code)
        return any(r == rule_id for r, _ in evaluate.SCANNERS[scanner](t))


def candidates(scanner, work, stage_dir):
    meta, commits = stage(scanner, work, stage_dir)
    found = []
    for f in RAW[scanner](stage_dir):
        if not f["significant"]:
            continue
        name = Path(f["path"]).name
        if not name.split(".")[0].isdigit():
            continue
        m = meta.get(int(name.split(".")[0]))
        if m:
            found.append(dict(f, **m))
    return found, commits, len(meta)


def select(scanner, cands, target, cap, seed):
    rng = random.Random(seed)
    by_rule = defaultdict(list)
    seen = set()
    ordered = sorted(cands, key=lambda c: (c["rule_id"], c["corpus"], c["path"], c["line"]))
    for c in ordered:
        key = (c["rule_id"], c["corpus"], c["path"])
        if key in seen:
            continue
        seen.add(key)
        by_rule[c["rule_id"]].append(c)
    for rule in by_rule:
        rng.shuffle(by_rule[rule])
    taken = defaultdict(int)
    chosen = []
    rules = sorted(by_rule)
    rng.shuffle(rules)
    progress = True
    while len(chosen) < target and progress:
        progress = False
        for rule in rules:
            if len(chosen) >= target:
                break
            if taken[rule] >= cap:
                continue
            while by_rule[rule]:
                c = by_rule[rule].pop()
                if still_found(scanner, NEUTRAL[c["ext"]], c["code"], rule):
                    chosen.append(c)
                    taken[rule] += 1
                    progress = True
                    break
    return chosen


def tool_version(scanner):
    r = sh([scanner, "--version"])
    text = (r.stdout or r.stderr).strip()
    return text.splitlines()[0] if text else "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanners", nargs="+", default=list(RAW))
    ap.add_argument("--target", type=int, default=100)
    ap.add_argument("--cap", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="test_cases_v6")
    ap.add_argument("--work", default="corpora_work")
    a = ap.parse_args()
    Path(a.work).mkdir(exist_ok=True)
