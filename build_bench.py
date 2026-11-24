import argparse
import hashlib
import json
import random
import re
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

import adapters
import evaluate

CORPORA = {
    "juice-shop": {"url": "https://github.com/juice-shop/juice-shop", "license": "MIT"},
    "WebGoat": {"url": "https://github.com/WebGoat/WebGoat", "license": "GPL-2.0-or-later"},
    "microservices-demo": {
        "url": "https://github.com/GoogleCloudPlatform/microservices-demo",
        "license": "Apache-2.0",
    },
    "pygoat": {"url": "https://github.com/adeyosemanputra/pygoat", "license": "MIT"},
    "terragoat": {
        "url": "https://github.com/bridgecrewio/terragoat",
        "license": "Apache-2.0",
    },
}
EXTRA = {
    "vulpy": {"url": "https://github.com/fportantier/vulpy", "license": "MIT"},
    "VAmPI": {"url": "https://github.com/erev0s/VAmPI", "license": "MIT"},
    "dvpwa": {
        "url": "https://github.com/anxolerd/dvpwa",
        "license": "MIT-style, see LICENSE",
    },
    "awesome-compose": {
        "url": "https://github.com/docker/awesome-compose",
        "license": "CC0, see LICENSE",
    },
    "example-voting-app": {
        "url": "https://github.com/dockersamples/example-voting-app",
        "license": "Apache-2.0",
    },
    "python-docs-samples": {
        "url": "https://github.com/GoogleCloudPlatform/python-docs-samples",
        "license": "Apache-2.0",
    },
}
MAIN = list(CORPORA)
CORPORA.update(EXTRA)
REAL = tuple(CORPORA)


def src(repos, *patterns, must=None):
    return [(r, p, must) for r in repos for p in patterns]


ALL = MAIN
WIDE = MAIN + list(EXTRA)
CODE = src(ALL, "**/*.java", "**/*.js", "**/*.ts", "**/*.py", "**/*.go", "**/*.cs")
TF = src(ALL, "**/*.tf")
K8S = src(ALL, "**/*.yaml", "**/*.yml", must="apiVersion:")
DOCKER = src(WIDE, "**/Dockerfile*", "**/*.dockerfile")
PY = src(WIDE, "**/*.py")

MANIFESTS = src(WIDE, "**/requirements*.txt", "**/pom.xml", "**/go.mod")

SOURCES = {
    "trivy": MANIFESTS,
    "osv-scanner": MANIFESTS,
    "grype": MANIFESTS,
    "dependency-check": MANIFESTS,
    "codeql": CODE,
    "sonarqube": CODE,
    "bandit": PY,
    "semgrep": CODE,
    "bearer": CODE,
    "checkov": TF + K8S,
    "kics": TF + K8S + DOCKER,
    "kubescape": K8S,
    "conftest": K8S + DOCKER,
    "hadolint": DOCKER,
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
    ".txt": "requirements.txt",
    ".xml": "pom.xml",
    ".mod": "go.mod",
}
SUBDIR_EXTS = (".txt", ".xml", ".mod")

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
    ".txt": "text",
    ".xml": "xml",
    ".mod": "go",
}

ANNOTATION = re.compile(r"\s*(#|//|--)\s*(todo|deep)?(ruleid|ok)\s*:.*$", re.I)
MAX_LINES = 200
MAX_CHARS = 12000


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
RAW.update(adapters.RAW_DIR)
DISPLAY.update(adapters.DISPLAY)


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
            lower = p.name.lower()
            if lower.endswith(".dockerfile") or lower.startswith("dockerfile"):
                ext = ".dockerfile"
            else:
                ext = ".yaml" if p.suffix == ".yml" else p.suffix
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
            if len(code) > MAX_CHARS:
                continue
            idx += 1
            if ext in SUBDIR_EXTS:
                sub = Path(stage_dir) / f"{idx:05d}"
                sub.mkdir()
                (sub / NEUTRAL[ext]).write_text(code)
            else:
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
        p = Path(f["path"])
        key = p.name.split(".")[0]
        if not key.isdigit():
            key = p.parent.name
        if not key.isdigit():
            continue
        m = meta.get(int(key))
        if m:
            found.append(dict(f, **m))
    return found, commits, len(meta)


def select(scanner, cands, target, cap, seed, file_cap=3):
    rng = random.Random(seed)
    taken = defaultdict(int)
    per_file = defaultdict(int)
    chosen = []
    pools = [
        [c for c in cands if c["corpus"] in REAL],
        [c for c in cands if c["corpus"] not in REAL],
    ]
    for pool in pools:
        by_rule = defaultdict(list)
        seen = set()
        ordered = sorted(
            pool, key=lambda c: (c["rule_id"], c["corpus"], c["path"], c["line"])
        )
        for c in ordered:
            key = (c["rule_id"], c["corpus"], c["path"])
            if key in seen:
                continue
            seen.add(key)
            by_rule[c["rule_id"]].append(c)
        for rule in by_rule:
            rng.shuffle(by_rule[rule])
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
                    fkey = (c["corpus"], c["path"])
                    if per_file[fkey] >= file_cap:
                        continue
                    if still_found(scanner, NEUTRAL[c["ext"]], c["code"], rule):
                        chosen.append(c)
                        taken[rule] += 1
                        per_file[fkey] += 1
                        progress = True
                        break
    return chosen


def tool_version(scanner):
    if scanner == "sonarqube":
        return "SonarQube Community (sonarqube:community docker image)"
    try:
        r = sh([scanner, "--version"])
    except Exception:
        return "unknown"
    text = (r.stdout or r.stderr).strip()
    return text.splitlines()[0] if text else "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanners", nargs="+", default=list(RAW))
    ap.add_argument("--target", type=int, default=100)
    ap.add_argument("--cap", type=int, default=15)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="test_cases_v6")
    ap.add_argument("--work", default="corpora_work")
    a = ap.parse_args()
    Path(a.work).mkdir(exist_ok=True)
    manifest = {
        "seed": a.seed,
        "max_lines": MAX_LINES,
        "per_rule_cap": a.cap,
        "corpora": CORPORA,
        "scanners": {},
        "cases": [],
    }
    for scanner in a.scanners:
        try:
            with tempfile.TemporaryDirectory() as stage_dir:
                cands, commits, staged = candidates(scanner, a.work, stage_dir)
            chosen = select(scanner, cands, a.target, a.cap, a.seed)
        except Exception as e:
            print(scanner, "FAILED:", e)
            manifest["scanners"][scanner] = {"error": str(e)[:500]}
            continue
        manifest["scanners"][scanner] = {
            "version": tool_version(scanner),
            "files_staged": staged,
            "candidates": len(cands),
            "selected": len(chosen),
            "distinct_rules": len({c["rule_id"] for c in chosen}),
            "corpus_commits": commits,
        }
        folder = Path(a.out) / scanner
        folder.mkdir(parents=True, exist_ok=True)
        for i, c in enumerate(chosen, 1):
            case = {
                "case_id": f"{scanner.upper()}-{i:03d}",
                "scanner": DISPLAY[scanner],
                "rule_id": c["rule_id"],
                "rule_name": c["rule_name"],
                "rule_description": c["description"],
                "language": LANGUAGES[c["ext"]],
                "file": NEUTRAL[c["ext"]],
                "line": c["line"],
                "vulnerable_code": c["code"],
                "source": {
                    "corpus": c["corpus"],
                    "url": CORPORA[c["corpus"]]["url"],
                    "commit": commits[c["corpus"]],
                    "path": c["path"],
                    "license": CORPORA[c["corpus"]]["license"],
                },
            }
            text = json.dumps(case, indent=2, ensure_ascii=False)
            (folder / (case["case_id"] + ".json")).write_text(text)
            manifest["cases"].append(
                {
                    "case_id": case["case_id"],
                    "rule_id": c["rule_id"],
                    "corpus": c["corpus"],
                    "path": c["path"],
                    "commit": commits[c["corpus"]],
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                }
            )
        print(
            scanner, "staged:", staged, "candidates:", len(cands), "selected:", len(chosen)
        )
    mdir = Path(a.out).resolve().parent / "manifests"
    mdir.mkdir(exist_ok=True)
    (mdir / ("_".join(a.scanners) + ".json")).write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
