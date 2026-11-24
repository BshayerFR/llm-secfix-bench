import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

KICS_QUERIES = os.environ.get("KICS_QUERIES", "")
KICS_LIBRARIES = os.environ.get("KICS_LIBRARIES", "")
CONFTEST_POLICY = os.environ.get("CONFTEST_POLICY", "policy")


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


WARNED = {}


def warn(name, r):
    n = WARNED.get(name, 0)
    if n >= 3:
        return
    WARNED[name] = n + 1
    print(
        f"[{name}] exit code {r.returncode}\n{(r.stderr or '')[-1500:]}\n{(r.stdout or '')[-500:]}",
        file=sys.stderr,
        flush=True,
    )


def read_json(path):
    p = Path(path)
    if not p.exists() or not p.read_text().strip():
        return None
    return json.loads(p.read_text())


def item(path, line, rule_id, rule_name, description, significant):
    return {
        "path": str(path),
        "line": line or 1,
        "rule_id": str(rule_id),
        "rule_name": str(rule_name or rule_id),
        "description": str(description or rule_name or rule_id),
        "significant": significant,
    }


def parse_kics(doc):
    out = []
    for q in (doc or {}).get("queries") or []:
        if q.get("category") == "Secret Management":
            continue
        files = q.get("files") or []
        if isinstance(files, dict):
            files = [files]
        for f in files:
            out.append(
                item(
                    f.get("file_name", ""),
                    f.get("line"),
                    q.get("query_id"),
                    q.get("query_name"),
                    q.get("description"),
                    str(q.get("severity")).upper() in ("CRITICAL", "HIGH", "MEDIUM"),
                )
            )
    return out


def run_kics(root):
    cmd = ["kics", "scan", "-p", str(root)]
    if KICS_QUERIES:
        cmd += ["-q", KICS_QUERIES]
    if KICS_LIBRARIES:
        cmd += ["--libraries-path", KICS_LIBRARIES]
    with tempfile.TemporaryDirectory() as out:
        cmd += ["--report-formats", "json", "-o", out, "--output-name", "results"]
        cmd += ["--no-progress", "--silent", "--disable-secrets", "--ignore-on-exit", "all"]
        sh(cmd)
        return parse_kics(read_json(Path(out) / "results.json"))


def parse_sarif(doc):
    out = []
    for run in (doc or {}).get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        parts = [driver] + (run.get("tool", {}).get("extensions") or [])
        rules = {r.get("id"): r for part in parts for r in part.get("rules") or []}
        for res in run.get("results", []):
            rid = res.get("ruleId", "unknown")
            rule = rules.get(rid, {})
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            level = str(
                res.get("level")
                or rule.get("defaultConfiguration", {}).get("level")
                or "warning"
            ).lower()
            name = (rule.get("shortDescription") or {}).get("text") or rule.get("name")
            msg = (res.get("message") or {}).get("text")
            out.append(
                item(
                    loc.get("artifactLocation", {}).get("uri", ""),
                    loc.get("region", {}).get("startLine"),
                    rid,
                    name or msg,
                    msg,
                    level in ("warning", "error"),
                )
            )
    return out


def run_kubescape(root):
    with tempfile.TemporaryDirectory() as out:
        target = Path(out) / "report.sarif"
        sh(
            ["kubescape", "scan", str(root), "--format", "sarif", "--output", str(target)]
            + ["--keep-local"]
        )
        for p in Path(out).glob("report*.sarif*"):
            return parse_sarif(read_json(p))
        return []


def parse_conftest(doc):
    out = []
    for r in doc or []:
        for part, significant in (("failures", True), ("warnings", False)):
            for f in r.get(part) or []:
                meta = f.get("metadata") or {}
                rid = meta.get("id") or f"{r.get('namespace')}:{f.get('msg')}"
                out.append(
                    item(
                        r.get("filename", ""),
                        1,
                        rid,
                        meta.get("title") or f.get("msg"),
                        f.get("msg"),
                        significant,
                    )
                )
    return out


def run_conftest(root):
    root = Path(root)
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    out = []
    for f in files:
        r = sh(
            [
                "conftest",
                "test",
                str(f),
                "--policy",
                CONFTEST_POLICY,
                "--all-namespaces",
                "--output",
                "json",
                "--no-color",
            ]
        )
        text = r.stdout.strip()
        if not text:
            warn("conftest", r)
            continue
        try:
            out += parse_conftest(json.loads(text))
        except json.JSONDecodeError:
            warn("conftest", r)
    return out


BEARER_LEVELS = ("critical", "high", "medium", "low", "warning")


def parse_bearer(doc):
    out = []
    for level in BEARER_LEVELS:
        for r in (doc or {}).get(level) or []:
            if "gitleaks" in str(r.get("id")):
                continue
            out.append(
                item(
                    r.get("filename", ""),
                    r.get("line_number"),
                    r.get("id"),
                    r.get("title"),
                    r.get("description") or r.get("title"),
                    level in ("critical", "high", "medium"),
                )
            )
    return out


def run_bearer(root):
    with tempfile.TemporaryDirectory() as out:
        target = Path(out) / "report.json"
        sh(
            [
                "bearer",
                "scan",
                str(root),
                "--format",
                "json",
                "--output",
                str(target),
                "--quiet",
                "--disable-version-check",
            ]
        )
        return parse_bearer(read_json(target))


RAW_DIR = {
    "kics": run_kics,
    "kubescape": run_kubescape,
    "conftest": run_conftest,
    "bearer": run_bearer,
}

DISPLAY = {
    "kics": "KICS",
    "kubescape": "Kubescape",
    "conftest": "Conftest",
    "bearer": "Bearer",
}


def scan_file(tool, path):
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(path, Path(d) / Path(path).name)
        found = RAW_DIR[tool](d)
    return [(f["rule_id"], f["significant"]) for f in found]


def make_scanner(tool):
    return lambda path: scan_file(tool, path)


def level_from_score(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9:
        return "critical"
    if s >= 7:
        return "high"
    return "medium" if s >= 4 else "low"


def sca_item(path, vuln_id, package, level, installed, fixed, title=None):
    desc = f"{title or vuln_id} in {package}. Installed {installed}, fixed in {fixed or 'none'}."
    return item(
        path,
        1,
        f"{vuln_id}:{package}",
        f"{vuln_id} in {package}",
        desc,
        str(level).lower() in ("high", "critical"),
    )


def parse_trivy(doc):
    out = []
    for res in (doc or {}).get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            out.append(
                sca_item(
                    res.get("Target", ""),
                    v.get("VulnerabilityID"),
                    v.get("PkgName"),
                    v.get("Severity"),
                    v.get("InstalledVersion"),
                    v.get("FixedVersion"),
                    v.get("Title"),
                )
            )
    return out


def run_trivy(root):
    with tempfile.TemporaryDirectory() as out:
        target = Path(out) / "report.json"
        r = sh(
            ["trivy", "fs", "--scanners", "vuln", "--offline-scan", "--format", "json"]
            + ["--output", str(target), str(root)]
        )
        if r.returncode != 0 or not target.exists():
            warn("trivy", r)
        return parse_trivy(read_json(target))


def parse_osv(doc):
    out = []
    for res in (doc or {}).get("results") or []:
        source = (res.get("source") or {}).get("path", "")
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            vulns = {v.get("id"): v for v in p.get("vulnerabilities") or []}
            groups = p.get("groups") or [{"ids": [i]} for i in vulns]
            for g in groups:
                ids = g.get("ids") or []
                aliases = set(ids)
                for i in ids:
                    aliases |= set((vulns.get(i) or {}).get("aliases") or [])
                rid = next((x for x in sorted(aliases) if x.startswith("CVE-")), None)
                rid = rid or (ids or ["unknown"])[0]
                v = next((vulns[i] for i in ids if i in vulns), {})
                fixed = next(
                    (
                        e["fixed"]
                        for af in v.get("affected") or []
                        for r in af.get("ranges") or []
                        for e in r.get("events") or []
                        if "fixed" in e
                    ),
                    None,
                )
                level = level_from_score(g.get("max_severity"))
                level = level or (v.get("database_specific") or {}).get(
                    "severity", "medium"
                )
                out.append(
                    sca_item(
                        source,
                        rid,
                        pkg.get("name"),
                        level,
                        pkg.get("version"),
                        fixed,
                        v.get("summary"),
                    )
                )
    return out


def run_osv(root):
    with tempfile.TemporaryDirectory() as out:
        target = Path(out) / "report.json"
        sh(
            ["osv-scanner", "scan", "source", "-r", "--format", "json"]
            + ["--output", str(target), str(root)]
        )
        return parse_osv(read_json(target))


def parse_grype(doc):
    out = []
    for m in (doc or {}).get("matches") or []:
        v, art = m.get("vulnerability") or {}, m.get("artifact") or {}
        rid = v.get("id")
        for rel in m.get("relatedVulnerabilities") or []:
            if str(rel.get("id")).startswith("CVE-") and not str(rid).startswith("CVE-"):
                rid = rel["id"]
                break
        where = ((art.get("locations") or [{}])[0].get("path") or "").lstrip("/")
        fixes = ", ".join((v.get("fix") or {}).get("versions") or [])
        out.append(
            sca_item(
                where,
                rid,
                art.get("name"),
                v.get("severity"),
                art.get("version"),
                fixes,
                v.get("description"),
            )
        )
    return out


def run_grype(root):
    r = sh(["grype", f"dir:{root}", "-o", "json", "-q"])
    text = r.stdout.strip()
    return parse_grype(json.loads(text) if text else {})


def parse_depcheck(doc):
    out = []
    for d in (doc or {}).get("dependencies") or []:
        pkgs = d.get("packages") or [{}]
        name = pkgs[0].get("id") or d.get("fileName")
        for v in d.get("vulnerabilities") or []:
            score = (v.get("cvssv3") or {}).get("baseScore")
            score = score or (v.get("cvssv2") or {}).get("score")
            level = str(v.get("severity") or level_from_score(score) or "medium")
            out.append(
                sca_item(
                    d.get("filePath", ""),
                    v.get("name"),
                    name,
                    level,
                    "",
                    None,
                    (v.get("description") or "")[:200],
                )
            )
    return out


def run_depcheck(root):
    with tempfile.TemporaryDirectory() as out:
        cmd = ["dependency-check.sh", "--scan", str(root), "--format", "JSON", "--out", out]
        cmd += ["--disableAssembly", "--disableOssIndex", "--disableYarnAudit"]
        cmd += ["--noupdate"] if os.environ.get("DC_NOUPDATE") else []
        key = os.environ.get("NVD_API_KEY")
        cmd += ["--nvdApiKey", key] if key else []
        sh(cmd)
        return parse_depcheck(read_json(Path(out) / "dependency-check-report.json"))


CODEQL_LANGS = {
    ".py": ("python", "python"),
    ".js": ("javascript-typescript", "javascript"),
    ".ts": ("javascript-typescript", "javascript"),
    ".java": ("java-kotlin", "java"),
    ".cs": ("csharp", "csharp"),
}


def run_codeql(root):
    found = []
    files = [p for p in sorted(Path(root).rglob("*")) if p.suffix in CODEQL_LANGS]
    for lang, pack in sorted({CODEQL_LANGS[p.suffix] for p in files}):
        with tempfile.TemporaryDirectory() as work:
            db, sarif = Path(work) / "db", Path(work) / "out.sarif"
            made = sh(
                ["codeql", "database", "create", str(db), f"--language={lang}"]
                + ["--build-mode=none", f"--source-root={root}", "--overwrite"]
            )
            if made.returncode != 0:
                continue
            suite = f"codeql/{pack}-queries:codeql-suites/{pack}-security-extended.qls"
            sh(
                ["codeql", "database", "analyze", str(db), suite]
                + ["--format=sarif-latest", f"--output={sarif}", "--threads=0"]
            )
            found += parse_sarif(read_json(sarif))
    return found


def parse_sonar(issues, hotspots):
    out = []
    for i in issues or []:
        if str(i.get("rule")).startswith("secrets:"):
            continue
        comp = str(i.get("component", "")).split(":", 1)[-1]
        out.append(
            item(
                comp,
                i.get("line"),
                i.get("rule"),
                i.get("message"),
                i.get("message"),
                str(i.get("severity")).upper() in ("BLOCKER", "CRITICAL", "MAJOR"),
            )
        )
    for h in hotspots or []:
        comp = str(h.get("component", "")).split(":", 1)[-1]
        out.append(
            item(
                comp,
                h.get("line"),
                h.get("ruleKey"),
                h.get("message"),
                f"Security hotspot: {h.get('message')}",
                str(h.get("vulnerabilityProbability")).upper() == "HIGH",
            )
        )
    return out


def sonar_get(path):
    import base64
    import urllib.error
    import urllib.request

    url = os.environ["SONAR_URL"].rstrip("/") + path
    token = base64.b64encode(f"{os.environ['SONAR_TOKEN']}:".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"[sonarqube] HTTP {e.code} {url}\n{e.read()[-800:]}", file=sys.stderr, flush=True)
        raise


def run_sonarqube(root):
    import uuid

    key = f"case-{uuid.uuid4().hex[:12]}"
    url = os.environ["SONAR_URL"]
    for dp, _, names in os.walk(root):
        os.chmod(dp, 0o755)
        for n in names:
            os.chmod(os.path.join(dp, n), 0o644)
    r = sh(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "-v",
            f"{Path(root).resolve()}:/usr/src",
        ]
        + ["-e", f"SONAR_HOST_URL={url}", "-e", f"SONAR_TOKEN={os.environ['SONAR_TOKEN']}"]
        + ["sonarsource/sonar-scanner-cli", f"-Dsonar.projectKey={key}"]
        + ["-Dsonar.scm.disabled=true", "-Dsonar.java.binaries=/usr/src"]
        + ["-Dsonar.working.directory=/tmp/scannerwork"]
        + ["-Dsonar.qualitygate.wait=true", "-Dsonar.qualitygate.timeout=300"]
    )
    if r.returncode != 0:
        warn("sonar-scanner", r)
    issues = sonar_get(f"/api/issues/search?componentKeys={key}&types=VULNERABILITY&ps=500")
    spots = sonar_get(f"/api/hotspots/search?projectKey={key}&ps=500")
    return parse_sonar(issues.get("issues"), spots.get("hotspots"))


RAW_DIR.update(
    {
        "trivy": run_trivy,
        "osv-scanner": run_osv,
        "grype": run_grype,
        "dependency-check": run_depcheck,
        "codeql": run_codeql,
        "sonarqube": run_sonarqube,
    }
)
DISPLAY.update(
    {
        "trivy": "Trivy",
        "osv-scanner": "OSV-Scanner",
        "grype": "Grype",
        "dependency-check": "Dependency-Check",
        "codeql": "CodeQL",
        "sonarqube": "SonarQube",
    }
)
