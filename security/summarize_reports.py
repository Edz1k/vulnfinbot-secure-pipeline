"""Summarize scanner reports in a directory into a Markdown table.

Usage: python security/summarize_reports.py reports/
"""

import collections
import json
import pathlib
import re
import sys

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN", "UNRATED"]


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def fmt(counter):
    if not counter:
        return "0"
    return ", ".join(f"{k}: {counter[k]}" for k in ORDER if counter.get(k)) or "0"


def bandit(d):
    c = collections.Counter(r["issue_severity"].upper() for r in d.get("results", []))
    ids = sorted({f'{r["test_id"]} {r["test_name"]}' for r in d.get("results", [])})
    return sum(c.values()), c, ids


def semgrep(d):
    sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    res = d.get("results", [])
    c = collections.Counter(sev.get(r["extra"]["severity"], "UNKNOWN") for r in res)
    ids = sorted({r["check_id"].split(".")[-1] for r in res})
    return len(res), c, ids


def pip_audit(d):
    deps = d.get("dependencies", d if isinstance(d, list) else [])
    vulns = [(x["name"], x["version"], v["id"], v.get("fix_versions")) for x in deps for v in x.get("vulns", [])]
    ids = [f"{n}=={ver}: {i} (fix: {', '.join(f) or 'n/a'})" for n, ver, i, f in vulns]
    # pip-audit reports advisories without a CVSS score -> "UNRATED"
    return len(vulns), collections.Counter({"UNRATED": len(vulns)} if vulns else {}), ids


def trivy(d):
    c, ids = collections.Counter(), []
    for res in d.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            c[v.get("Severity", "UNKNOWN")] += 1
            if v.get("Severity") in ("CRITICAL", "HIGH"):
                ids.append(f'{v["PkgName"]} {v["VulnerabilityID"]} ({v["Severity"]}, fixed: {v.get("FixedVersion") or "no fix"})')
    return sum(c.values()), c, sorted(set(ids))


def zap(d):
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    c, ids = collections.Counter(), []
    for site in d.get("site", []):
        for a in site.get("alerts", []):
            c[risk.get(str(a.get("riskcode")), "UNKNOWN")] += 1
            ids.append(f'{a["name"]} ({risk.get(str(a.get("riskcode")))})')
    return sum(c.values()), c, sorted(set(ids))


def ai(text):
    m = re.search(r"(\d+) passed, (\d+) failed, (\d+) skipped", text)
    if not m:
        return 0, collections.Counter(), []
    failed = int(m.group(2))
    return failed, collections.Counter({"HIGH": failed} if failed else {}), [m.group(0)]


ACTIONS = {
    "Bandit": "Fix HIGH issues before merge; review MEDIUM/LOW, suppress only with justification (# nosec + reason).",
    "Semgrep": "ERROR rules block the pipeline; refactor insecure patterns (eval, shell=True, secrets).",
    "pip-audit": "Upgrade affected packages to the fixed versions and re-pin requirements.txt.",
    "Trivy": "Rebuild on the latest base image; upgrade fixable packages; track unfixed CVEs.",
    "OWASP ZAP": "Add/adjust security headers; review informational alerts; run full scan before release.",
    "AI Security Tests": "Investigate any failed scenario; extend guardrails and the attack corpus.",
}


def main(directory):
    p = pathlib.Path(directory)
    rows = []
    for tool, fname, fn in [
        ("Bandit", "bandit-report.json", bandit),
        ("Semgrep", "semgrep-report.json", semgrep),
        ("pip-audit", "dependency-report.json", pip_audit),
        ("Trivy", "trivy-report.json", trivy),
        ("OWASP ZAP", "zap-report.json", zap),
    ]:
        d = load(p / fname)
        rows.append((tool, *(fn(d) if d is not None else (None, None, ["report missing"]))))
    ai_path = p / "ai-security-report.md"
    rows.append(("AI Security Tests", *(ai(ai_path.read_text(encoding="utf-8")) if ai_path.exists() else (None, None, ["report missing"]))))

    print("## Security summary\n")
    print("| Security Tool | Findings | Severity | Recommended Action |")
    print("|---|---|---|---|")
    for tool, n, c, _ in rows:
        print(f"| {tool} | {'n/a' if n is None else n} | {'n/a' if c is None else fmt(c)} | {ACTIONS[tool]} |")
    print("\n## Details\n")
    for tool, _, _, ids in rows:
        print(f"**{tool}**\n")
        for i in ids[:40] or ["no findings"]:
            print(f"- {i}")
        print()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "reports")
