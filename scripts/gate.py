#!/usr/bin/env python3
"""Quality gate: evaluate the scan reports against gate/policy.json.

Shadow mode (policy "enforce": false) prints what WOULD fail and always exits 0.
Enforcing mode exits 1 if any rule trips or any report is missing.
Accepted risks (gate/accepted.json) are listed but do not trip a rule until they expire.
"""
import argparse
import datetime
import json
import os
import sys
from pathlib import Path


def load(reports, name):
    path = Path(reports) / name
    if not path.is_file() or path.stat().st_size == 0:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def worst_score(package):
    scores = []
    for group in package.get("groups") or []:
        try:
            scores.append(float(group.get("max_severity")))
        except (TypeError, ValueError):
            pass
    return max(scores) if scores else None


def eval_gitleaks(rule, reports):
    data = load(reports, "gitleaks.json")
    if data is None:
        return None, "gitleaks.json is missing"
    found = [{"key": f"gitleaks:{f['RuleID']}:{f['File']}:{f['StartLine']}",
              "text": f"{f['RuleID']} at {f['File']}:{f['StartLine']}"} for f in data]
    return (found if len(found) >= rule.get("min_findings", 1) else []), None


def eval_semgrep(rule, reports):
    data = load(reports, "semgrep.json")
    if data is None:
        return None, "semgrep.json is missing"
    wanted = set(rule["severities"])
    return [{"key": f"semgrep:{r['check_id'].split('.')[-1]}:{r['path'].replace('/src/', '')}:{r['start']['line']}",
             "text": f"{r['extra']['severity']} {r['check_id'].split('.')[-1]} at {r['path'].replace('/src/', '')}:{r['start']['line']}"}
            for r in data.get("results", []) if r["extra"]["severity"] in wanted], None


def eval_osv(rule, reports):
    data = load(reports, "osv.json")
    if data is None:
        return None, "osv.json is missing"
    out = []
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            score = worst_score(pkg)
            if score is not None and score >= rule["min_score"]:
                name = f"{pkg['package']['name']}@{pkg['package']['version']}"
                out.append({"key": f"osv:{name}", "text": f"{name} worst score {score}"})
    return out, None


def eval_trivy(rule, reports):
    data = load(reports, "trivy.json")
    if data is None:
        return None, "trivy.json is missing"
    wanted = set(rule["severities"])
    out = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            if v["Severity"] in wanted and (not rule.get("require_fix") or v.get("FixedVersion")):
                name = f"{v['PkgName']}@{v['InstalledVersion']}"
                out.append({"key": f"trivy:{v['VulnerabilityID']}:{name}",
                            "text": f"{v['Severity']} {v['VulnerabilityID']} in {name} (fixed in {v.get('FixedVersion') or 'none'})"})
    return out, None


def eval_zap(rule, reports):
    out = []
    for name in ("zap-baseline.json", "zap-api.json"):
        data = load(reports, name)
        if data is None:
            return None, f"{name} is missing"
        for site in data.get("site") or []:
            for alert in site.get("alerts") or []:
                if int(alert["riskcode"]) >= rule["min_riskcode"]:
                    out.append({"key": f"zap:{alert['pluginid']}:{alert['name']}",
                                "text": f"{alert['riskdesc']} {alert['name']} ({name.split('.')[0]}, {len(alert.get('instances', []))} instance(s))"})
    return out, None


def eval_integrity(rule, reports):
    problems = []
    for name in ("gitleaks.json", "semgrep.json", "osv.json", "trivy.json", "sbom.cdx.json", "zap-baseline.json", "zap-api.json"):
        if load(reports, name) is None:
            problems.append(f"{name} is missing")
    semgrep = load(reports, "semgrep.json")
    if semgrep is not None and not (semgrep.get("paths") or {}).get("scanned"):
        problems.append("semgrep scanned no files")
    sbom = load(reports, "sbom.cdx.json")
    if sbom is not None and not sbom.get("components"):
        problems.append("the SBOM has no components")
    trivy = load(reports, "trivy.json")
    if trivy is not None and not trivy.get("Results"):
        problems.append("trivy scanned no targets")
    for name in ("zap-baseline.json", "zap-api.json"):
        zap = load(reports, name)
        if zap is not None and not zap.get("site"):
            problems.append(f"{name} has no scanned site")
    return [{"key": f"integrity:{p}", "text": p} for p in problems], None


EVALUATORS = {"gitleaks": eval_gitleaks, "semgrep": eval_semgrep, "osv": eval_osv,
              "trivy": eval_trivy, "zap": eval_zap, "integrity": eval_integrity}


def threshold_text(rule):
    bits = [f"{k}={v}" for k, v in rule.items() if k not in ("id", "tool", "description")]
    return ", ".join(bits) if bits else "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default="gate/policy.json")
    ap.add_argument("--accepted", default="gate/accepted.json")
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--today", default=datetime.date.today().isoformat(), help="for tests")
    args = ap.parse_args()

    policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    accepted = {a["key"]: a for a in json.loads(Path(args.accepted).read_text(encoding="utf-8"))
                if a.get("expires", "") >= args.today}
    enforce = bool(policy.get("enforce"))

    rows, tripped = [], False
    for rule in policy["rules"]:
        found, error = EVALUATORS[rule["tool"]](rule, args.reports)
        if error:
            rows.append((rule, "ERROR", error, [], []))
            tripped = True
            continue
        live = [f for f in found if f["key"] not in accepted]
        waived = [f for f in found if f["key"] in accepted]
        status = "TRIPPED" if live else "ok"
        tripped = tripped or bool(live)
        rows.append((rule, status, f"{len(live)} finding(s)" + (f", {len(waived)} accepted" if waived else ""), live, waived))

    mode = "ENFORCING" if enforce else "SHADOW MODE (nothing can fail yet)"
    lines = [f"Quality gate: {mode}", ""]
    lines.append(f"{'rule':<24} {'status':<8} {'threshold':<34} result")
    for rule, status, result, live, waived in rows:
        lines.append(f"{rule['id']:<24} {status:<8} {threshold_text(rule):<34} {result}")
    for rule, status, result, live, waived in rows:
        for f in live:
            lines.append(f"  - {rule['id']}: {f['text']}")
        for f in waived:
            a = accepted[f["key"]]
            lines.append(f"  - {rule['id']}: ACCEPTED until {a['expires']}: {f['text']} ({a.get('reason', 'no reason given')})")
    verdict = ("the build WOULD FAIL" if tripped else "the build would pass")
    lines += ["", ("RESULT: " + ("FAIL" if tripped else "PASS") if enforce else f"SHADOW RESULT: {verdict}")]
    text = "\n".join(lines)
    print(text)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### Quality gate (" + ("enforcing" if enforce else "shadow mode") + ")\n\n```\n" + text + "\n```\n")

    sys.exit(1 if (enforce and tripped) else 0)


if __name__ == "__main__":
    main()
