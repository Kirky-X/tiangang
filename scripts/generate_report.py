#!/usr/bin/env python3
"""
Parses the raw tool outputs left in a results directory (by run_scan.py) and
produces one unified Markdown report, findings grouped by severity then by
file. Handles SARIF (semgrep, gosec, flawfinder, brakeman, psalm, codeql),
Bandit JSON, Cppcheck XML, and cargo-audit JSON. Add a parser here for any
new tool wired into run_scan.py or referenced in tools.md.

Usage:
    python3 generate_report.py <results-dir> [--out report.md]
"""
import argparse
import json
import os
from collections import defaultdict

try:
    from defusedxml import ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def norm_severity(raw):
    if raw is None:
        return "unknown"
    s = str(raw).strip().lower()
    mapping = {
        "error": "high", "warning": "medium", "note": "low",
        "blocker": "critical", "critical": "critical",
        "high": "high", "medium": "medium", "moderate": "medium",
        "low": "low", "info": "info", "informational": "info",
        "1": "low", "2": "medium", "3": "high",  # cppcheck-style numeric/verbosity fallback
    }
    return mapping.get(s, s if s in SEVERITY_ORDER else "unknown")


def parse_sarif(path, tool_name):
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"

    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown-rule")
            rule = rules.get(rule_id, {})
            level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
            msg = result.get("message", {}).get("text", "")
            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            file_path = loc.get("artifactLocation", {}).get("uri", "unknown file")
            line = loc.get("region", {}).get("startLine", "?")
            findings.append({
                "tool": tool_name, "rule": rule_id, "severity": norm_severity(level),
                "file": file_path, "line": line, "message": msg,
            })
    return findings, None


def parse_bandit(path):
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    for r in data.get("results", []):
        findings.append({
            "tool": "bandit", "rule": r.get("test_id", "unknown"),
            "severity": norm_severity(r.get("issue_severity")),
            "file": r.get("filename", "unknown file"), "line": r.get("line_number", "?"),
            "message": r.get("issue_text", ""),
        })
    return findings, None


def parse_cppcheck(path):
    findings = []
    try:
        tree = ET.parse(path)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    for err in tree.getroot().iter("error"):
        sev = err.get("severity", "unknown")
        msg = err.get("msg", "")
        loc = err.find("location")
        file_path = loc.get("file", "unknown file") if loc is not None else "unknown file"
        line = loc.get("line", "?") if loc is not None else "?"
        findings.append({
            "tool": "cppcheck", "rule": err.get("id", "unknown"),
            "severity": norm_severity(sev), "file": file_path, "line": line, "message": msg,
        })
    return findings, None


def parse_cargo_audit(path):
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    for vuln in data.get("vulnerabilities", {}).get("list", []):
        advisory = vuln.get("advisory", {})
        pkg = vuln.get("package", {})
        findings.append({
            "tool": "cargo-audit", "rule": advisory.get("id", "unknown"),
            "severity": norm_severity(advisory.get("severity") or "high"),
            "file": "Cargo.lock", "line": "?",
            "message": f"{pkg.get('name', '?')} {pkg.get('version', '?')}: {advisory.get('title', '')}",
        })
    return findings, None


# filename (in results dir) -> (parser, tool label)
PARSERS = {
    "semgrep.sarif": (lambda p: parse_sarif(p, "semgrep"), "semgrep"),
    "gosec.sarif": (lambda p: parse_sarif(p, "gosec"), "gosec"),
    "flawfinder.sarif": (lambda p: parse_sarif(p, "flawfinder"), "flawfinder"),
    "brakeman.sarif": (lambda p: parse_sarif(p, "brakeman"), "brakeman"),
    "psalm.sarif": (lambda p: parse_sarif(p, "psalm"), "psalm"),
    "bandit.json": (parse_bandit, "bandit"),
    "cppcheck.xml": (parse_cppcheck, "cppcheck"),
    "cargo-audit.json": (parse_cargo_audit, "cargo-audit"),
}


def collect_findings(results_dir):
    all_findings = []
    parse_errors = []
    for fname, (parser, _label) in PARSERS.items():
        path = os.path.join(results_dir, fname)
        if os.path.exists(path):
            findings, err = parser(path)
            all_findings.extend(findings)
            if err:
                parse_errors.append(err)
    # any codeql-*.sarif files, one per language
    for fname in os.listdir(results_dir):
        if fname.startswith("codeql-") and fname.endswith(".sarif"):
            findings, err = parse_sarif(os.path.join(results_dir, fname), "codeql")
            all_findings.extend(findings)
            if err:
                parse_errors.append(err)
    return all_findings, parse_errors


def render_report(results_dir, findings, parse_errors, manifest):
    lines = ["# Security audit report", ""]
    lines.append(f"Target: `{manifest.get('target', results_dir)}`  ")
    lines.append(f"Languages scanned: {', '.join(manifest.get('languages', [])) or '(none detected)'}  ")
    lines.append(f"Generated: {manifest.get('timestamp', '')}")
    lines.append("")

    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f["severity"]] += 1
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITY_ORDER:
        if by_sev.get(sev):
            lines.append(f"| {sev} | {by_sev[sev]} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    skipped = manifest.get("skipped", [])
    if skipped:
        lines.append("## Tools not run")
        lines.append("")
        lines.append("These weren't installed or weren't applicable, so their coverage is missing "
                      "from this report — treat the findings below as partial, not exhaustive.")
        lines.append("")
        for s in skipped:
            lines.append(f"- **{s['tool']}**: {s['reason']}")
        lines.append("")

    if parse_errors:
        lines.append("## Parse errors")
        lines.append("")
        for e in parse_errors:
            lines.append(f"- {e}")
        lines.append("")

    if not findings:
        lines.append("No findings from the tools that ran. This does not guarantee the code is "
                      "free of security issues — it reflects the coverage of the tools listed "
                      "above, nothing more.")
        return "\n".join(lines)

    findings_sorted = sorted(findings, key=lambda f: (SEVERITY_RANK.get(f["severity"], 99), f["file"], str(f["line"])))

    lines.append("## Findings")
    lines.append("")
    current_sev = None
    for f in findings_sorted:
        if f["severity"] != current_sev:
            if current_sev is not None:
                lines.append("")
            current_sev = f["severity"]
            lines.append(f"### {current_sev.capitalize()}")
            lines.append("")
        lines.append(f"- **[{f['tool']}:{f['rule']}]** `{f['file']}:{f['line']}` — {f['message']}")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    results_dir = os.path.abspath(args.results_dir)
    manifest_path = os.path.join(results_dir, "scan_manifest.json")
    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path) as f:
            manifest = json.load(f)

    findings, parse_errors = collect_findings(results_dir)
    report = render_report(results_dir, findings, parse_errors, manifest)

    out_path = args.out or os.path.join(results_dir, "report.md")
    with open(out_path, "w") as f:
        f.write(report)

    print(f"Report written to {out_path} ({len(findings)} findings)")


if __name__ == "__main__":
    main()
