#!/usr/bin/env python3
"""SARIF 2.1.0 report aggregator for the tiangang scanner suite.

Reads the raw per-tool outputs that ``run_scan.py`` dropped into a results
directory (semgrep.sarif, bandit.json, cppcheck.xml, gosec.sarif, flawfinder.sarif,
brakeman.sarif, psalm.sarif, njsscan.sarif, eslint-security.json, cargo-audit.json,
codeql-*.sarif, …) and aggregates them into a single SARIF 2.1.0 document that
GitHub Code Scanning, Azure DevOps, SonarCloud, and IDE SARIF viewers can ingest.

Design: this script is a thin adapter on top of ``generate_report.collect_findings``,
which already normalizes the heterogeneous tool outputs into one finding-dict
shape (tool/rule/severity/file/line/message, plus optional cwe/cwe_url/fix).
Reusing that path means every parser fix and every redaction rule lives in one
place — there is no second copy of the parsers to drift. SARIF's run is emitted
under a single ``tool.driver`` named ``tiangang`` (the aggregator), with each
finding's source tool recorded in ``result.properties.tool`` so downstream
viewers can still group by origin.

Security: ``collect_findings`` already runs ``redact.redact_secrets`` on every
free-text field (P0.6), so a hardcoded credential in a SARIF ``region.snippet``
or Bandit ``code`` value cannot reach this aggregated output. We do not copy
source snippets into the aggregated SARIF — only file:line + message — so the
aggregated document is safe to upload to a third party.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
Schema:    https://json.schemastore.org/sarif-2.1.0.json

Usage:
    python3 sarif_report.py <results-dir> --output report.sarif [--validate]
    python3 sarif_report.py <results-dir>           # write SARIF to stdout
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# generate_report.py and redact.py live next to this script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_report import collect_findings  # noqa: E402

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "tiangang"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = (
    "https://github.com/anthropics/claude-code-skills/tree/main/skills/tiangang"
)

# tiangang severity (already normalized by generate_report.norm_severity) →
# SARIF result.level. SARIF level is one of: error | warning | note | none.
# Map conservatively: only critical/high escalate to error so CI gates that
# fail on `error` don't fire on low-severity noise.
_LEVEL_MAP: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "none",
}


def _severity_to_level(severity: Optional[str]) -> str:
    if not severity:
        return "none"
    return _LEVEL_MAP.get(str(severity).lower(), "none")


def _rule_id(tool: str, raw_rule: str) -> str:
    """Build a stable, namespaced ruleId.

    Different tools reuse generic ids ("SCS001", "G104", "B602"); prefixing
    with the tool keeps them from colliding when aggregated into one SARIF
    run's rules table, and gives viewers a clean group key.
    """
    rule = str(raw_rule or "unknown").strip() or "unknown"
    return f"{tool}/{rule}"


def _fingerprint(file_path: str, rule_id: str, start_line: Any) -> str:
    """Stable 16-char id so viewers can dedupe across runs.

    Deterministic (Rule: deterministic logic must not be delegated to a model) —
    same file/rule/line always yields the same id, never a random one.
    """
    raw = f"{file_path}|{rule_id}|{start_line}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def _location(file_path: str, line: Any) -> Dict[str, Any]:
    """Build a SARIF location. ``line`` may be a non-numeric placeholder ("?")."""
    region: Dict[str, Any] = {}
    if isinstance(line, int):
        region["startLine"] = max(1, line)
    elif isinstance(line, str) and line.isdigit():
        region["startLine"] = max(1, int(line))
    loc: Dict[str, Any] = {
        "artifactLocation": {"uri": str(file_path)},
    }
    if region:
        loc["region"] = region
    return {"physicalLocation": loc}


def _result_from_finding(f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert one normalized finding dict into a SARIF result object.

    Returns None when the finding has no usable file/line location — SARIF
    requires a physicalLocation.artifactLocation.uri, so we skip rather than
    emit a malformed result. The aggregator counts these skips so the caller
    can surface them.
    """
    file_path = f.get("file")
    if not file_path:
        return None
    rule_id = _rule_id(f.get("tool", "unknown"), f.get("rule", "unknown"))
    message = f.get("message") or f.get("rule") or rule_id
    # Stitch the CWE reference and fix into the human-readable message so
    # viewers that ignore result.properties still surface them; also expose
    # them as structured properties for tooling that reads properties.
    extras: List[str] = []
    if f.get("cwe_url"):
        extras.append(f"CWE: {f['cwe']} ({f['cwe_url']})")
    if f.get("fix"):
        extras.append(f"Fix: {f['fix']}")
    full_message = message if not extras else message + "\n" + "\n".join(extras)
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": _severity_to_level(f.get("severity")),
        "message": {"text": full_message},
        "locations": [_location(str(file_path), f.get("line"))],
        "fingerprints": {
            "primary": _fingerprint(str(file_path), rule_id, f.get("line")),
        },
        "properties": {
            "tool": f.get("tool", "unknown"),
            "severity": f.get("severity", "unknown"),
        },
    }
    if f.get("cwe"):
        result["properties"]["cwe"] = f["cwe"]
    if f.get("cwe_url"):
        result["properties"]["cweUrl"] = f["cwe_url"]
    return result


def _build_rules(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect unique ruleIds into SARIF rule entries for the driver.rules table.

    SARIF requires every result.ruleId to have a matching entry here (viewers
    error otherwise). We pull the short description from the first occurrence's
    message's first line.
    """
    seen: Dict[str, str] = {}
    for r in results:
        rid = r["ruleId"]
        if rid not in seen:
            seen[rid] = r["message"]["text"].split("\n")[0]
    return [
        {
            "id": rid,
            "name": rid.split("/", 1)[-1],
            "shortDescription": {"text": desc or rid},
        }
        for rid, desc in sorted(seen.items())
    ]


def to_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate normalized findings into a SARIF 2.1.0 document.

    Findings without a usable file location are skipped (SARIF requires a
    physicalLocation); the caller is expected to surface that count.
    """
    results: List[Dict[str, Any]] = []
    for f in findings:
        res = _result_from_finding(f)
        if res is not None:
            results.append(res)
    rules = _build_rules(results)
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def validate_sarif(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Structurally validate a SARIF 2.1.0 document (no network schema fetch).

    Returns (ok, errors). Self-contained by design — fetching the official
    JSON schema over the network would make a security tool depend on a
    registry being reachable, which is exactly the failure mode that bit
    run_scan.py's semgrep --config auto flow.
    """
    errors: List[str] = []
    if doc.get("$schema") != SARIF_SCHEMA:
        errors.append(f"missing/incorrect $schema (expected {SARIF_SCHEMA})")
    if doc.get("version") != SARIF_VERSION:
        errors.append(f"missing/incorrect version (expected {SARIF_VERSION})")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("runs must be a non-empty list")
        return False, errors

    valid_levels = {"error", "warning", "note", "none"}
    for ri, run in enumerate(runs):
        tool = run.get("tool")
        if not isinstance(tool, dict):
            errors.append(f"runs[{ri}].tool missing")
            continue
        driver = tool.get("driver")
        if not isinstance(driver, dict) or not driver.get("name"):
            errors.append(f"runs[{ri}].tool.driver.name missing")
        results = run.get("results", [])
        if not isinstance(results, list):
            errors.append(f"runs[{ri}].results must be a list")
            continue
        for rj, res in enumerate(results):
            prefix = f"runs[{ri}].results[{rj}]"
            if not res.get("ruleId"):
                errors.append(f"{prefix}.ruleId missing")
            level = res.get("level")
            if level not in valid_levels:
                errors.append(f"{prefix}.level={level!r} not in {sorted(valid_levels)}")
            msg = res.get("message")
            if not isinstance(msg, dict) or not msg.get("text"):
                errors.append(f"{prefix}.message.text missing")
            locs = res.get("locations")
            if not isinstance(locs, list) or not locs:
                errors.append(f"{prefix}.locations missing")
            else:
                for lk, loc in enumerate(locs):
                    pl = loc.get("physicalLocation", {})
                    if not pl.get("artifactLocation", {}).get("uri"):
                        errors.append(
                            f"{prefix}.locations[{lk}].artifactLocation.uri missing"
                        )

    return len(errors) == 0, errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate tiangang scanner findings into a SARIF 2.1.0 report.",
    )
    parser.add_argument(
        "results_dir",
        help="Directory of raw scanner outputs (produced by run_scan.py)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output SARIF file path (default: stdout)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Structurally validate the generated SARIF and report errors to stderr",
    )
    args = parser.parse_args()

    results_dir = os.path.abspath(args.results_dir)
    if not os.path.isdir(results_dir):
        print(f"error: {results_dir} is not a directory", file=sys.stderr)
        return 1

    findings, parse_errors = collect_findings(results_dir)
    if parse_errors:
        for e in parse_errors:
            print(f"warning: {e}", file=sys.stderr)

    # Findings without a usable file location are skipped by to_sarif (SARIF
    # requires a physicalLocation). Surface that count so the user knows the
    # aggregated total may be smaller than the parsed total — silent truncation
    # would read as "everything made it" when it didn't (Rule: failures must
    # be explicit).
    sarif = to_sarif(findings)
    emitted = len(sarif["runs"][0]["results"])
    skipped = len(findings) - emitted
    if skipped > 0:
        print(
            f"note: {skipped} finding(s) skipped (no file location — cannot "
            f"express in SARIF)",
            file=sys.stderr,
        )

    text = json.dumps(sarif, indent=2)
    if args.validate:
        ok, errors = validate_sarif(sarif)
        if ok:
            print(f"SARIF validation: OK ({emitted} results)", file=sys.stderr)
        else:
            print(
                f"SARIF validation FAILED ({len(errors)} error(s)):",
                file=sys.stderr,
            )
            for e in errors:
                print(f"  - {e}", file=sys.stderr)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(
            f"SARIF report written to {args.output} ({emitted} results)",
            file=sys.stderr,
        )
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
