#!/usr/bin/env python3
"""
Parses the raw tool outputs left in a results directory (by run_scan.py) and
produces one unified Markdown report, findings grouped by severity then by
file. Handles SARIF (semgrep, gosec, flawfinder, brakeman, psalm, codeql),
Bandit JSON, Cppcheck XML, and cargo-audit JSON. Add a parser here for any
new tool wired into run_scan.py or referenced in tools.md.

Each finding carries optional remediation metadata when the upstream tool
provides it:
  - ``cwe`` / ``cwe_url``: extracted from SARIF rule ``properties.tags`` (e.g.
    semgrep emits ``["security","cwe-78","owasp-a1"]``) or Bandit's
    ``issue_cwe`` object. Renders as a link to cwe.mitre.org.
  - ``fix``: extracted from SARIF ``result.fixes[].description.text`` (Semgrep
    emits these when a rule ships an autofix). Rendered inline.

Security: every string field is run through ``redact.redact_secrets`` before
the report is written, so a hardcoded credential surfacing inside a SARIF
``region.snippet`` or a Bandit ``code`` value cannot land on disk via the
report. This is the P0 secret-on-disk mitigation for the report path.

Usage:
    python3 generate_report.py <results-dir> [--out report.md]
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

try:
    from defusedxml import ElementTree as ET
except ImportError:
    # Fallback to stdlib ElementTree. XXE risk is mitigated because
    # ElementTree (unlike minidom/sax) does not resolve external entities
    # by default — expat's external_entity_ref_handler is None. defusedxml
    # remains the preferred parser; install it via `pip install defusedxml`.
    import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

# redact.py lives next to this script. Importing it means the secret
# redaction rules have a single source of truth (no second copy here).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redact import redact_secrets  # noqa: E402

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Match "cwe-78", "cwe/89", "CWE_1234", "cwe 22" anywhere in a tag/id.
# Used on the union of rule.tags / rule.id / bandit test_id to recover the
# CWE reference each tool emits in its own dialect.
_CWE_RE = re.compile(r"cwe[-_/ ]?(\d{1,5})", re.IGNORECASE)


def _cwe_from_iterable(values):
    """Return the first CWE id (e.g. "CWE-78") found in an iterable of strings.

    Tools are inconsistent — semgrep puts "cwe-78" in properties.tags, gosec
    uses "G104" ids, flawfinder embeds the CWE in rule metadata. Walk whatever
    iterable the caller hands us and return the first plausible match; None
    when nothing looks like a CWE.
    """
    if not values:
        return None
    if isinstance(values, str):
        values = [values]
    for v in values:
        if not isinstance(v, str):
            continue
        m = _CWE_RE.search(v)
        if m:
            num = int(m.group(1))
            if 1 <= num <= 2000:  # guard against nonsense like "cwe-99999"
                return f"CWE-{num}"
    return None


def _cwe_url(cwe_id):
    """Map "CWE-78" → "https://cwe.mitre.org/data/definitions/78.html"."""
    if not cwe_id:
        return None
    m = re.search(r"(\d+)", cwe_id)
    if not m:
        return None
    return f"https://cwe.mitre.org/data/definitions/{int(m.group(1))}.html"


def _fix_from_sarif_result(result, rule):
    """Extract a human-readable fix string from a SARIF result/rule pair.

    Semgrep emits autofixes under ``result.fixes[].description.text``. Some
    tools instead annotate the rule (``rule.properties.fix``). Prefer the
    per-result fix (specific to this occurrence) and fall back to the rule.
    Returns "" when neither is present — most rules don't carry a fix.
    """
    for fix in result.get("fixes", []) or []:
        desc = fix.get("description", {})
        text = desc.get("text") if isinstance(desc, dict) else None
        if text:
            return text
    props = rule.get("properties", {}) if isinstance(rule, dict) else {}
    if isinstance(props, dict):
        rule_fix = props.get("fix")
        if isinstance(rule_fix, str) and rule_fix.strip():
            return rule_fix.strip()
    return ""


def norm_severity(raw):
    if raw is None:
        return "unknown"
    s = str(raw).strip().lower()
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "blocker": "critical",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        # cppcheck severity values: error/warning/style/performance/portability
        "style": "low",
        "performance": "low",
        "portability": "low",
        "1": "low",
        "2": "medium",
        "3": "high",  # cppcheck-style numeric/verbosity fallback
    }
    return mapping.get(s, s if s in SEVERITY_ORDER else "unknown")


def _line_sort_key(line):
    """Sort key for finding line numbers: numeric lines first (ascending),
    non-numeric (e.g. "?") last. Avoids the string-dictionary bug where
    "1"/"10"/"2" would sort as 1 → 10 → 2 instead of 1 → 2 → 10.

    Returns a tuple (group, value) so numeric and non-numeric lines never
    interleave by accident.
    """
    s = str(line)
    if s.isdigit():
        return (0, int(s))
    return (1, s)


def parse_sarif(path, tool_name):
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"

    for run in data.get("runs", []):
        rules_list = run.get("tool", {}).get("driver", {}).get("rules", [])
        rules = {r.get("id"): r for r in rules_list if "id" in r}
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            if rule_id is None:
                # SARIF allows referencing rules by index; guard against out-of-range
                rule_idx = result.get("ruleIndex")
                if isinstance(rule_idx, int) and 0 <= rule_idx < len(rules_list):
                    rule_id = rules_list[rule_idx].get("id", "unknown-rule")
                else:
                    rule_id = "unknown-rule"
            rule = rules.get(rule_id, {})
            level = result.get("level") or rule.get("defaultConfiguration", {}).get(
                "level"
            )
            msg = result.get("message", {}).get("text", "")
            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            file_path = loc.get("artifactLocation", {}).get("uri", "unknown file")
            line = loc.get("region", {}).get("startLine", "?")
            # P1.4: recover CWE + autofix metadata when the tool emits them.
            # properties.tags is the SARIF convention (semgrep, codeql, gosec
            # all populate it); rule.id is a fallback some tools use instead.
            props = rule.get("properties", {}) if isinstance(rule, dict) else {}
            tag_sources = []
            if isinstance(props, dict):
                tag_sources.append(props.get("tags"))
                tag_sources.append(props.get("cwe"))
            tag_sources.append(rule_id)
            cwe = _cwe_from_iterable(tag_sources)
            finding = {
                "tool": tool_name,
                "rule": rule_id,
                "severity": norm_severity(level),
                "file": file_path,
                "line": line,
                "message": msg,
            }
            if cwe:
                finding["cwe"] = cwe
                finding["cwe_url"] = _cwe_url(cwe)
            fix = _fix_from_sarif_result(result, rule)
            if fix:
                finding["fix"] = fix
            findings.append(finding)
    return findings, None


def parse_bandit(path):
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    for r in data.get("results", []):
        finding = {
            "tool": "bandit",
            "rule": r.get("test_id", "unknown"),
            "severity": norm_severity(r.get("issue_severity")),
            "file": r.get("filename", "unknown file"),
            "line": r.get("line_number", "?"),
            "message": r.get("issue_text", ""),
        }
        # P1.4: Bandit ships issue_cwe as {"id": <int>, "link": "<url>"}.
        # Map to the same cwe/cwe_url shape used by parse_sarif so the
        # renderer and SARIF aggregator share one code path.
        cwe_obj = r.get("issue_cwe") or {}
        if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
            finding["cwe"] = f"CWE-{int(cwe_obj['id'])}"
            finding["cwe_url"] = cwe_obj.get("link") or _cwe_url(finding["cwe"])
        findings.append(finding)
    return findings, None


def parse_cppcheck(path):
    findings = []
    try:
        # ET comes from defusedxml when installed (preferred); the stdlib
        # fallback (see import above) is safe because ElementTree does not
        # resolve external entities by default. nosemgrep suppresses the
        # static flag on the fallback path.
        tree = ET.parse(path)  # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    for err in tree.getroot().iter("error"):
        sev = err.get("severity", "unknown")
        msg = err.get("msg", "")
        loc = err.find("location")
        file_path = (
            loc.get("file", "unknown file") if loc is not None else "unknown file"
        )
        line = loc.get("line", "?") if loc is not None else "?"
        findings.append(
            {
                "tool": "cppcheck",
                "rule": err.get("id", "unknown"),
                "severity": norm_severity(sev),
                "file": file_path,
                "line": line,
                "message": msg,
            }
        )
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
        # RUSTSEC advisories: severity is optional; when absent, default to MEDIUM
        # (not HIGH — over-rating noise vulnerabilities drowns out real critical ones)
        findings.append(
            {
                "tool": "cargo-audit",
                "rule": advisory.get("id", "unknown"),
                "severity": norm_severity(advisory.get("severity") or "medium"),
                "file": "Cargo.lock",
                "line": "?",
                "message": f"{pkg.get('name', '?')} {pkg.get('version', '?')}: {advisory.get('title', '')}",
            }
        )
    return findings, None


def parse_security_code_scan(path):
    """Parse Security Code Scan (.NET Roslyn analyzer) JSON output.

    Expected format: a JSON array of objects with fields like:
      [{"ruleId": "SCS001", "severity": "Warning", "message": "...",
        "file": "...", "line": 42}, ...]
    Falls back gracefully if the shape differs.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    items = data if isinstance(data, list) else data.get("results", [])
    for r in items:
        findings.append(
            {
                "tool": "security-code-scan",
                "rule": r.get("ruleId", r.get("rule", "unknown")),
                "severity": norm_severity(r.get("severity")),
                "file": r.get("file", r.get("location", "unknown file")),
                "line": r.get("line", "?"),
                "message": r.get("message", ""),
            }
        )
    return findings, None


def parse_miri_log(path):
    """Parse Miri (Rust UB detector) text log.

    Looks for lines like:
      error: Undefined Behavior: ... at src/foo.rs:42:15
    """
    findings = []
    try:
        with open(path) as f:
            for line in f:
                if "error: Undefined Behavior" not in line:
                    continue
                # Try to extract file:line from trailing " at <path>:<line>:<col>"
                file_path = "unknown file"
                line_no = "?"
                if " at " in line:
                    loc_part = line.rsplit(" at ", 1)[-1].strip()
                    # loc_part looks like "src/foo.rs:42:15"
                    parts = loc_part.rsplit(":", 2)
                    if len(parts) >= 2:
                        file_path = parts[0]
                        line_no = parts[1]
                findings.append(
                    {
                        "tool": "miri",
                        "rule": "undefined-behavior",
                        "severity": "high",
                        "file": file_path,
                        "line": line_no,
                        "message": line.split("error: Undefined Behavior:", 1)[
                            -1
                        ].strip()
                        if "error: Undefined Behavior:" in line
                        else line.strip(),
                    }
                )
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    return findings, None


def parse_eslint_security(path):
    """Parse ESLint JSON output (eslint --format json) for security findings.

    The standard eslint JSON formatter emits a list of per-file result objects:
      [{"filePath": "/abs", "messages": [{"ruleId": "security/detect-eval-with-expression",
        "severity": 2, "message": "...", "line": 42, "column": 5}], ...}]
    severity 1 = warning, 2 = error. Only messages carrying a `security/*`
    ruleId are real findings — without that filter, a project's whole eslint
    output (style, import order, etc.) would flood the report. We surface the
    rest of eslint by skipping non-security rules here.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    if not isinstance(data, list):
        return [], f"unexpected eslint json shape in {path} (expected list)"
    for file_entry in data:
        if not isinstance(file_entry, dict):
            continue
        file_path = file_entry.get("filePath") or "unknown file"
        for msg in file_entry.get("messages", []) or []:
            rule_id = msg.get("ruleId") or "unknown"
            # Only collect eslint-plugin-security findings — eslint output
            # otherwise carries every lint rule the project configured.
            if not rule_id.startswith("security/"):
                continue
            sev = "high" if msg.get("severity") == 2 else "low"
            findings.append(
                {
                    "tool": "eslint-security",
                    "rule": rule_id,
                    "severity": norm_severity(sev),
                    "file": file_path,
                    "line": msg.get("line", "?"),
                    "message": msg.get("message", ""),
                }
            )
    return findings, None


def _cvss_to_severity(score):
    """Map a CVSS v3 base score (0.0–10.0) to a tiangang severity bucket.

    Uses the standard CVSS v3 severity bands so trivy findings without an
    explicit Severity field still get a defensible rating rather than
    defaulting to "unknown" and being buried at the bottom of the report.
    """
    if score is None:
        return "unknown"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


def _trivy_cvss_score(vuln):
    """Extract a numeric CVSS v3 score from a trivy vulnerability entry.

    trivy nests the score under any of several vendor keys (nvd, redhat,
    ghsa, …). Walk them in preference order and return the first numeric
    V3Score; None when no score is present.
    """
    cvss = vuln.get("CVSS") or {}
    if not isinstance(cvss, dict):
        return None
    for vendor in ("nvd", "redhat", "ghsa", "oracleoval"):
        block = cvss.get(vendor) or {}
        if isinstance(block, dict):
            for key in ("V3Score", "V2Score"):
                v = block.get(key)
                if isinstance(v, (int, float)):
                    return float(v)
    return None


def parse_trivy(path):
    """Parse `trivy fs --scanners vuln --format json` output.

    Walks ``.Results[].Vulnerabilities[]`` and emits one finding per CVE.
    Severity comes from trivy's ``Severity`` field (HIGH/CRITICAL/…) when
    present, falling back to the CVSS v3 score bands via ``_cvss_to_severity``
    so advisories that omit the string severity still get a defensible rating.

    The lockfile path (``Target``) becomes the finding ``file`` so the report
    points the reviewer at the manifest that pins the vulnerable dependency.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    for result in data.get("Results", []) or []:
        target = result.get("Target", "unknown lockfile")
        for vuln in result.get("Vulnerabilities", []) or []:
            cve = vuln.get("VulnerabilityID", "unknown-cve")
            pkg = vuln.get("PkgName", "?")
            installed = vuln.get("InstalledVersion", "?")
            fixed = vuln.get("FixedVersion", "")
            sev_raw = vuln.get("Severity")
            if sev_raw:
                severity = norm_severity(sev_raw)
            else:
                severity = _cvss_to_severity(_trivy_cvss_score(vuln))
            message = f"{pkg} {installed}: {cve}"
            if fixed:
                message += f" (fixed in {fixed})"
            finding = {
                "tool": "trivy",
                "rule": cve,
                "severity": severity,
                "file": target,
                "line": "?",
                "message": message,
            }
            findings.append(finding)
    return findings, None


def parse_gitleaks(path):
    """Parse `gitleaks detect --report-format json` output.

    gitleaks emits a JSON array of findings. The ``Secret`` and ``Match``
    fields carry the actual credential value — they MUST NOT be copied into
    the finding ``message``, otherwise the report becomes a secret-on-disk
    (the exact P0 the redact module exists to prevent). We surface the rule
    id, file, and line so the reviewer can locate and rotate the credential
    without the value being persisted.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    if not isinstance(data, list):
        return [], f"unexpected gitleaks json shape in {path} (expected list)"
    for r in data:
        if not isinstance(r, dict):
            continue
        rule_id = r.get("RuleID") or r.get("Description") or "unknown-rule"
        file_path = r.get("File", "unknown file")
        line = r.get("StartLine", "?")
        # message intentionally excludes Secret/Match — never persist the value.
        message = f"Hardcoded secret detected by rule '{rule_id}'"
        entropy = r.get("Entropy")
        if entropy is not None:
            message += f" (entropy={entropy})"
        findings.append(
            {
                "tool": "gitleaks",
                "rule": rule_id,
                "severity": "high",
                "file": file_path,
                "line": line,
                "message": message,
            }
        )
    return findings, None


def parse_trufflehog(path):
    """Parse `trufflehog filesystem --json` output (JSONL, one record per line).

    trufflehog streams newline-delimited JSON. The ``Raw`` and ``Redacted``
    fields carry the credential — like gitleaks, they MUST NOT be copied into
    the finding message. Verified secrets are escalated to critical (trufflehog
    has confirmed they're live); unverified ones stay at high.

    Non-JSON lines (progress logs, preamble) are skipped rather than crashing.
    """
    findings = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    for line in lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        detector = r.get("DetectorName", "unknown-detector")
        verified = bool(r.get("Verified", False))
        # path lives under SourceMetadata.Data.Filesystem.path
        fs_meta = (r.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem", {})
        file_path = fs_meta.get("path", "unknown file")
        severity = "critical" if verified else "high"
        status = "verified" if verified else "unverified"
        # message intentionally excludes Raw/Redacted — never persist the value.
        message = f"Secret detected by {detector} detector ({status})"
        findings.append(
            {
                "tool": "trufflehog",
                "rule": detector,
                "severity": severity,
                "file": file_path,
                "line": "?",
                "message": message,
            }
        )
    return findings, None


def parse_retire(path):
    """Parse `retire --outputformat json` output (frontend known-CVE library scan).

    retire.js emits a list of components, each carrying one or more
    vulnerabilities. Each CVE becomes its own finding so the report matches
    the one-finding-per-CVE shape used by the trivy SCA channel — reviewers
    can triage and fix CVE-by-CVE rather than a single noisy component entry.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    if not isinstance(data, list):
        return [], f"unexpected retire json shape in {path} (expected list)"
    for comp in data:
        if not isinstance(comp, dict):
            continue
        component = comp.get("component", "?")
        version = comp.get("version", "?")
        file_path = comp.get("path", "unknown file")
        for result in comp.get("results", []) or []:
            for vuln in result.get("vulnerabilities", []) or []:
                severity = norm_severity(vuln.get("severity", "medium"))
                identifiers = vuln.get("identifiers") or {}
                cves = []
                if isinstance(identifiers, dict):
                    cves = list(identifiers.get("CVE", []) or [])
                if not cves:
                    # No CVE mapped — use retire's internal id so the finding
                    # still surfaces, rather than dropping it silently.
                    rule_id = f"retire-{vuln.get('id', 'unknown')}"
                else:
                    rule_id = cves[0]
                message = f"{component} {version}: {rule_id}"
                findings.append(
                    {
                        "tool": "retire",
                        "rule": rule_id,
                        "severity": severity,
                        "file": file_path,
                        "line": "?",
                        "message": message,
                    }
                )
    return findings, None


def parse_trivy_version(path):
    """Parse `trivy version --format json` output to surface DB staleness.

    trivy returns zero findings when its vulnerability DB is stale, which
    masquerades as "secure" — exactly the false-negative this signal exists
    to catch. We emit a single `medium` finding when the DB is older than
    14 days so the report explicitly says "trivy DB is N days old, run
    `trivy db update`" rather than silently showing zero trivy findings.

    No finding is emitted when the DB is fresh or the version JSON is
    malformed (the latter produces a parse error so collect_findings logs it).
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    db_info = data.get("VulnerabilityDB") or {}
    if not isinstance(db_info, dict):
        return [], None
    updated = db_info.get("UpdatedAt") or db_info.get("CreatedAt")
    if not updated:
        # No timestamp to check — don't fabricate a finding, just pass through.
        return [], None
    try:
        # trivy emits RFC3339 timestamps (e.g. "2026-07-01T12:00:00Z").
        # Python <3.11 datetime.fromisoformat doesn't parse "Z" suffix; replace it.
        ts = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - ts).days
    except (ValueError, TypeError):
        return [], None
    if age_days < 0:
        # Future timestamp — clock skew, don't false-alarm.
        return [], None
    if age_days <= 14:
        return [], None
    return [
        {
            "tool": "trivy-version",
            "rule": "stale-vuln-db",
            "severity": "medium",
            "file": "trivy-version.json",
            "line": "?",
            "message": (
                f"trivy vulnerability DB is {age_days} days old "
                f"(UpdatedAt={updated}) — run `trivy db update`. "
                f"A stale DB can return zero findings for known CVEs; "
                f"treat any clean trivy result with caution."
            ),
        }
    ], None


def parse_checkov(path):
    """Parse checkov JSON output (IaC security scanner).

    checkov emits a JSON object with a "results" key containing
    "passed_checks" and "failed_checks" lists. We only report failed checks
    — passed checks are noise in a security report.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    results = data.get("results") or {}
    if not isinstance(results, dict):
        return [], None
    for check in results.get("failed_checks", []) or []:
        if not isinstance(check, dict):
            continue
        check_id = check.get("check_id", "unknown-check")
        resource = check.get("resource", "unknown-resource")
        file_path = check.get("file_path", "unknown file")
        file_path = file_path.lstrip("/") if file_path else "unknown file"
        line_range = check.get("file_line_range")
        line_no = line_range[0] if isinstance(line_range, list) and line_range else "?"
        severity = norm_severity(check.get("severity"))
        guideline = check.get("guideline", "")
        message = f"{check_id}: {check.get('name', '')} (resource: {resource})"
        if guideline:
            message += f" — see {guideline}"
        findings.append({
            "tool": "checkov", "rule": check_id, "severity": severity,
            "file": file_path, "line": line_no, "message": message,
        })
    return findings, None


def parse_tfsec(path):
    """Parse tfsec JSON output (Terraform-specific security scanner)."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    results = data.get("results") if isinstance(data, dict) else data
    if not isinstance(results, list):
        return [], None
    for r in results:
        if not isinstance(r, dict):
            continue
        rule_id = r.get("rule_id") or r.get("ruleID") or "unknown-rule"
        severity = norm_severity(r.get("severity"))
        location = r.get("location", {}) or {}
        file_path = location.get("filename", "unknown file")
        line = location.get("start_line", "?")
        message = r.get("description", "") or r.get("rule_description", "")
        if r.get("resolution"):
            message += f" — fix: {r['resolution']}"
        findings.append({
            "tool": "tfsec", "rule": rule_id, "severity": severity,
            "file": file_path, "line": line, "message": message,
        })
    return findings, None


def parse_ocr(path):
    """Parse OCR (open-code-review) JSON output (AI-powered code review).

    OCR emits a JSON array of review comments, each with:
      - path: file path
      - content: review comment text
      - start_line / end_line: line range
      - category: bug|security|performance|maintainability|test|style|documentation|other
      - severity: critical|high|medium|low
      - suggestion_code: optional fix suggestion

    The ``content`` field is mapped to finding ``message``; ``suggestion_code``
    to ``fix``. Category is encoded in the ``rule`` field as ``ocr/<category>``
    so it's visible in the report alongside the tool name. ``content`` is run
    through ``redact_secrets`` via the standard post-processing pipeline — OCR
    may include code snippets that contain hardcoded credentials.
    """
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        return [], f"could not parse {path}: {e}"
    if not isinstance(data, list):
        return [], f"unexpected ocr json shape in {path} (expected list)"
    for r in data:
        if not isinstance(r, dict):
            continue
        category = r.get("category", "other")
        severity = norm_severity(r.get("severity"))
        file_path = r.get("path", "unknown file")
        line = r.get("start_line", "?")
        content = r.get("content", "")
        finding = {
            "tool": "ocr",
            "rule": f"ocr/{category}",
            "severity": severity,
            "file": file_path,
            "line": line,
            "message": content,
        }
        suggestion = r.get("suggestion_code")
        if suggestion:
            finding["fix"] = suggestion
        findings.append(finding)
    return findings, None


# filename (in results dir) -> (parser, tool label)
PARSERS = {
    "semgrep.sarif": (lambda p: parse_sarif(p, "semgrep"), "semgrep"),
    "semgrep-agent.sarif": (lambda p: parse_sarif(p, "semgrep-agent"), "semgrep-agent"),
    "gosec.sarif": (lambda p: parse_sarif(p, "gosec"), "gosec"),
    "flawfinder.sarif": (lambda p: parse_sarif(p, "flawfinder"), "flawfinder"),
    "brakeman.sarif": (lambda p: parse_sarif(p, "brakeman"), "brakeman"),
    "psalm.sarif": (lambda p: parse_sarif(p, "psalm"), "psalm"),
    "findsecbugs.sarif": (lambda p: parse_sarif(p, "findsecbugs"), "findsecbugs"),
    "njsscan.sarif": (lambda p: parse_sarif(p, "njsscan"), "njsscan"),
    "bandit.json": (parse_bandit, "bandit"),
    "cppcheck.xml": (parse_cppcheck, "cppcheck"),
    "cargo-audit.json": (parse_cargo_audit, "cargo-audit"),
    "security-code-scan.json": (parse_security_code_scan, "security-code-scan"),
    "eslint-security.json": (parse_eslint_security, "eslint-security"),
    "miri.log": (parse_miri_log, "miri"),
    # SCA + secret channels absorbed from strix's source-aware SAST playbook.
    # trivy covers all major ecosystems (npm/pypi/go/maven/rubygems/cargo/…)
    # via lockfile scanning; gitleaks + trufflehog form an independent secret
    # channel so hardcoded credentials don't depend solely on semgrep p/secrets.
    "trivy.json": (parse_trivy, "trivy"),
    "trivy-version.json": (parse_trivy_version, "trivy-version"),
    "gitleaks.json": (parse_gitleaks, "gitleaks"),
    "trufflehog.jsonl": (parse_trufflehog, "trufflehog"),
    "retire.json": (parse_retire, "retire"),
    # IaC security scanners — Terraform/K8s/Docker/CloudFormation
    "checkov.json": (parse_checkov, "checkov"),
    "tfsec.json": (parse_tfsec, "tfsec"),
    # AI-powered code review — opt-in via --ocr / --ocr-delegate.
    "ocr.json": (parse_ocr, "ocr"),
}


# Proximity window (lines) for cross-tool CWE dedup tier 3.
# Tools may report slightly different line numbers for the same issue;
# 5 lines is generous enough to catch most off-by-a-few cases without
# merging unrelated findings.
_PROXIMITY_LINES = 5


def _merge_confirmation(deduped, f):
    """Merge a duplicate finding's tool into the surviving entry's confirmed_by.

    When two tools flag the same issue (different rule IDs, same CWE+location),
    the dedup keeps the first (higher-priority tool) but records that the
    second tool also confirmed it. This `confirmed_by` list is used downstream
    for triage: findings confirmed by 2+ tools are more likely true positives.
    """
    if not deduped:
        return
    surviving = deduped[-1]
    tool = f.get("tool", "")
    if tool and tool != surviving.get("tool"):
        confirmed = surviving.setdefault("confirmed_by", [])
        if tool not in confirmed:
            confirmed.append(tool)


def _proximity_match(deduped, proximity_list, f):
    """Check if finding ``f`` matches any existing finding within ±5 lines + same CWE.

    Returns True if a proximity match is found (caller should skip this
    finding). The proximity list is a list of (file, line_int, cwe, idx) tuples.
    """
    try:
        f_line = int(f["line"])
    except (ValueError, TypeError):
        return False
    f_file = f["file"]
    f_cwe = f.get("cwe")
    for p_file, p_line, p_cwe, _idx in proximity_list:
        if p_file == f_file and p_cwe == f_cwe and abs(p_line - f_line) <= _PROXIMITY_LINES:
            return True
    return False


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
    # Deduplicate cross-tool findings: different tools (e.g. semgrep + bandit)
    # may flag the same issue at the same file:line:rule. Keep the first
    # occurrence (tools are iterated in PARSERS order, which lists semgrep
    # first — its findings win ties).
    # Three-tier dedup:
    #   1. Exact: same (file, line, rule) — always deduped.
    #   2. Cross-tool CWE: same (file, line) with same CWE — deduped, keeping
    #      the first (higher-priority tool).
    #   3. Proximity CWE: same file, same CWE, lines within ±5 — deduped.
    #      Catches cases where tools report slightly different line numbers
    #      for the same underlying issue.
    # Multi-tool confirmation: when dedup merges findings from different tools,
    # the surviving finding gets a `confirmed_by` list for triage priority.
    seen_exact = set()
    seen_cwe_by_location = {}  # (file, line) -> set of CWE ids
    seen_cwe_by_proximity = []  # list of (file, line_int, cwe, idx_in_deduped)
    deduped = []
    for f in all_findings:
        key = (f["file"], str(f["line"]), f["rule"])
        if key in seen_exact:
            # Same exact finding — attribute to existing entry's confirmed_by.
            _merge_confirmation(deduped, f)
            continue
        seen_exact.add(key)
        cwe = f.get("cwe")
        loc = (f["file"], str(f["line"]))
        # Tier 2: exact location + same CWE.
        if cwe and loc in seen_cwe_by_location and cwe in seen_cwe_by_location[loc]:
            _merge_confirmation(deduped, f)
            continue
        # Tier 3: proximity (±5 lines) + same CWE on same file.
        if cwe and _proximity_match(deduped, seen_cwe_by_proximity, f):
            _merge_confirmation(deduped, f)
            continue
        if cwe:
            seen_cwe_by_location.setdefault(loc, set()).add(cwe)
            try:
                line_int = int(f["line"])
            except (ValueError, TypeError):
                line_int = None
            if line_int is not None:
                seen_cwe_by_proximity.append((f["file"], line_int, cwe, len(deduped)))
        deduped.append(f)
    # P0.6: redact known secret shapes from any free-text field before the
    # report is written. A hardcoded credential surfacing in a SARIF message
    # or a Bandit issue_text would otherwise turn the report itself into a
    # secret-on-disk. redact_secrets is a no-op when no pattern matches, so
    # findings without secret-shaped content are unchanged.
    for f in deduped:
        if isinstance(f.get("message"), str):
            f["message"] = redact_secrets(f["message"])
        if isinstance(f.get("fix"), str):
            f["fix"] = redact_secrets(f["fix"])
    return deduped, parse_errors


def render_report(results_dir, findings, parse_errors, manifest):
    lines = ["# Security audit report", ""]
    lines.append(f"Target: `{manifest.get('target', results_dir)}`  ")
    lines.append(
        f"Languages scanned: {', '.join(manifest.get('languages', [])) or '(none detected)'}  "
    )
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
        lines.append(
            "These weren't installed or weren't applicable, so their coverage is missing "
            "from this report — treat the findings below as partial, not exhaustive."
        )
        lines.append("")
        for s in skipped:
            lines.append(f"- **{s['tool']}**: {s['reason']}")
        lines.append("")

    # T-P1-4: surface tools that were attempted but failed (non-zero exit) —
    # a clean-looking report must not silently hide a crashed scanner.
    failed_tools = [r for r in manifest.get("ran", []) if r.get("returncode", 0) != 0]
    if failed_tools:
        lines.append("## Tools attempted but failed")
        lines.append("")
        lines.append(
            "These tools were invoked but exited non-zero — their coverage is missing "
            "from the findings below. Treat the report as partial; investigate the "
            "failures before relying on a clean result."
        )
        lines.append("")
        for r in failed_tools:
            tail = r.get("log_tail", "")
            lines.append(
                f"- **{r['tool']}** (exit {r['returncode']}): {tail[-300:] if tail else '(no output)'}"
            )
        lines.append("")

    if parse_errors:
        lines.append("## Parse errors")
        lines.append("")
        for e in parse_errors:
            lines.append(f"- {e}")
        lines.append("")

    if not findings:
        lines.append(
            "No findings from the tools that ran. This does not guarantee the code is "
            "free of security issues — it reflects the coverage of the tools listed "
            "above, nothing more."
        )
        return "\n".join(lines)

    findings_sorted = sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(f["severity"], 99),
            f["file"],
            _line_sort_key(f["line"]),
        ),
    )

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
        # P1.4: append CWE link and the tool-proffered fix inline, so a
        # reviewer can both triage by weakness category and apply the
        # remediation without leaving the report.
        cwe_url = f.get("cwe_url")
        if cwe_url and f.get("cwe"):
            cwe_part = f" ([{f['cwe']}]({cwe_url}))"
        else:
            cwe_part = ""
        lines.append(
            f"- **[{f['tool']}:{f['rule']}]** `{f['file']}:{f['line']}` — {f['message']}{cwe_part}"
        )
        if f.get("fix"):
            lines.append(f"  - **Fix:** {f['fix']}")
    lines.append("")

    return "\n".join(lines)


def render_html_report(results_dir, findings, parse_errors, manifest):
    """Render a self-contained HTML report with severity-colored cards.

    The HTML is a single file with inline CSS — no external dependencies.
    Findings are grouped by severity (critical → info) with color-coded badges.
    """
    import html as html_mod
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f["severity"]] += 1
    sev_colors = {
        "critical": "#d32f2f", "high": "#f57c00", "medium": "#fbc02d",
        "low": "#388e3c", "info": "#1976d2", "unknown": "#757575",
    }
    target = html_mod.escape(manifest.get("target", results_dir))
    langs = ", ".join(manifest.get("languages", [])) or "(none detected)"
    ts = html_mod.escape(manifest.get("timestamp", ""))
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>Security Audit Report — {target}</title>",
        "<style>",
        "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }",
        "h1 { margin-bottom: 0.5rem; } .meta { color: #666; margin-bottom: 2rem; }",
        ".summary { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 2rem; }",
        ".badge { padding: 0.25rem 0.75rem; border-radius: 4px; color: white; font-weight: 600; font-size: 0.85rem; }",
        ".finding { border-left: 4px solid #ccc; padding: 0.5rem 1rem; margin-bottom: 0.75rem; background: #fafafa; }",
        ".finding .loc { font-family: monospace; font-size: 0.9rem; }",
        ".finding .msg { margin-top: 0.25rem; }",
        ".confirmed { color: #1976d2; font-size: 0.8rem; }",
        "</style></head><body>",
        f"<h1>Security Audit Report</h1>",
        f'<div class="meta">Target: <code>{target}</code><br>Languages: {html_mod.escape(langs)}<br>Generated: {ts}</div>',
        '<div class="summary">',
    ]
    for sev in SEVERITY_ORDER:
        cnt = by_sev.get(sev, 0)
        if cnt:
            color = sev_colors.get(sev, "#757575")
            parts.append(f'<span class="badge" style="background:{color}">{sev.upper()}: {cnt}</span>')
    parts.append(f'<span class="badge" style="background:#424242">Total: {len(findings)}</span>')
    parts.append("</div>")
    if not findings:
        parts.append("<p>No findings. This does not guarantee the code is free of security issues.</p>")
    else:
        findings_sorted = sorted(
            findings,
            key=lambda f: (SEVERITY_RANK.get(f["severity"], 99), f["file"], _line_sort_key(f["line"])),
        )
        current_sev = None
        for f in findings_sorted:
            if f["severity"] != current_sev:
                if current_sev is not None:
                    parts.append("</div>")
                current_sev = f["severity"]
                color = sev_colors.get(current_sev, "#757575")
                parts.append(f'<h2 style="color:{color}">{current_sev.capitalize()}</h2><div>')
            tool_rule = html_mod.escape(f"{f['tool']}:{f['rule']}")
            loc = html_mod.escape(f"{f['file']}:{f['line']}")
            msg = html_mod.escape(f.get("message", ""))
            confirmed = f.get("confirmed_by", [])
            confirmed_html = ""
            if confirmed:
                confirmed_html = f' <span class="confirmed">(confirmed by: {html_mod.escape(", ".join(confirmed))})</span>'
            parts.append(
                f'<div class="finding" style="border-color:{sev_colors.get(f["severity"], "#ccc")}">'
                f'<span class="loc">[{tool_rule}] {loc}</span>'
                f'<div class="msg">{msg}{confirmed_html}</div></div>'
            )
        parts.append("</div>")
    parts.append("</body></html>")
    return "\n".join(parts)


def render_json_report(results_dir, findings, parse_errors, manifest):
    """Render a JSON report with all findings and metadata.

    Machine-readable format for downstream tooling (dashboards, CI gates,
    trend tracking). Same structure as the Markdown report but as JSON.
    """
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f["severity"]] += 1
    return json.dumps({
        "target": manifest.get("target", results_dir),
        "languages": manifest.get("languages", []),
        "timestamp": manifest.get("timestamp", ""),
        "summary": {"total": len(findings), **dict(by_sev)},
        "skipped_tools": manifest.get("skipped", []),
        "parse_errors": parse_errors,
        "findings": findings,
    }, indent=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir")
    parser.add_argument("--out", default=None)
    parser.add_argument(
        "--format",
        choices=["md", "html", "json", "all"],
        default="md",
        help="Output format (default: md). 'all' writes md + html + json.",
    )
    parser.add_argument(
        "--triage",
        action="store_true",
        help="Generate LLM triage prompt for false positive assessment.",
    )
    parser.add_argument(
        "--trend",
        action="store_true",
        help="Include trend comparison with previous scans in the report.",
    )
    args = parser.parse_args()

    results_dir = os.path.abspath(args.results_dir)
    manifest_path = os.path.join(results_dir, "scan_manifest.json")
    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path) as f:
            manifest = json.load(f)

    findings, parse_errors = collect_findings(results_dir)

    # Save trend entry for this scan.
    save_trend_entry(results_dir, findings, manifest)

    # Load trend history if --trend requested.
    trend_section = ""
    if args.trend:
        history = load_trend_history(results_dir)
        trend_section = render_trend_section(history, findings)

    # Generate triage prompt if --triage requested.
    if args.triage and findings:
        prompt = generate_triage_prompt(findings)
        triage_path = args.out and args.out.replace(".md", ".triage.txt") or os.path.join(results_dir, "triage_prompt.txt")
        with open(triage_path, "w") as f:
            f.write(prompt)
        print(f"Triage prompt written to {triage_path} ({len(findings)} findings)")

    formats = ["md", "html", "json"] if args.format == "all" else [args.format]
    for fmt in formats:
        if fmt == "md":
            report = render_report(results_dir, findings, parse_errors, manifest)
            if trend_section:
                report += "\n" + trend_section
            out_path = args.out or os.path.join(results_dir, "report.md")
            with open(out_path, "w") as f:
                f.write(report)
            print(f"Markdown report written to {out_path} ({len(findings)} findings)")
        elif fmt == "html":
            report = render_html_report(results_dir, findings, parse_errors, manifest)
            out_path = args.out or os.path.join(results_dir, "report.html")
            with open(out_path, "w") as f:
                f.write(report)
            print(f"HTML report written to {out_path} ({len(findings)} findings)")
        elif fmt == "json":
            report = render_json_report(results_dir, findings, parse_errors, manifest)
            out_path = args.out or os.path.join(results_dir, "report.json")
            with open(out_path, "w") as f:
                f.write(report)
            print(f"JSON report written to {out_path} ({len(findings)} findings)")


def generate_triage_prompt(findings, context=None):
    """Generate an LLM prompt for triaging findings as true/false positives.

    The prompt asks the LLM to assess each finding's likelihood of being a
    true positive based on the code context. Findings confirmed by multiple
    tools are highlighted as higher-confidence. The output is a JSON array
    of {finding_idx, verdict, confidence, reasoning} objects.

    This is a deterministic prompt generator — the LLM itself does the
    classification. The prompt is structured so the LLM's response can be
    parsed programmatically.
    """
    lines = [
        "You are a security analyst triaging SAST findings. For each finding below,",
        "assess whether it is likely a TRUE POSITIVE or FALSE POSITIVE.",
        "",
        "Consider:",
        "- Is the code path actually reachable?",
        "- Is there existing sanitization/validation?",
        "- Is this a test file or dead code?",
        "- Findings confirmed by multiple tools are more likely true positives.",
        "",
        "Respond with a JSON array of objects:",
        '[{"index": 0, "verdict": "true_positive|false_positive", "confidence": "high|medium|low", "reasoning": "..."}]',
        "",
        "Findings:",
    ]
    for i, f in enumerate(findings):
        confirmed = f.get("confirmed_by", [])
        confirmed_note = f" (confirmed by: {', '.join(confirmed)})" if confirmed else ""
        lines.append(
            f"{i}. [{f.get('severity', '?').upper()}] {f.get('tool', '?')}:{f.get('rule', '?')} "
            f"at {f.get('file', '?')}:{f.get('line', '?')}{confirmed_note}"
        )
        lines.append(f"   Message: {f.get('message', '')}")
        if f.get("fix"):
            lines.append(f"   Suggested fix: {f['fix']}")
        lines.append("")
    return "\n".join(lines)


def load_trend_history(results_dir, max_entries=10):
    """Load recent scan trend data from ~/.tiangang/trends/<project-hash>/.

    Returns a list of {timestamp, total, by_severity} dicts sorted by time.
    Used to show whether findings are increasing/decreasing over time.
    """
    import hashlib
    manifest_path = os.path.join(results_dir, "scan_manifest.json")
    if not os.path.exists(manifest_path):
        return []
    with open(manifest_path) as f:
        manifest = json.load(f)
    target = manifest.get("target", "")
    proj_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
    trend_dir = os.path.join(
        os.path.expanduser("~"), ".tiangang", "trends", proj_hash
    )
    os.makedirs(trend_dir, exist_ok=True)
    # Load existing trend file.
    trend_file = os.path.join(trend_dir, "trend_history.json")
    history = []
    if os.path.exists(trend_file):
        try:
            with open(trend_file) as f:
                history = json.load(f)
        except Exception:
            history = []
    return history[-max_entries:]


def save_trend_entry(results_dir, findings, manifest):
    """Append a trend entry with current scan's finding counts.

    Called after each scan to build up trend history. The trend data is
    stored per-project (by target path hash) so different projects don't
    mix their histories.
    """
    import hashlib
    target = manifest.get("target", "")
    proj_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
    trend_dir = os.path.join(
        os.path.expanduser("~"), ".tiangang", "trends", proj_hash
    )
    os.makedirs(trend_dir, exist_ok=True)
    trend_file = os.path.join(trend_dir, "trend_history.json")
    history = []
    if os.path.exists(trend_file):
        try:
            with open(trend_file) as f:
                history = json.load(f)
        except Exception:
            history = []
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f["severity"]] += 1
    entry = {
        "timestamp": manifest.get("timestamp", ""),
        "total": len(findings),
        "by_severity": dict(by_sev),
    }
    history.append(entry)
    # Keep last 50 entries.
    history = history[-50:]
    with open(trend_file, "w") as f:
        json.dump(history, f, indent=2)


def render_trend_section(history, current_findings):
    """Render a trend section for the Markdown report.

    Shows whether findings are increasing/decreasing compared to recent scans.
    """
    if not history:
        return ""
    lines = ["## Scan Trend", ""]
    lines.append("| Scan | Total | Critical | High | Medium | Low |")
    lines.append("|---|---|---|---|---|---|")
    for entry in history[-5:]:
        ts = entry.get("timestamp", "")[:10]
        by_sev = entry.get("by_severity", {})
        lines.append(
            f"| {ts} | {entry.get('total', 0)} | "
            f"{by_sev.get('critical', 0)} | {by_sev.get('high', 0)} | "
            f"{by_sev.get('medium', 0)} | {by_sev.get('low', 0)} |"
        )
    # Current scan.
    cur_sev = defaultdict(int)
    for f in current_findings:
        cur_sev[f["severity"]] += 1
    lines.append(
        f"| **Current** | **{len(current_findings)}** | "
        f"**{cur_sev.get('critical', 0)}** | **{cur_sev.get('high', 0)}** | "
        f"**{cur_sev.get('medium', 0)}** | **{cur_sev.get('low', 0)}** |"
    )
    # Delta.
    if history:
        prev_total = history[-1].get("total", 0)
        delta = len(current_findings) - prev_total
        if delta > 0:
            lines.append(f"\n**+{delta}** new findings since last scan.")
        elif delta < 0:
            lines.append(f"\n**{delta}** findings resolved since last scan.")
        else:
            lines.append("\nNo change since last scan.")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
