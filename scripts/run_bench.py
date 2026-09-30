#!/usr/bin/env python3
"""
Run the bundled-rule accuracy benchmark (tests/bench/): scan the known-vuln
fixtures with semgrep + tiangang's bundled offline rules, compare the findings
against the expectation manifest, and print a TP/FP/FN scorecard.

Mechanism (absorbed from xalgorix's challenge bench): each fixture declares
ground truth (class, CWE, expected rule); positive fixtures must hit their
expected rule (recall floor), negative controls must stay clean (precision
signal — over-reporting fails them). Ground-truth scope is stated in the
manifest so a passing run is never read as "the ruleset catches everything".

Offline by design: only local rule files from the manifest are loaded,
``--metrics=off``, no registry access. Explicit per-file targets bypass
semgrep's built-in semgrepignore defaults (which exclude dirs named
``tests``/``fixtures`` and would otherwise silently scan zero files).

Exit codes: 0 = all expectations pass (or SKIP: semgrep unavailable),
1 = any FN/FP or scan failure. A skip is printed, never silent.

Usage:
    python3 run_bench.py [--bench-dir tests/bench] [--json]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, os.pardir))
MANIFEST_NAME = "manifest.json"
SEMGREP_TIMEOUT = 300
# Path length cap for anything echoed into the scorecard — rule files and
# paths come from the manifest, keep one bad entry from flooding the output.
_MAX_ECHO = 200


def _rule_id(check_id):
    """Normalize a semgrep checkId to the bare rule id.

    Local config files report ids as ``<path>.<rule-id>`` (e.g.
    ``rules.llm-security.llm-sec-output-to-sql``); rule ids themselves never
    contain dots, so the last dot-segment is always the bare id.
    """
    return str(check_id or "").rsplit(".", 1)[-1]


def _load_manifest(bench_dir):
    path = os.path.join(bench_dir, MANIFEST_NAME)
    with open(path) as f:
        manifest = json.load(f)
    if not isinstance(manifest, dict) or not manifest.get("expectations"):
        raise ValueError(f"{path} has no expectations")
    return manifest


def _fixture_paths(bench_dir, expectations):
    """Resolve every expectation's file to an absolute path; missing = error.

    Explicitly listed files are always scanned by semgrep regardless of
    semgrepignore defaults — that is exactly why we pass files, not the dir.
    The containment check runs before existence so a manifest pointing outside
    the bench dir is rejected as scope tampering even when the file exists.
    """
    paths = []
    bench_abs = os.path.abspath(bench_dir)
    for exp in expectations:
        rel = exp.get("file", "")
        full = os.path.normpath(os.path.join(bench_dir, rel))
        # A fixture must stay inside the bench dir — a manifest pointing at
        # arbitrary repo files would silently widen the benchmark's scope.
        if os.path.abspath(full) != bench_abs and not os.path.abspath(full).startswith(
            bench_abs + os.sep
        ):
            raise ValueError(f"fixture escapes bench dir: {rel}")
        if not os.path.isfile(full):
            raise FileNotFoundError(f"fixture missing: {full}")
        paths.append(full)
    return paths


def _run_semgrep(rule_paths, fixture_paths):
    """Run semgrep once over all fixtures with the bundled local rules.

    Returns (findings, semgrep_version, error). Findings are normalized to
    {rule, file, line} dicts. error is None on success.
    """
    rules_rel = [os.path.join(REPO_ROOT, r) for r in rule_paths]
    for r in rules_rel:
        if not os.path.isfile(r):
            return [], None, f"rule file missing: {r}"
    cmd = ["semgrep", "scan", "--metrics=off", "--json"]
    for r in rules_rel:
        cmd.extend(["--config", r])
    cmd.extend(fixture_paths)
    try:
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            timeout=SEMGREP_TIMEOUT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return [], None, None  # semgrep not installed — caller decides SKIP
    except subprocess.TimeoutExpired:
        return [], None, f"semgrep timed out after {SEMGREP_TIMEOUT}s"
    if proc.returncode != 0:
        tail = ((proc.stderr or "") + (proc.stdout or ""))[-_MAX_ECHO:]
        return [], None, f"semgrep exited {proc.returncode}: {tail}"
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return [], None, f"semgrep output is not JSON: {e}"
    findings = []
    for r in data.get("results", []):
        findings.append(
            {
                "rule": _rule_id(r.get("check_id")),
                "file": os.path.normpath(os.path.abspath(r.get("path", ""))),
                "line": r.get("start", {}).get("line"),
            }
        )
    version = None
    vproc = subprocess.run(
        ["semgrep", "--version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if vproc.returncode == 0:
        version = (vproc.stdout or "").strip().splitlines()[0][:80] or None
    return findings, version, None


def _exp_fixture_path(bench_dir, exp):
    """Absolute path of an expectation's fixture (bench-relative → absolute)."""
    return os.path.normpath(os.path.abspath(os.path.join(bench_dir, exp["file"])))


def score(bench_dir, expectations, findings):
    """Score findings against expectations. Purely deterministic.

    - positive: hit = finding of expect_rule in that fixture (TP, first line
      wins); miss = FN.
    - negative: any finding in the fixture = FP.
    - Any finding not accounted for by its fixture's expectation (different
      rule on a positive fixture, or a file no expectation claims) is an
      unexpected over-report = FP — a bench run must be able to explain every
      finding it produced.

    Returns a scorecard dict with per-expectation detail and totals.
    """
    details = []
    tp = fn = fp = 0
    claimed = set()  # indexes into findings already matched to an expectation
    for exp in expectations:
        fixture = _exp_fixture_path(bench_dir, exp)
        hits = [i for i, f in enumerate(findings) if f["file"] == fixture]
        entry = {
            "id": exp["id"],
            "class": exp.get("class"),
            "cwe": exp.get("cwe"),
            "file": exp["file"],
            "negative": bool(exp.get("negative")),
        }
        if exp.get("negative"):
            bad = [findings[i] for i in hits]
            if bad:
                fp += len(bad)
                entry.update(
                    outcome="FP",
                    detail=[
                        f"unexpected {b['rule']} at line {b['line']}" for b in bad
                    ],
                )
            else:
                entry.update(outcome="clean", detail=[])
            # Negative-control findings are accounted either way (clean or
            # counted as FP above) — never re-counted as unclaimed below.
            claimed.update(hits)
            details.append(entry)
            continue
        expected = exp.get("expect_rule")
        matched = [i for i in hits if findings[i]["rule"] == expected]
        if matched:
            tp += 1
            claimed.update(matched[:1])
            first = findings[matched[0]]
            extras = [i for i in hits if i not in matched[:1]]
            entry.update(
                outcome="TP",
                detail=[f"{expected} at line {first['line']}"],
            )
            if extras:
                fp += len(extras)
                claimed.update(extras)
                entry["detail"].append(
                    "unexpected rule(s): "
                    + ", ".join(sorted({findings[i]["rule"] for i in extras}))
                )
        else:
            fn += 1
            note = (
                f"{expected} not hit"
                if not hits
                else f"{expected} not hit (other rules fired: "
                + ", ".join(sorted({findings[i]["rule"] for i in hits}))
                + ")"
            )
            entry.update(outcome="FN", detail=[note])
        details.append(entry)
    # Findings on files no expectation claims (manifest drift) count as FP.
    known = {_exp_fixture_path(bench_dir, e) for e in expectations}
    for i, f in enumerate(findings):
        if i in claimed:
            continue
        fp += 1
        file_ref = (
            os.path.relpath(f["file"], REPO_ROOT)
            if f["file"] in known
            else f["file"]
        )
        details.append(
            {
                "id": "(unclaimed)",
                "file": file_ref,
                "negative": None,
                "outcome": "FP",
                "detail": [f"{f['rule']} at line {f['line']}"],
            }
        )
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "passed": fn == 0 and fp == 0,
        "expectations": details,
    }


def render_scorecard(scorecard, semgrep_version, elapsed_s):
    """Render the human-readable scorecard table."""
    lines = [
        "tiangang bundled-rule accuracy bench",
        f"semgrep: {semgrep_version or '?'} | elapsed: {elapsed_s:.1f}s",
        "",
        "| Expectation | Class | File | Outcome | Detail |",
        "|---|---|---|---|---|",
    ]
    for e in scorecard["expectations"]:
        detail = "; ".join(e.get("detail", [])) or "-"
        cwe = e.get("cwe") or "-"
        lines.append(
            f"| {e['id']} | {e.get('class', '-')} ({cwe}) "
            f"| {e['file']} | {e['outcome']} | {detail} |"
        )
    lines.append("")
    lines.append(
        f"TP={scorecard['tp']}  FN={scorecard['fn']}  FP={scorecard['fp']}  "
        f"→ {'PASS' if scorecard['passed'] else 'FAIL'}"
    )
    lines.append(
        "Scope note: this bench quantifies the bundled offline rules on these "
        "fixtures only — it is not a recall claim for the whole ruleset."
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--bench-dir",
        default=os.path.join(REPO_ROOT, "tests", "bench"),
        help="Bench directory holding manifest.json + fixtures/",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON scorecard")
    args = parser.parse_args()

    bench_dir = os.path.abspath(args.bench_dir)
    try:
        manifest = _load_manifest(bench_dir)
        fixture_paths = _fixture_paths(bench_dir, manifest["expectations"])
    except (OSError, ValueError, KeyError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    start = time.monotonic()
    findings, version, err = _run_semgrep(manifest.get("rules", []), fixture_paths)
    elapsed = time.monotonic() - start
    if err is None and findings == [] and version is None:
        print(
            "SKIP: semgrep not available — accuracy bench not run (install "
            "semgrep or run scripts/install_tools.sh)"
        )
        return 0
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    scorecard = score(bench_dir, manifest["expectations"], findings)
    scorecard["semgrep_version"] = version
    scorecard["elapsed_s"] = round(elapsed, 2)

    if args.json:
        print(json.dumps(scorecard, indent=2, ensure_ascii=False))
    else:
        print(render_scorecard(scorecard, version, elapsed))
    return 0 if scorecard["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
