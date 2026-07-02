#!/usr/bin/env python3
"""
Orchestrates a security scan: runs semgrep (always) plus whichever
language-specific tools are available for the detected languages, writing
every tool's raw output into a single results directory for
generate_report.py to pick up afterwards.

Usage:
    python3 run_scan.py <target-dir> [--out <results-dir>] [--langs python,go,...]

If --langs is omitted, this calls detect_languages.py itself. Tools that
aren't installed are skipped with a note in the summary rather than failing
the whole run — a partial scan with a clear list of what was skipped is more
useful than an all-or-nothing failure. Run install_tools.sh first to get
better coverage.

This does NOT run CodeQL — that's a separate, heavier opt-in flow. See
references/codeql.md.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def sh(cmd, cwd=None, timeout=600):
    """Run a shell command, returning (returncode, stdout+stderr). Never raises."""
    try:
        proc = subprocess.run(
            cmd, shell=True, cwd=cwd, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout}s"
    except Exception as e:
        return -1, str(e)


def have(cmd):
    return shutil.which(cmd) is not None


def detect_languages(target):
    rc, out = sh(f"python3 {SCRIPT_DIR}/detect_languages.py {target!r} --json")
    if rc != 0:
        return []
    try:
        return json.loads(out)["languages"]
    except Exception:
        return []


def run_tool(name, ran, skipped, cmd, cwd=None, timeout=600):
    rc, out = sh(cmd, cwd=cwd, timeout=timeout)
    ran.append({"tool": name, "command": cmd, "returncode": rc,
                "log_tail": out[-2000:] if out else ""})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--out", default=None, help="Results directory (default: <target>/.security-audit)")
    parser.add_argument("--langs", default=None, help="Comma-separated language list; auto-detected if omitted")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.abspath(args.out) if args.out else os.path.join(target, ".security-audit")
    os.makedirs(out_dir, exist_ok=True)

    langs = args.langs.split(",") if args.langs else detect_languages(target)
    print(f"Languages: {langs or '(none detected — semgrep only)'}")

    ran = []
    skipped = []

    # Universal: semgrep
    if have("semgrep"):
        sarif = os.path.join(out_dir, "semgrep.sarif")
        run_tool("semgrep", ran, skipped,
                  f"semgrep scan --config auto --sarif --output {sarif!r} {target!r}", timeout=900)
    else:
        skipped.append({"tool": "semgrep", "reason": "not installed — run install_tools.sh"})

    if "python" in langs:
        if have("bandit"):
            j = os.path.join(out_dir, "bandit.json")
            run_tool("bandit", ran, skipped,
                      f"bandit -r {target!r} -f json -o {j!r} -x '*/tests/*,*/venv/*,*/.venv/*'")
        else:
            skipped.append({"tool": "bandit", "reason": "not installed"})

    if "go" in langs:
        if have("gosec"):
            sarif = os.path.join(out_dir, "gosec.sarif")
            run_tool("gosec", ran, skipped, f"gosec -fmt=sarif -out={sarif!r} ./...", cwd=target)
        else:
            skipped.append({"tool": "gosec", "reason": "not installed"})

    if "c_cpp" in langs:
        if have("flawfinder"):
            sarif = os.path.join(out_dir, "flawfinder.sarif")
            run_tool("flawfinder", ran, skipped, f"flawfinder --sarif {target!r} > {sarif!r}")
        else:
            skipped.append({"tool": "flawfinder", "reason": "not installed"})
        if have("cppcheck"):
            xml = os.path.join(out_dir, "cppcheck.xml")
            run_tool("cppcheck", ran, skipped,
                      f"cppcheck --enable=warning,portability --xml --xml-version=2 {target!r} 2> {xml!r}")
        else:
            skipped.append({"tool": "cppcheck", "reason": "not installed"})

    if "ruby" in langs:
        if have("brakeman"):
            sarif = os.path.join(out_dir, "brakeman.sarif")
            run_tool("brakeman", ran, skipped, f"brakeman -f sarif -o {sarif!r} {target!r}")
        else:
            skipped.append({"tool": "brakeman", "reason": "not installed"})

    if "php" in langs:
        if have("psalm") or os.path.exists(os.path.join(target, "vendor/bin/psalm")):
            sarif = os.path.join(out_dir, "psalm.sarif")
            psalm_cmd = "psalm" if have("psalm") else "vendor/bin/psalm"
            run_tool("psalm", ran, skipped,
                      f"{psalm_cmd} --taint-analysis --report={sarif!r}", cwd=target)
        else:
            skipped.append({"tool": "psalm", "reason": "not installed or no composer.json — relying on semgrep's PHP ruleset"})

    if "java" in langs:
        skipped.append({"tool": "findsecbugs", "reason": "needs project-specific build wiring — see references/tools.md, not auto-run"})

    if "dotnet" in langs:
        skipped.append({"tool": "security-code-scan", "reason": "Roslyn analyzer, needs to be added to the .csproj — see references/tools.md, not auto-run"})

    if "rust" in langs:
        if have("cargo"):
            j = os.path.join(out_dir, "cargo-audit.json")
            run_tool("cargo-audit", ran, skipped, f"cargo audit --json > {j!r}", cwd=target)
        else:
            skipped.append({"tool": "cargo-audit", "reason": "not installed"})
        # Miri only worth it if there's unsafe code; leave to the caller/skill instructions
        # to decide since it's slow and needs a nightly toolchain.

    manifest = {
        "target": target,
        "out_dir": out_dir,
        "languages": langs,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ran": ran,
        "skipped": skipped,
    }
    manifest_path = os.path.join(out_dir, "scan_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nRan {len(ran)} tool(s), skipped {len(skipped)}.")
    for s in skipped:
        print(f"  skipped: {s['tool']} — {s['reason']}")
    print(f"\nResults + manifest written to {out_dir}")
    print(f"Next: python3 {SCRIPT_DIR}/generate_report.py {out_dir!r}")


if __name__ == "__main__":
    main()
