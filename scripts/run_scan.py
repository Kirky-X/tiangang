#!/usr/bin/env python3
"""
Orchestrates a security scan: runs semgrep (always) plus whichever
language-specific tools are available for the detected languages, writing
every tool's raw output into a single results directory for
generate_report.py to pick up afterwards.

Usage:
    python3 run_scan.py <target-dir> [--out <results-dir>] [--langs python,go,...]
    python3 run_scan.py <target-dir> --agent-rules rules/agent-antipatterns.yml

If --langs is omitted, this calls detect_languages.py itself. Tools that
aren't installed are skipped with a note in the summary rather than failing
the whole run — a partial scan with a clear list of what was skipped is more
useful than an all-or-nothing failure. Run install_tools.sh first to get
better coverage.

This does NOT run CodeQL — that's a separate, heavier opt-in flow. See
references/codeql.md.

Security: all commands are executed as argument lists (subprocess.run without
shell=True). Path arguments with shell metacharacters ($(), backticks, quotes)
are treated as literal strings, never parsed by the shell. This prevents
command injection via crafted target paths or --out values.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Languages run_scan.py knows how to wire tools for. Mirrors the values in
# detect_languages.py's EXT_MAP. Used to validate --langs input early so a
# typo like `--langs python,rustt` produces a warning instead of silently
# skipping the rust branch.
SUPPORTED_LANGS = {"python", "java", "go", "c_cpp", "ruby", "php", "dotnet", "rust"}


def sh(cmd, cwd=None, timeout=600):
    """Run a command (list form), returning (returncode, combined_output). Never raises.

    cmd MUST be a list — the shell is never invoked, preventing command
    injection. Path arguments with metacharacters ($(), backticks, quotes)
    are treated as literal strings, not parsed by any shell.
    """
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, combined
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout}s"
    except Exception as e:
        return -1, str(e)


def have(cmd):
    return shutil.which(cmd) is not None


def detect_languages(target):
    """Detect languages in target dir. Returns [] on failure (with warning to stderr)."""
    rc, out = sh([sys.executable, os.path.join(SCRIPT_DIR, "detect_languages.py"), target, "--json"])
    if rc != 0:
        print(f"warning: language detection failed (rc={rc}): {out}", file=sys.stderr)
        return []
    try:
        return json.loads(out)["languages"]
    except Exception:
        return []


def run_tool(name, ran, cmd, cwd=None, timeout=600, output_file=None, output_stream="stdout"):
    """Run a tool. If output_file given, write the specified stream to that path.

    cmd MUST be a list — the shell is never invoked, preventing command injection.
    output_stream: "stdout" or "stderr" — which stream to write to output_file
                   (cppcheck writes XML to stderr).
    """
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        rc = proc.returncode
        stdout_content = proc.stdout or ""
        stderr_content = proc.stderr or ""
        if output_file:
            content = stdout_content if output_stream == "stdout" else stderr_content
            if content:
                try:
                    with open(output_file, "w") as f:
                        f.write(content)
                except Exception:
                    pass
        log = stdout_content + stderr_content
    except subprocess.TimeoutExpired:
        rc, log = -1, f"timed out after {timeout}s"
    except Exception as e:
        rc, log = -1, str(e)
    ran.append({"tool": name, "command": " ".join(cmd) if isinstance(cmd, list) else cmd,
                "returncode": rc, "log_tail": log[-2000:] if log else ""})


def _cargo_audit_available():
    """Check if `cargo audit` subcommand is available (cargo-audit crate installed).

    cargo-audit is a separate crate that provides the `cargo audit` subcommand.
    Checking `cargo` alone is insufficient — cargo may exist without cargo-audit.
    """
    try:
        rc, _ = sh(["cargo", "audit", "--version"])
        return rc == 0
    except Exception:
        return False


def _has_ruby_code(target):
    """Check whether target has any .rb files or a Gemfile.

    Brakeman exits non-zero on non-Ruby projects (and is Rails-specific), so
    we skip it entirely when there's no Ruby code to scan — otherwise the
    report shows a misleading "tool failed" entry for a tool that was never
    applicable.
    """
    if os.path.exists(os.path.join(target, "Gemfile")):
        return True
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith(".")
                   and d not in ("node_modules", "vendor", "target", "build", "dist")]
        if any(f.endswith(".rb") for f in files):
            return True
    return False


def _run_semgrep(target, out_dir, ran, agent_rules=None):
    """Run semgrep with offline fallback and optional agent rules."""
    sarif = os.path.join(out_dir, "semgrep.sarif")
    semgrep_cmd = ["semgrep", "scan", "--config", "auto", "--exclude=.security-audit",
                   "--sarif", "--output", sarif, target]
    rc, out = sh(semgrep_cmd, timeout=900)
    # Offline fallback: if --config auto fails due to network/registry, retry with bundled rulesets
    if rc != 0 and any(kw in out.lower() for kw in ("network", "registry", "timeout", "connection")):
        print("warning: semgrep --config auto failed (likely network issue), "
              "falling back to p/security-audit p/secrets", file=sys.stderr)
        semgrep_cmd = ["semgrep", "scan", "--config", "p/security-audit", "--config", "p/secrets",
                       "--exclude=.security-audit", "--sarif", "--output", sarif, target]
        rc, out = sh(semgrep_cmd, timeout=900)
    ran.append({"tool": "semgrep", "command": " ".join(semgrep_cmd),
                "returncode": rc, "log_tail": out[-2000:] if out else ""})

    # Load agent antipattern rules if requested (for LangChain/CrewAI/etc. codebases)
    if agent_rules and os.path.exists(agent_rules):
        agent_sarif = os.path.join(out_dir, "semgrep-agent.sarif")
        agent_cmd = ["semgrep", "scan", "--config", agent_rules, "--exclude=.security-audit",
                     "--sarif", "--output", agent_sarif, target]
        run_tool("semgrep-agent", ran, agent_cmd, timeout=900)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--out", default=None, help="Results directory (default: <target>/.security-audit)")
    parser.add_argument("--langs", default=None, help="Comma-separated language list; auto-detected if omitted")
    parser.add_argument("--agent-rules", default=None,
                        help="Path to agent antipattern Semgrep rules YAML (for LLM agent codebases)")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.abspath(args.out) if args.out else os.path.join(target, ".security-audit")
    os.makedirs(out_dir, exist_ok=True)

    # T-P1-7: strip whitespace from each language token to avoid silent skip
    langs = [x.strip() for x in args.langs.split(",") if x.strip()] if args.langs else detect_languages(target)
    # T-P2-7: validate --langs against the supported set; unknown names are
    # warned and dropped rather than silently skipped (a typo like "pyton"
    # would otherwise produce a semgrep-only scan with no indication why).
    if args.langs:
        unknown = [l for l in langs if l not in SUPPORTED_LANGS]
        for u in unknown:
            print(f"warning: unsupported language '{u}' — skipping "
                  f"(supported: {', '.join(sorted(SUPPORTED_LANGS))})", file=sys.stderr)
        langs = [l for l in langs if l in SUPPORTED_LANGS]
    print(f"Languages: {langs or '(none detected — semgrep only)'}")

    ran = []
    skipped = []

    # Universal: semgrep
    if have("semgrep"):
        _run_semgrep(target, out_dir, ran, agent_rules=args.agent_rules)
    else:
        skipped.append({"tool": "semgrep", "reason": "not installed — run install_tools.sh"})

    if "python" in langs:
        if have("bandit"):
            j = os.path.join(out_dir, "bandit.json")
            run_tool("bandit", ran,
                     ["bandit", "-r", target, "-f", "json", "-o", j, "-x", "*/tests/*,*/venv/*,*/.venv/*"])
        else:
            skipped.append({"tool": "bandit", "reason": "not installed"})

    if "go" in langs:
        if have("gosec"):
            sarif = os.path.join(out_dir, "gosec.sarif")
            run_tool("gosec", ran,
                     ["gosec", "-fmt=sarif", f"-out={sarif}", "./..."], cwd=target)
        else:
            skipped.append({"tool": "gosec", "reason": "not installed"})

    if "c_cpp" in langs:
        if have("flawfinder"):
            sarif = os.path.join(out_dir, "flawfinder.sarif")
            # flawfinder writes SARIF to stdout; redirect via output_file
            run_tool("flawfinder", ran,
                     ["flawfinder", "--sarif", target], output_file=sarif)
        else:
            skipped.append({"tool": "flawfinder", "reason": "not installed"})
        if have("cppcheck"):
            xml = os.path.join(out_dir, "cppcheck.xml")
            # cppcheck writes XML to stderr; redirect via output_stream="stderr"
            run_tool("cppcheck", ran,
                     ["cppcheck", "--enable=warning,portability", "--xml", "--xml-version=2", target],
                     output_file=xml, output_stream="stderr")
        else:
            skipped.append({"tool": "cppcheck", "reason": "not installed"})

    if "ruby" in langs:
        # T-P2-12: brakeman exits non-zero on non-Ruby projects; skip if no
        # Ruby code is present rather than producing a misleading "failed" entry.
        if not _has_ruby_code(target):
            skipped.append({"tool": "brakeman",
                            "reason": "no Ruby files or Gemfile found — brakeman only works on Ruby projects"})
        elif have("brakeman"):
            sarif = os.path.join(out_dir, "brakeman.sarif")
            run_tool("brakeman", ran,
                     ["brakeman", "-f", "sarif", "-o", sarif, target])
        else:
            skipped.append({"tool": "brakeman", "reason": "not installed"})

    if "php" in langs:
        if have("psalm") or os.path.exists(os.path.join(target, "vendor/bin/psalm")):
            sarif = os.path.join(out_dir, "psalm.sarif")
            psalm_cmd = "psalm" if have("psalm") else "vendor/bin/psalm"
            run_tool("psalm", ran,
                     [psalm_cmd, "--taint-analysis", f"--report={sarif}"], cwd=target)
        else:
            skipped.append({"tool": "psalm", "reason": "not installed or no composer.json — relying on semgrep's PHP ruleset"})

    if "java" in langs:
        skipped.append({"tool": "findsecbugs", "reason": "needs project-specific build wiring — see references/tools.md, not auto-run"})

    if "dotnet" in langs:
        skipped.append({"tool": "security-code-scan", "reason": "Roslyn analyzer, needs to be added to the .csproj — see references/tools.md, not auto-run"})

    if "rust" in langs:
        # T-P1-1: cargo-audit is a separate crate; check `cargo audit --version` not just `cargo`
        if _cargo_audit_available():
            j = os.path.join(out_dir, "cargo-audit.json")
            run_tool("cargo-audit", ran,
                     ["cargo", "audit", "--json"], cwd=target, output_file=j)
        else:
            skipped.append({"tool": "cargo-audit", "reason": "not installed — run `cargo install cargo-audit`"})
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
    print(f"Next: python3 {os.path.join(SCRIPT_DIR, 'generate_report.py')} {out_dir!r}")


if __name__ == "__main__":
    main()
