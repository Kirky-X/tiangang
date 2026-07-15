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
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Languages run_scan.py knows how to wire tools for. Mirrors the values in
# detect_languages.py's EXT_MAP. Used to validate --langs input early so a
# typo like `--langs python,rustt` produces a warning instead of silently
# skipping the rust branch.
SUPPORTED_LANGS = {
    "python",
    "java",
    "go",
    "c_cpp",
    "ruby",
    "php",
    "dotnet",
    "rust",
    "javascript",  # JS + TS share scanner set (njsscan + eslint-plugin-security)
}

# Default upper bound on concurrent scanners. Each scanner is an I/O-bound
# subprocess wait, so a modest parallelism turns a serial ~10-tool run into
# roughly the slowest single tool. Override via env for large hosts.


def _max_workers():
    env = os.environ.get("TIANGANG_MAX_WORKERS")
    if env and env.strip().isdigit() and int(env) > 0:
        return int(env)
    return 8


# Semgrep per-file timeout and parallelism — explicit values keep runs
# reproducible across hosts (absorbed from strix's semgrep CLI playbook,
# which warns that omitting these lets semgrep pick host-dependent defaults).
SEMGREP_JOBS = 4
SEMGREP_TIMEOUT = 20  # seconds, per file


# B3: reuse SKIP_DIRS from detect_languages to avoid two divergent skip sets
# (the old _has_ruby_code inline tuple missed __pycache__/venv/.venv/.tox/bin/obj).
from detect_languages import SKIP_DIRS


def sh(cmd, cwd=None, timeout=600):
    """Run a command (list form), returning (returncode, combined_output). Never raises.

    cmd MUST be a list — the shell is never invoked, preventing command
    injection. Path arguments with metacharacters ($(), backticks, quotes)
    are treated as literal strings, not parsed by any shell.
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
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
    rc, out = sh(
        [
            sys.executable,
            os.path.join(SCRIPT_DIR, "detect_languages.py"),
            target,
            "--json",
        ]
    )
    if rc != 0:
        print(f"warning: language detection failed (rc={rc}): {out}", file=sys.stderr)
        return []
    try:
        return json.loads(out)["languages"]
    except Exception:
        return []


def run_tool(
    name, ran, cmd, cwd=None, timeout=600, output_file=None, output_stream="stdout"
):
    """Run a tool. If output_file given, write the specified stream to that path.

    cmd MUST be a list — the shell is never invoked, preventing command injection.
    output_stream: "stdout" or "stderr" — which stream to write to output_file
                   (cppcheck writes XML to stderr).
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        rc = proc.returncode
        stdout_content = proc.stdout or ""
        stderr_content = proc.stderr or ""
        log = stdout_content + stderr_content
        if output_file:
            content = stdout_content if output_stream == "stdout" else stderr_content
            if content:
                try:
                    with open(output_file, "w") as f:
                        f.write(content)
                except Exception as e:
                    rc = -2
                    log = log + f"[output write failed] {e}"
    except subprocess.TimeoutExpired:
        rc, log = -1, f"timed out after {timeout}s"
    except Exception as e:
        rc, log = -1, str(e)
    ran.append(
        {
            "tool": name,
            "command": " ".join(cmd) if isinstance(cmd, list) else cmd,
            "returncode": rc,
            "log_tail": log[-2000:] if log else "",
        }
    )


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
        # B3: reuse SKIP_DIRS from detect_languages to keep behavior consistent
        # (single source of truth — no divergent inline tuple).
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        if any(f.endswith(".rb") for f in files):
            return True
    return False


def _run_semgrep(target, out_dir, ran, agent_rules=None):
    """Run semgrep with offline fallback and optional agent rules.

    Flags absorbed from strix's semgrep CLI playbook:
    - ``--metrics=off``: semgrep sends telemetry by default; explicit off is
      both a privacy requirement and a correctness guard (the metrics call can
      fail in restricted networks and break the scan).
    - ``--quiet``: suppress progress noise in automation.
    - ``--jobs`` / ``--timeout``: explicit values so runs are reproducible
      across hosts instead of depending on semgrep's host-dependent defaults.
    """
    sarif = os.path.join(out_dir, "semgrep.sarif")
    semgrep_cmd = [
        "semgrep",
        "scan",
        "--config",
        "auto",
        "--metrics=off",
        "--quiet",
        "--jobs",
        str(SEMGREP_JOBS),
        "--timeout",
        str(SEMGREP_TIMEOUT),
        "--exclude=.security-audit",
        "--sarif",
        "--output",
        sarif,
        target,
    ]
    rc, out = sh(semgrep_cmd, timeout=900)
    # B4: preserve first-attempt error so debugging info isn't lost on fallback.
    # Previously `out` and `semgrep_cmd` were reassigned, dropping the original
    # network error from the manifest — debuggers had no clue why fallback fired.
    first_rc, first_out, first_cmd = rc, out, semgrep_cmd[:]
    fallback_triggered = False
    # Offline fallback: if --config auto fails due to network/registry, retry with bundled rulesets
    if rc != 0 and any(
        kw in out.lower() for kw in ("network", "registry", "timeout", "connection")
    ):
        print(
            "warning: semgrep --config auto failed (likely network issue), "
            "falling back to p/security-audit p/secrets",
            file=sys.stderr,
        )
        semgrep_cmd = [
            "semgrep",
            "scan",
            "--config",
            "p/security-audit",
            "--config",
            "p/secrets",
            "--metrics=off",
            "--quiet",
            "--jobs",
            str(SEMGREP_JOBS),
            "--timeout",
            str(SEMGREP_TIMEOUT),
            "--exclude=.security-audit",
            "--sarif",
            "--output",
            sarif,
            target,
        ]
        rc, out = sh(semgrep_cmd, timeout=900)
        fallback_triggered = True
    # B4: when fallback fired, log_tail + command record BOTH attempts so the
    # manifest tells the full story (original error + fallback outcome).
    if fallback_triggered:
        log_tail = (
            f"[first attempt rc={first_rc}]\n{first_out[-1000:]}\n"
            f"[fallback rc={rc}]\n{out[-1000:]}"
        )
        command_str = (
            f"first: {' '.join(first_cmd)} | fallback: {' '.join(semgrep_cmd)}"
        )
    else:
        log_tail = out[-2000:] if out else ""
        command_str = " ".join(semgrep_cmd)
    ran.append(
        {
            "tool": "semgrep",
            "command": command_str,
            "returncode": rc,
            "log_tail": log_tail[-2000:] if log_tail else "",
        }
    )

    # Load agent antipattern rules if requested (for LangChain/CrewAI/etc. codebases)
    if agent_rules and os.path.exists(agent_rules):
        agent_sarif = os.path.join(out_dir, "semgrep-agent.sarif")
        agent_cmd = [
            "semgrep",
            "scan",
            "--config",
            agent_rules,
            "--metrics=off",
            "--quiet",
            "--exclude=.security-audit",
            "--sarif",
            "--output",
            agent_sarif,
            target,
        ]
        run_tool("semgrep-agent", ran, agent_cmd, timeout=900)
    elif agent_rules:
        print(
            f"warning: --agent-rules file not found: {agent_rules} — agent antipattern scan skipped",
            file=sys.stderr,
        )


def _tool_thunk(name, cmd, **kwargs):
    """Build a scanner thunk: runs one tool via run_tool, returns its ran entries.

    Each thunk owns a private ``ran`` list so concurrent execution never
    mutates shared state. Per-tool ``timeout`` is forwarded via kwargs and
    enforced by subprocess.run inside run_tool — concurrency adds no global
    deadline, so timeout control is identical to the serial version.
    """

    def _run():
        r = []
        run_tool(name, r, cmd, **kwargs)
        return r

    return _run


def _semgrep_thunk(target, out_dir, agent_rules):
    """Wrap _run_semgrep (which has its own offline-fallback + agent-rules flow)
    as a thunk returning a ran-entry list, so it composes with the other scanners
    under the concurrent runner."""

    def _run():
        r = []
        _run_semgrep(target, out_dir, r, agent_rules=agent_rules)
        return r

    return _run


def _trivy_thunk(target, out_dir):
    """trivy SCA thunk: record DB staleness signal, then scan lockfiles.

    The ``trivy version`` JSON is written next to the scan output so a stale
    ``VulnerabilityDB.UpdatedAt`` shows up as a visible signal rather than
    letting a clean scan mask an outdated DB. Absorbed from strix's
    dependency_cve_scanning skill, which warns that "zero results is
    suspicious" when the DB is stale.

    ``--scanners vuln`` focuses the pass on dependency CVEs (secrets are
    handled by the gitleaks + trufflehog channel). ``--offline-scan`` keeps
    per-package advisory lookups offline so the scan works in restricted
    networks; the DB refresh happens separately via ``trivy db update``.
    """

    def _run():
        r = []
        # DB staleness signal — write version JSON so a stale DB is visible.
        version_path = os.path.join(out_dir, "trivy-version.json")
        run_tool(
            "trivy-version",
            r,
            ["trivy", "version", "--format", "json"],
            output_file=version_path,
            timeout=120,
        )
        # SCA scan: --output writes the JSON report directly (trivy native flag).
        out_path = os.path.join(out_dir, "trivy.json")
        run_tool(
            "trivy",
            r,
            [
                "trivy",
                "fs",
                "--scanners",
                "vuln",
                "--offline-scan",
                "--format",
                "json",
                "--output",
                out_path,
                target,
            ],
            timeout=900,
        )
        return r

    return _run


def _gitleaks_thunk(target, out_dir):
    """gitleaks secret scanner thunk.

    gitleaks exits 1 when secrets are found — that's a finding, not a failure.
    The thunk normalizes rc=1 → 0 when the report file was produced, so the
    manifest doesn't show a misleading "failed" entry for a successful scan
    that happened to find credentials.
    """

    def _run():
        r = []
        out_path = os.path.join(out_dir, "gitleaks.json")
        run_tool(
            "gitleaks",
            r,
            [
                "gitleaks",
                "detect",
                "--source",
                target,
                "--report-format",
                "json",
                "--report-path",
                out_path,
                "--no-banner",
            ],
            timeout=900,
        )
        # rc=1 means "secrets found" — normalize to 0 when the report exists.
        if r and r[-1]["returncode"] == 1 and os.path.exists(out_path):
            r[-1]["returncode"] = 0
            r[-1]["log_tail"] = (
                (r[-1].get("log_tail") or "")
                + "\n[gitleaks rc=1 normalized: secrets found, not a failure]"
            )
        return r

    return _run


def _trufflehog_thunk(target, out_dir):
    """trufflehog secret scanner thunk (JSONL output to stdout).

    ``--no-update`` skips the detector signature DB update (works offline).
    ``--no-verification`` skips live credential verification — we want the
    finding surfaced for rotation without trufflehog making outbound auth
    attempts against the detected credential's service.
    """

    def _run():
        r = []
        out_path = os.path.join(out_dir, "trufflehog.jsonl")
        run_tool(
            "trufflehog",
            r,
            [
                "trufflehog",
                "filesystem",
                "--no-update",
                "--json",
                "--no-verification",
                target,
            ],
            output_file=out_path,
            timeout=900,
        )
        return r

    return _run


def _retire_thunk(target, out_dir):
    """retire.js thunk — frontend/Node known-CVE library scan.

    Scans for vulnerable versions of JS libraries (jquery, lodash, etc.) that
    ship in the project. retire writes JSON to --outputpath; exit code is 0
    even when vulnerabilities are found (unless --exitcode is set), so no
    normalization is needed.
    """

    def _run():
        r = []
        out_path = os.path.join(out_dir, "retire.json")
        run_tool(
            "retire",
            r,
            [
                "retire",
                "--path",
                target,
                "--outputformat",
                "json",
                "--outputpath",
                out_path,
            ],
            timeout=600,
        )
        return r

    return _run


def _eslint_security_configured(target):
    """True iff the target has an eslint config that wires eslint-plugin-security.

    Mirrors the detection in install_tools.sh. ESLint rules live in the project
    (the plugin is a devDependency, the config extends/loads it), so — like
    FindSecBugs / Security Code Scan — we run it only when the user has wired it,
    and skip with guidance otherwise rather than silently modifying package.json.
    """
    cfg_names = [
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.cjs",
        ".eslintrc.js",
        ".eslintrc.json",
        ".eslintrc.yml",
        ".eslintrc.yaml",
    ]
    for c in cfg_names:
        p = os.path.join(target, c)
        if not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        if (
            "eslint-plugin-security" in content
            or "plugin:security" in content
            or '"security"' in content
            or "'security'" in content
        ):
            return True
    return False


def _default_out_dir(target):
    """Choose a results directory OUTSIDE the target tree.

    P0: the results dir holds raw scanner output — including Bandit's `code`
    snippet and SARIF `region.snippet` — which carry the offending source line.
    That line is exactly where hardcoded credentials live, so writing it into
    the scanned project turns a security tool's output into a secret-on-disk.
    Default to ~/.tiangang/scans/<ts>-<basename>/ and fall back to a system
    temp dir if home is not writable. ``--out`` still overrides.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tname = os.path.basename(os.path.abspath(target)) or "target"
    primary = os.path.join(
        os.path.expanduser("~"), ".tiangang", "scans", f"{ts}-{tname}"
    )
    try:
        os.makedirs(primary, exist_ok=True)
        # makedirs can succeed on a read-only-but-existing parent; verify with
        # a write probe so we fall through to /tmp instead of failing mid-scan.
        probe = os.path.join(primary, ".write-probe")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
        return primary
    except OSError:
        return tempfile.mkdtemp(prefix=f"tiangang-{ts}-")


def _run_concurrently(tasks):
    """Run scanner thunks concurrently; return ran entries in planned order.

    ``tasks`` is a list of (name, fn) where fn() -> list[ran_entry]. Completion
    order is independent of output order: results are reindexed by their
    position in ``tasks`` so the manifest is deterministic (stable across runs
    and diffs). A thunk that raises is recorded as a single failed ran entry
    rather than aborting the batch — mirrors run_tool's "never raises, log it"
    contract so one crashed scanner doesn't sink the others.
    """
    ran = []
    if not tasks:
        return ran
    n = min(_max_workers(), len(tasks))
    results_by_idx = {}
    with ThreadPoolExecutor(max_workers=n) as ex:
        futures = {ex.submit(fn): idx for idx, (_name, fn) in enumerate(tasks)}
        for fut in as_completed(futures):
            idx = futures[fut]
            name = tasks[idx][0]
            try:
                results_by_idx[idx] = list(fut.result())
            except Exception as e:
                results_by_idx[idx] = [
                    {
                        "tool": name,
                        "command": "",
                        "returncode": -3,
                        "log_tail": f"[scanner task crashed] {type(e).__name__}: {e}",
                    }
                ]
    for idx in sorted(results_by_idx):
        ran.extend(results_by_idx[idx])
    return ran


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument(
        "--out",
        default=None,
        help="Results directory (default: ~/.tiangang/scans/<ts>-<name>/ — outside the "
        "target tree, so source snippets / potential secrets don't land in the "
        "scanned project). Override with a path to write elsewhere.",
    )
    parser.add_argument(
        "--langs",
        default=None,
        help="Comma-separated language list; auto-detected if omitted",
    )
    parser.add_argument(
        "--agent-rules",
        default=None,
        help="Path to agent antipattern Semgrep rules YAML (for LLM agent codebases)",
    )
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.abspath(args.out) if args.out else _default_out_dir(target)
    os.makedirs(out_dir, exist_ok=True)

    # T-P1-7: strip whitespace from each language token to avoid silent skip
    langs = (
        [x.strip() for x in args.langs.split(",") if x.strip()]
        if args.langs
        else detect_languages(target)
    )
    # T-P2-7: validate --langs against the supported set; unknown names are
    # warned and dropped rather than silently skipped (a typo like "pyton"
    # would otherwise produce a semgrep-only scan with no indication why).
    if args.langs:
        unknown = [l for l in langs if l not in SUPPORTED_LANGS]
        for u in unknown:
            print(
                f"warning: unsupported language '{u}' — skipping "
                f"(supported: {', '.join(sorted(SUPPORTED_LANGS))})",
                file=sys.stderr,
            )
        langs = [l for l in langs if l in SUPPORTED_LANGS]
    print(f"Languages: {langs or '(none detected — semgrep only)'}")

    # Build the scan plan: each present tool becomes a thunk (runs concurrently
    # in _run_concurrently); each absent tool becomes a static skipped entry.
    # Order here is preserved in the manifest via task-index reassembly.
    tasks = []  # list of (name, thunk) — thunk() -> list[ran_entry]
    skipped = []

    # Universal: semgrep
    if have("semgrep"):
        tasks.append(("semgrep", _semgrep_thunk(target, out_dir, args.agent_rules)))
    else:
        skipped.append(
            {"tool": "semgrep", "reason": "not installed — run install_tools.sh"}
        )

    # Universal SCA + secret channel (absorbed from strix's source-aware SAST
    # playbook). trivy covers all major ecosystems via lockfile scanning; the
    # gitleaks + trufflehog pair forms an independent secret-detection channel
    # so hardcoded credentials don't depend solely on semgrep's p/secrets.
    if have("trivy"):
        tasks.append(("trivy", _trivy_thunk(target, out_dir)))
    else:
        skipped.append(
            {"tool": "trivy", "reason": "not installed — run install_tools.sh"}
        )
    if have("gitleaks"):
        tasks.append(("gitleaks", _gitleaks_thunk(target, out_dir)))
    else:
        skipped.append(
            {"tool": "gitleaks", "reason": "not installed — run install_tools.sh"}
        )
    if have("trufflehog"):
        tasks.append(("trufflehog", _trufflehog_thunk(target, out_dir)))
    else:
        skipped.append(
            {"tool": "trufflehog", "reason": "not installed — run install_tools.sh"}
        )

    if "python" in langs:
        if have("bandit"):
            j = os.path.join(out_dir, "bandit.json")
            tasks.append(
                (
                    "bandit",
                    _tool_thunk(
                        "bandit",
                        [
                            "bandit",
                            "-r",
                            target,
                            "-f",
                            "json",
                            "-o",
                            j,
                            "-x",
                            "*/tests/*,*/venv/*,*/.venv/*",
                        ],
                    ),
                )
            )
        else:
            skipped.append({"tool": "bandit", "reason": "not installed"})

    if "go" in langs:
        if have("gosec"):
            sarif = os.path.join(out_dir, "gosec.sarif")
            tasks.append(
                (
                    "gosec",
                    _tool_thunk(
                        "gosec",
                        ["gosec", "-fmt=sarif", f"-out={sarif}", "./..."],
                        cwd=target,
                    ),
                )
            )
        else:
            skipped.append({"tool": "gosec", "reason": "not installed"})

    if "c_cpp" in langs:
        if have("flawfinder"):
            sarif = os.path.join(out_dir, "flawfinder.sarif")
            # flawfinder writes SARIF to stdout; redirect via output_file
            tasks.append(
                (
                    "flawfinder",
                    _tool_thunk(
                        "flawfinder",
                        ["flawfinder", "--sarif", target],
                        output_file=sarif,
                    ),
                )
            )
        else:
            skipped.append({"tool": "flawfinder", "reason": "not installed"})
        if have("cppcheck"):
            xml = os.path.join(out_dir, "cppcheck.xml")
            # cppcheck writes XML to stderr; redirect via output_stream="stderr"
            tasks.append(
                (
                    "cppcheck",
                    _tool_thunk(
                        "cppcheck",
                        [
                            "cppcheck",
                            "--enable=warning,portability",
                            "--xml",
                            "--xml-version=2",
                            target,
                        ],
                        output_file=xml,
                        output_stream="stderr",
                    ),
                )
            )
        else:
            skipped.append({"tool": "cppcheck", "reason": "not installed"})

    if "ruby" in langs:
        # T-P2-12: brakeman exits non-zero on non-Ruby projects; skip if no
        # Ruby code is present rather than producing a misleading "failed" entry.
        if not _has_ruby_code(target):
            skipped.append(
                {
                    "tool": "brakeman",
                    "reason": "no Ruby files or Gemfile found — brakeman only works on Ruby projects",
                }
            )
        elif have("brakeman"):
            sarif = os.path.join(out_dir, "brakeman.sarif")
            tasks.append(
                (
                    "brakeman",
                    _tool_thunk(
                        "brakeman", ["brakeman", "-f", "sarif", "-o", sarif, target]
                    ),
                )
            )
        else:
            skipped.append({"tool": "brakeman", "reason": "not installed"})

    if "php" in langs:
        if have("psalm") or os.path.exists(os.path.join(target, "vendor/bin/psalm")):
            sarif = os.path.join(out_dir, "psalm.sarif")
            psalm_cmd = "psalm" if have("psalm") else "vendor/bin/psalm"
            tasks.append(
                (
                    "psalm",
                    _tool_thunk(
                        "psalm",
                        [psalm_cmd, "--taint-analysis", f"--report={sarif}"],
                        cwd=target,
                    ),
                )
            )
        else:
            skipped.append(
                {
                    "tool": "psalm",
                    "reason": "not installed or no composer.json — relying on semgrep's PHP ruleset",
                }
            )

    if "java" in langs:
        skipped.append(
            {
                "tool": "findsecbugs",
                "reason": "needs project-specific build wiring — see references/tools.md, not auto-run",
            }
        )

    if "dotnet" in langs:
        skipped.append(
            {
                "tool": "security-code-scan",
                "reason": "Roslyn analyzer, needs to be added to the .csproj — see references/tools.md, not auto-run",
            }
        )

    if "rust" in langs:
        # T-P1-1: cargo-audit is a separate crate; check `cargo audit --version` not just `cargo`
        if _cargo_audit_available():
            j = os.path.join(out_dir, "cargo-audit.json")
            tasks.append(
                (
                    "cargo-audit",
                    _tool_thunk(
                        "cargo-audit",
                        ["cargo", "audit", "--json"],
                        cwd=target,
                        output_file=j,
                    ),
                )
            )
        else:
            skipped.append(
                {
                    "tool": "cargo-audit",
                    "reason": "not installed — run `cargo install cargo-audit`",
                }
            )
        # Miri only worth it if there's unsafe code; leave to the caller/skill instructions
        # to decide since it's slow and needs a nightly toolchain.

    if "javascript" in langs:
        # njsscan: standalone Python CLI, non-intrusive, SARIF to stdout.
        if have("njsscan"):
            sarif = os.path.join(out_dir, "njsscan.sarif")
            tasks.append(
                (
                    "njsscan",
                    _tool_thunk(
                        "njsscan", ["njsscan", "--sarif", target], output_file=sarif
                    ),
                )
            )
        else:
            skipped.append(
                {
                    "tool": "njsscan",
                    "reason": "not installed — run install_tools.sh javascript (uv tool install njsscan)",
                }
            )
        # eslint-plugin-security: requires project-local config + the plugin as
        # a devDependency. Run only when wired; otherwise skip with guidance.
        # --no-install refuses silent downloads; -o writes the JSON report.
        if _eslint_security_configured(target):
            out_json = os.path.join(out_dir, "eslint-security.json")
            tasks.append(
                (
                    "eslint-security",
                    _tool_thunk(
                        "eslint-security",
                        [
                            "npx",
                            "--no-install",
                            "eslint",
                            "--format",
                            "json",
                            "--output-file",
                            out_json,
                            ".",
                        ],
                        cwd=target,
                    ),
                )
            )
        else:
            skipped.append(
                {
                    "tool": "eslint-security",
                    "reason": "eslint config not found or eslint-plugin-security not wired — see references/tools.md (npm install --save-dev eslint eslint-plugin-security, then add 'security' to plugins)",
                }
            )
        # retire.js: scans for known-CVE versions of frontend/Node libraries
        # (jquery, lodash, …) that ship in the project. Complements trivy's
        # npm lockfile scan by catching vendored/minified copies that aren't
        # in package-lock.json. Absorbed from strix's source-aware SAST playbook.
        if have("retire"):
            tasks.append(("retire", _retire_thunk(target, out_dir)))
        else:
            skipped.append(
                {
                    "tool": "retire",
                    "reason": "not installed — run install_tools.sh javascript (npm install -g retire)",
                }
            )

    ran = _run_concurrently(tasks)

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
    print(
        f"      python3 {os.path.join(SCRIPT_DIR, 'sarif_report.py')} {out_dir!r} --output {os.path.join(out_dir, 'report.sarif')}"
    )


if __name__ == "__main__":
    main()
