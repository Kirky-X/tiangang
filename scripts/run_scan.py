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
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
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
    "iac",         # IaC: Terraform/Kubernetes/Docker (checkov + tfsec)
}

# Default upper bound on concurrent scanners. Each scanner is an I/O-bound
# subprocess wait, so a modest parallelism turns a serial ~10-tool run into
# roughly the slowest single tool. Override via env for large hosts.
DEFAULT_MAX_WORKERS = max(2, (os.cpu_count() or 4))

# Tools that are CPU-intensive (internal parallelism via --jobs / multi-thread).
# These are serialized (max 2 concurrent) to avoid CPU oversubscription when
# running alongside I/O-bound tools that can share cores while waiting on disk.
_CPU_INTENSIVE_TOOLS = {"semgrep", "cppcheck", "semgrep-agent"}

# Global scan timeout (seconds). Prevents a single hung tool from blocking
# the entire scan indefinitely. Override via TIANGANG_SCAN_TIMEOUT env.
DEFAULT_SCAN_TIMEOUT = 3600  # 60 minutes


def _max_workers():
    env = os.environ.get("TIANGANG_MAX_WORKERS")
    if env:
        try:
            val = int(env.strip())
            if val > 0:
                return val
        except ValueError:
            pass
    return DEFAULT_MAX_WORKERS


def _scan_timeout():
    env = os.environ.get("TIANGANG_SCAN_TIMEOUT")
    if env:
        try:
            val = int(env.strip())
            if val > 0:
                return val
        except ValueError:
            pass
    return DEFAULT_SCAN_TIMEOUT


class ToolPlugin:
    """Base class for scanner tool plugins.

    Subclass this to add a new scanner to tiangang without modifying the core
    dispatch logic. Each plugin declares:
      - name: unique identifier (used in manifest, skip reasons, etc.)
      - languages: set of languages this plugin handles
      - check_available(): whether the tool is installed
      - build_thunk(): return a callable that runs the tool and returns
        a list of ran_entry dicts (same shape as run_tool output)

    To register a plugin, add it to the PLUGIN_REGISTRY dict at module level.
    The dispatch system will automatically pick it up when the matching
    language is detected.

    Example:
        class MyPlugin(ToolPlugin):
            name = "my-scanner"
            languages = {"python"}
            def check_available(self, detect_info):
                return have("my-scanner")
            def build_thunk(self, target, out_dir, detect_info):
                out_file = os.path.join(out_dir, "my-scanner.json")
                cmd = ["my-scanner", "--json", "-o", out_file, target]
                return lambda: run_tool(self.name, cmd, out_file)
    """
    name: str = ""
    languages: set = set()

    def check_available(self, detect_info: dict) -> bool:
        """Return True if the tool is installed and ready to run."""
        raise NotImplementedError

    def build_thunk(self, target: str, out_dir: str, detect_info: dict):
        """Return a callable (thunk) that runs the scanner.

        The thunk should return a list of ran_entry dicts compatible with
        run_tool's output format. Return None to skip this plugin.
        """
        raise NotImplementedError


# Plugin registry: maps tool name -> ToolPlugin instance.
# Built-in tools are registered below via _register_builtin_plugins().
# External plugins can be added by calling register_plugin().
_PLUGIN_REGISTRY: dict = {}


def register_plugin(plugin: ToolPlugin):
    """Register a ToolPlugin instance. Call this at module load time."""
    _PLUGIN_REGISTRY[plugin.name] = plugin


def get_plugins():
    """Return all registered plugins."""
    return dict(_PLUGIN_REGISTRY)


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


def detect_languages(target, max_depth=0):
    """Detect languages in target dir. Returns {} on failure (with warning to stderr).

    Returns a dict with keys:
        languages: list of detected language names
        ext_counts: dict of language -> file count
        manifest_matches: list of strong-signal languages
        has_gemfile: bool — whether a Gemfile was found (for brakeman pre-check)
    """
    cmd = [sys.executable, os.path.join(SCRIPT_DIR, "detect_languages.py"), target, "--json"]
    if max_depth > 0:
        cmd.extend(["--max-depth", str(max_depth)])
    rc, out = sh(cmd)
    if rc != 0:
        print(f"warning: language detection failed (rc={rc}): {out}", file=sys.stderr)
        return {"languages": [], "ext_counts": {}, "manifest_matches": [], "has_gemfile": False}
    try:
        data = json.loads(out)
        # Normalize: ensure all expected keys exist even when the detector
        # returns a partial dict (e.g. {} with no "languages" key).
        result = {
            "languages": data.get("languages", []),
            "ext_counts": data.get("ext_counts", {}),
            "manifest_matches": data.get("manifest_matches", []),
            # Derive has_gemfile from manifest_matches (strong signal) — avoids
            # a redundant directory walk in _has_ruby_code().
            "has_gemfile": "ruby" in data.get("manifest_matches", []),
        }
        return result
    except Exception:
        return {"languages": [], "ext_counts": {}, "manifest_matches": [], "has_gemfile": False}


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


def _ocr_detect_project_type(target):
    """Detect project type from manifest files and return a review background.

    Mirrors ocr_scan.sh's detect_background() — checks for Cargo.toml (Rust),
    go.mod (Go), package.json (Node/TS), requirements.txt/pyproject.toml (Python),
    pubspec.yaml (Flutter/Dart). Returns a language-specific multi-dimension
    review background string that OCR passes to the LLM as context.
    """
    if os.path.isfile(os.path.join(target, "Cargo.toml")):
        return (
            "Rust项目全维度深度审查。必须覆盖以下全部维度：\n"
            "1.安全性: SQL注入/XSS/CSRF/路径注入/命令注入/敏感信息泄露/权限校验缺失\n"
            "2.线程安全与并发: 竞态条件/非原子复合操作/Mutex guard生命周期/跨.await持锁/原子操作ordering\n"
            "3.错误处理: unwrap/expect滥用/异常吞没/过早丢弃错误上下文/错误传播缺失\n"
            "4.所有权与生命周期: 引用逃逸/不必要clone/内部可变性滥用/引用循环/生命周期标注缺失\n"
            "5.Unsafe边界: unsafe块过大/缺少安全不变量文档/FFI边界未校验\n"
            "6.Async与取消安全: JoinHandle被丢弃/Future非取消安全/async中用同步IO\n"
            "7.性能: 循环内数据库查询(N+1)/O(n^2)查找/不必要分配/未预分配集合/热路径锁竞争\n"
            "8.测试覆盖: 关键逻辑路径是否有测试/边界条件覆盖"
        )
    if os.path.isfile(os.path.join(target, "go.mod")):
        return (
            "Go项目全维度深度审查。必须覆盖：\n"
            "1.安全性: SQL注入/XSS/命令注入/敏感信息泄露/权限校验\n"
            "2.并发安全: goroutine泄漏/channel死锁/竞态条件/Mutex使用/WaitGroup遗漏\n"
            "3.错误处理: error wrapping(%w)/defer资源释放/panic恢复/error返回值检查\n"
            "4.context传播: 超时传递/cancel传播/context.Value滥用\n"
            "5.接口设计: 小接口原则/错误类型设计/选项模式\n"
            "6.性能: 内存分配/切片预分配/字符串拼接\n"
            "7.测试覆盖: 表驱动测试/边界条件/mock注入"
        )
    if os.path.isfile(os.path.join(target, "package.json")):
        return (
            "Node.js/TypeScript项目全维度深度审查。必须覆盖：\n"
            "1.安全性: XSS/注入/原型污染/敏感信息泄露/依赖漏洞\n"
            "2.类型安全: any滥用/类型断言安全/泛型约束/null/undefined处理\n"
            "3.异步: Promise错误处理/未await/内存泄漏(事件监听器)/并发控制\n"
            "4.性能: 热路径分配/N+1查询/大数组操作\n"
            "5.可维护性: 命名/模块边界/循环依赖\n"
            "6.测试覆盖: 单元测试/mock/边界条件"
        )
    if (os.path.isfile(os.path.join(target, "requirements.txt"))
            or os.path.isfile(os.path.join(target, "pyproject.toml"))):
        return (
            "Python项目全维度深度审查。覆盖："
            "安全性/异常处理/类型提示/可变默认参数/性能/测试"
        )
    if os.path.isfile(os.path.join(target, "pubspec.yaml")):
        return (
            "Flutter/Dart项目全维度深度审查。覆盖："
            "安全性/Widget重建性能/Stream泄漏/空安全/异步/测试"
        )
    return "通用项目全维度深度审查。覆盖：安全性/错误处理/并发/性能/可维护性/测试"


def _ocr_setup_env():
    """Configure OCR environment variables and verify LLM connectivity.

    Token priority: OCR_LLM_TOKEN > AGNES_TOKEN (mapped to OCR_LLM_TOKEN).
    Sets defaults for OCR_LLM_URL, OCR_LLM_MODEL, OCR_LLM_PROTOCOL when not
    already configured. Returns (ok: bool, error_msg: str|None).
    """
    token = os.environ.get("OCR_LLM_TOKEN", "").strip()
    if not token:
        agnes = os.environ.get("AGNES_TOKEN", "").strip()
        if agnes:
            os.environ["OCR_LLM_TOKEN"] = agnes
            token = agnes
        else:
            return False, (
                "OCR API key not set. Export AGNES_TOKEN=<key> or "
                "OCR_LLM_TOKEN=<key> before running with --ocr."
            )
    # Defaults for endpoint configuration (absorbed from ocr_scan.sh).
    os.environ.setdefault("OCR_LLM_URL", "https://apihub.agnes-ai.com/v1/chat/completions")
    os.environ.setdefault("OCR_LLM_MODEL", "agnes-2.5-flash")
    os.environ.setdefault("OCR_LLM_PROTOCOL", "openai")
    # Connectivity test — fail fast before launching a long scan.
    try:
        proc = subprocess.run(
            ["ocr", "llm", "test"],
            capture_output=True, text=True, timeout=30,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        if "✓" not in combined and proc.returncode != 0:
            return False, (
                f"OCR LLM connectivity test failed (rc={proc.returncode}). "
                f"Check OCR_LLM_TOKEN and network. Output: {combined[-200:]}"
            )
    except subprocess.TimeoutExpired:
        return False, "OCR LLM connectivity test timed out (30s)"
    except FileNotFoundError:
        return False, "ocr CLI not found — run install_tools.sh first"
    except Exception as e:
        return False, f"OCR LLM connectivity test error: {e}"
    return True, None


def _ocr_find_subdirs(target):
    """Find immediate subdirectories containing source files for batch scanning.

    Mirrors ocr_scan.sh's directory discovery — scans each top-level directory
    separately to stay within rate limits, with a delay between batches.
    Returns a list of relative paths (relative to target).
    """
    src_exts = {".rs", ".go", ".ts", ".tsx", ".js", ".jsx", ".py", ".dart",
                ".java", ".rb", ".php", ".c", ".cpp", ".h", ".cs"}
    subdirs = []
    try:
        entries = sorted(os.listdir(target))
    except OSError:
        return subdirs
    for entry in entries:
        full = os.path.join(target, entry)
        if not os.path.isdir(full) or entry.startswith("."):
            continue
        # Check if this directory has any source files (shallow walk).
        for root, dirs, files in os.walk(full):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            if any(os.path.splitext(f)[1].lower() in src_exts for f in files):
                subdirs.append(entry)
                break
    return subdirs


def _ocr_extract_session_findings(target, out_dir):
    """Extract findings from OCR session JSONL files (richer than --format json).

    OCR stores detailed session data under ~/.opencodereview/sessions/ as JSONL.
    Each line with type=tool_call may carry review comments with severity,
    category, and content. This parser extracts and deduplicates those findings,
    writing them to ocr-session.json for the report parser.

    Returns the list of findings (may be empty if no session data found).
    """
    session_base = os.path.join(os.path.expanduser("~"), ".opencodereview", "sessions")
    if not os.path.isdir(session_base):
        return []
    # Try to match by project slug first, fall back to recent sessions.
    project_slug = re.sub(r"[^a-zA-Z0-9]", "-", os.path.basename(os.path.abspath(target)))
    session_dir = None
    try:
        for entry in sorted(os.listdir(session_base), reverse=True):
            full = os.path.join(session_base, entry)
            if not os.path.isdir(full):
                continue
            if project_slug in entry:
                session_dir = full
                break
        if session_dir is None:
            # Fallback: most recently modified session dir (within 2 hours).
            now = time.time()
            for entry in sorted(os.listdir(session_base), reverse=True):
                full = os.path.join(session_base, entry)
                if not os.path.isdir(full):
                    continue
                try:
                    mtime = os.path.getmtime(full)
                    if now - mtime < 7200:  # 2 hours
                        session_dir = full
                        break
                except OSError:
                    continue
    except OSError:
        return []
    if session_dir is None:
        return []
    # Parse all JSONL files in the session directory.
    findings = []
    seen = set()
    try:
        jsonl_files = sorted(
            [os.path.join(session_dir, f) for f in os.listdir(session_dir)
             if f.endswith(".jsonl")],
            key=os.path.getmtime, reverse=True,
        )
    except OSError:
        return []
    for jsonl_path in jsonl_files:
        try:
            with open(jsonl_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if d.get("type") != "tool_call":
                        continue
                    fp = d.get("filePath", "")
                    args_raw = d.get("arguments", "")
                    if not fp or not args_raw:
                        continue
                    try:
                        args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                    except json.JSONDecodeError:
                        continue
                    for comment in (args.get("comments") or []):
                        content = comment.get("content", "")
                        key = (fp, content[:80])
                        if key in seen:
                            continue
                        seen.add(key)
                        sev_raw = comment.get("severity", comment.get("level", "unknown"))
                        cat_raw = comment.get("category", comment.get("rule", "other"))
                        findings.append({
                            "path": fp,
                            "content": content,
                            "severity": str(sev_raw).lower(),
                            "category": str(cat_raw).lower(),
                            "start_line": comment.get("lines", comment.get("line_range", "?")),
                            "suggestion_code": comment.get("suggestion_code", ""),
                        })
        except OSError:
            continue
    # Write session findings to ocr-session.json for the parser.
    if findings:
        session_out = os.path.join(out_dir, "ocr-session.json")
        try:
            with open(session_out, "w") as f:
                json.dump(findings, f)
        except OSError:
            pass
    return findings


def _ocr_thunk(target, out_dir, ocr_mode="scan",
               ocr_background="", ocr_delay=5, ocr_retry=2, ocr_timeout=60):
    """OCR (open-code-review) AI-powered code review thunk.

    Two modes:
      - ``scan``: ``ocr scan`` — reviews whole files/dirs, no git needed.
        Uses batch scanning by subdirectory with rate-limit delays and
        failure retry (absorbed from ocr_scan.sh).
      - ``review``: ``ocr review`` — reviews git diffs (staged + unstaged).
        Best for PR/commit review. No batching needed (diff is bounded).

    Environment setup (token, connectivity) is handled by _ocr_setup_env().
    Project-type-aware review background is generated by
    _ocr_detect_project_type() and merged with user-supplied --ocr-background.

    OCR exits non-zero when findings exist — that's a finding, not a
    failure. Normalize rc=1 → 0 when the report file was produced.
    """

    def _run():
        r = []
        out_path = os.path.join(out_dir, "ocr.json")

        # --- Environment setup ---
        ok, err_msg = _ocr_setup_env()
        if not ok:
            r.append({
                "tool": "ocr", "command": "",
                "returncode": -1,
                "log_tail": f"[ocr env setup failed] {err_msg}",
            })
            return r

        # --- Build background string ---
        lang_bg = _ocr_detect_project_type(target)
        if ocr_background:
            full_background = f"{lang_bg}\n\n额外关注: {ocr_background}"
        else:
            full_background = lang_bg

        if ocr_mode == "review":
            # Git diff-based review — no batching needed.
            cmd = [
                "ocr", "review",
                "--format", "json",
                "--audience", "agent",
            ]
            run_tool("ocr", r, cmd, cwd=target, timeout=ocr_timeout * 10)
            # rc=1 means findings found — normalize to 0 when report exists.
            if r and r[-1]["returncode"] == 1 and os.path.exists(out_path):
                r[-1]["returncode"] = 0
                r[-1]["log_tail"] = (
                    (r[-1].get("log_tail") or "")
                    + "\n[ocr rc=1 normalized: findings detected, not a failure]"
                )
        else:
            # --- Batch scanning mode (absorbed from ocr_scan.sh) ---
            subdirs = _ocr_find_subdirs(target)
            if not subdirs:
                # No subdirectories — single scan of the whole target.
                cmd = [
                    "ocr", "scan",
                    "--format", "json",
                    "--output", out_path,
                    "--concurrency", "1",
                    "--background", full_background,
                    "--timeout", str(ocr_timeout),
                    target,
                ]
                run_tool("ocr", r, cmd, timeout=ocr_timeout * 10)
            else:
                # Batch by subdirectory with delays between batches.
                all_findings = []
                failed_files = set()
                for i, subdir in enumerate(subdirs):
                    if i > 0:
                        time.sleep(ocr_delay)
                    batch_out = os.path.join(out_dir, f"ocr_batch_{i}.json")
                    cmd = [
                        "ocr", "scan",
                        "--path", subdir,
                        "--concurrency", "1",
                        "--background", full_background,
                        "--format", "json",
                        "--output", batch_out,
                        "--timeout", str(ocr_timeout),
                    ]
                    batch_ran = []
                    run_tool("ocr", batch_ran, cmd, cwd=target,
                             timeout=ocr_timeout * 10)
                    r.extend(batch_ran)
                    # Collect findings from this batch.
                    if os.path.exists(batch_out):
                        try:
                            with open(batch_out) as f:
                                batch_data = json.load(f)
                            if isinstance(batch_data, list):
                                all_findings.extend(batch_data)
                        except (json.JSONDecodeError, OSError):
                            pass
                    # Track failed files for retry.
                    log_tail = batch_ran[-1].get("log_tail", "") if batch_ran else ""
                    for m in re.finditer(r"Scan subtask error for (\S+)", log_tail):
                        failed_files.add(m.group(1))

                # --- Retry failed files ---
                for retry_round in range(ocr_retry):
                    if not failed_files:
                        break
                    time.sleep(ocr_delay)
                    retry_list = sorted(failed_files)
                    failed_files = set()
                    retry_csv = ",".join(retry_list)
                    retry_out = os.path.join(out_dir, f"ocr_retry_{retry_round}.json")
                    cmd = [
                        "ocr", "scan",
                        "--path", retry_csv,
                        "--concurrency", "1",
                        "--background", full_background,
                        "--format", "json",
                        "--output", retry_out,
                        "--timeout", str(ocr_timeout),
                    ]
                    retry_ran = []
                    run_tool("ocr", retry_ran, cmd, cwd=target,
                             timeout=ocr_timeout * 10)
                    r.extend(retry_ran)
                    if os.path.exists(retry_out):
                        try:
                            with open(retry_out) as f:
                                retry_data = json.load(f)
                            if isinstance(retry_data, list):
                                all_findings.extend(retry_data)
                        except (json.JSONDecodeError, OSError):
                            pass
                    log_tail = retry_ran[-1].get("log_tail", "") if retry_ran else ""
                    for m in re.finditer(r"Scan subtask error for (\S+)", log_tail):
                        failed_files.add(m.group(1))

                # Write merged findings to ocr.json.
                if all_findings:
                    try:
                        with open(out_path, "w") as f:
                            json.dump(all_findings, f)
                    except OSError:
                        pass

            # Normalize rc for the last entry.
            if r and r[-1]["returncode"] == 1 and os.path.exists(out_path):
                r[-1]["returncode"] = 0
                r[-1]["log_tail"] = (
                    (r[-1].get("log_tail") or "")
                    + "\n[ocr rc=1 normalized: findings detected, not a failure]"
                )

        # --- Session extraction (enriches report with detailed session data) ---
        _ocr_extract_session_findings(target, out_dir)

        return r


def _checkov_thunk(target, out_dir):
    """checkov thunk — IaC security scanner (Terraform/K8s/Docker/CloudFormation).

    checkov scans infrastructure-as-code for misconfigurations and security
    issues. It outputs JSON to stdout; we capture it to a file for the
    report parser. Exit code 1 means findings were found (not a failure).
    """

    def _run():
        r = []
        out_path = os.path.join(out_dir, "checkov.json")
        run_tool(
            "checkov",
            r,
            [
                "checkov",
                "--directory", target,
                "--output", "json",
                "--quiet",
                "--compact",
            ],
            output_file=out_path,
            timeout=900,
        )
        # checkov exits 1 when findings exist — normalize to 0 when report exists.
        if r and r[-1]["returncode"] == 1 and os.path.exists(out_path):
            r[-1]["returncode"] = 0
            r[-1]["log_tail"] = (
                (r[-1].get("log_tail") or "")
                + "\n[checkov rc=1 normalized: findings detected, not a failure]"
            )
        return r

    return _run


def _tfsec_thunk(target, out_dir):
    """tfsec thunk — Terraform-specific security scanner.

    tfsec does deeper Terraform analysis than checkov (provider-specific
    security rules). Outputs JSON to stdout. Complements checkov's broader
    IaC coverage with Terraform-focused depth.
    """

    def _run():
        r = []
        out_path = os.path.join(out_dir, "tfsec.json")
        run_tool(
            "tfsec",
            r,
            [
                "tfsec",
                target,
                "--format", "json",
                "--out", out_path,
                "--soft-fail",
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


def _run_concurrently(tasks, sequential=False):
    """Run scanner thunks concurrently; return ran entries in planned order.

    ``tasks`` is a list of (name, fn) where fn() -> list[ran_entry]. Completion
    order is independent of output order: results are reindexed by their
    position in ``tasks`` so the manifest is deterministic (stable across runs
    and diffs). A thunk that raises is recorded as a single failed ran entry
    rather than aborting the batch — mirrors run_tool's "never raises, log it"
    contract so one crashed scanner doesn't sink the others.

    CPU-intensive tools (semgrep, cppcheck) are limited to min(2, workers)
    concurrent to avoid CPU oversubscription. I/O-bound tools use full
    parallelism. When ``sequential`` is True, all tools run one-by-one.
    """
    ran = []
    if not tasks:
        return ran
    if sequential:
        for name, fn in tasks:
            try:
                ran.extend(list(fn()))
            except Exception as e:
                ran.append({
                    "tool": name, "command": "", "returncode": -3,
                    "log_tail": f"[scanner task crashed] {type(e).__name__}: {e}",
                })
        return ran
    # Partition tasks into CPU-intensive and I/O-bound groups.
    cpu_tasks = [(n, f) for n, f in tasks if n in _CPU_INTENSIVE_TOOLS]
    io_tasks = [(n, f) for n, f in tasks if n not in _CPU_INTENSIVE_TOOLS]
    results_by_idx = {}
    task_idx = 0
    # Run CPU-intensive tools with limited parallelism first.
    if cpu_tasks:
        cpu_workers = min(2, len(cpu_tasks))
        with ThreadPoolExecutor(max_workers=cpu_workers) as ex:
            futures = {ex.submit(fn): task_idx + i for i, (_, fn) in enumerate(cpu_tasks)}
            for fut in as_completed(futures):
                idx = futures[fut]
                name = cpu_tasks[idx - task_idx][0]
                try:
                    results_by_idx[idx] = list(fut.result())
                except Exception as e:
                    results_by_idx[idx] = [{
                        "tool": name, "command": "", "returncode": -3,
                        "log_tail": f"[scanner task crashed] {type(e).__name__}: {e}",
                    }]
        task_idx += len(cpu_tasks)
    # Run I/O-bound tools with full parallelism.
    if io_tasks:
        io_workers = min(_max_workers(), len(io_tasks))
        with ThreadPoolExecutor(max_workers=io_workers) as ex:
            futures = {ex.submit(fn): task_idx + i for i, (_, fn) in enumerate(io_tasks)}
            for fut in as_completed(futures):
                idx = futures[fut]
                name = io_tasks[idx - task_idx][0]
                try:
                    results_by_idx[idx] = list(fut.result())
                except Exception as e:
                    results_by_idx[idx] = [{
                        "tool": name, "command": "", "returncode": -3,
                        "log_tail": f"[scanner task crashed] {type(e).__name__}: {e}",
                    }]
    for idx in sorted(results_by_idx):
        ran.extend(results_by_idx[idx])
    return ran


# ---------------------------------------------------------------------------
# Tool registry — data-driven dispatch replacing the old if-block chain.
#
# Each entry defines when a tool runs, how to check availability, how to
# build its thunk, and what to log when skipped. Adding a new scanner =
# appending one dict to this list + writing its thunk factory above.
#
# Fields:
#   name:        tool identifier (used in manifest + report)
#   langs:       set of languages that trigger this tool, or None = universal
#   available:   callable() -> bool; True = tool is installed
#   factory:     callable(target, out_dir, ctx) -> thunk; builds the scanner
#   skip_reason: str or callable(target, ctx) -> str|None;
#                if str: always-skip message (e.g. findsecbugs needs build wiring)
#                if callable: dynamic check (e.g. brakeman needs Ruby code)
#                if None: standard "not installed" message
# ---------------------------------------------------------------------------


def _build_registry(target, out_dir, agent_rules, detect_info,
                     ocr=False, ocr_delegate=False,
                     ocr_background="", ocr_delay=5, ocr_retry=2, ocr_timeout=60):
    """Build the tool registry with closures over target/out_dir/context.

    Separated from the dispatch loop so the registry is a plain data structure
    (testable, iterable, extensible) while the closures capture runtime values.
    """
    has_gemfile = detect_info.get("has_gemfile", False)
    return [
        # --- Universal: always run regardless of detected languages ---
        {
            "name": "semgrep",
            "langs": None,
            "available": lambda: have("semgrep"),
            "factory": lambda: _semgrep_thunk(target, out_dir, agent_rules),
        },
        {
            "name": "trivy",
            "langs": None,
            "available": lambda: have("trivy"),
            "factory": lambda: _trivy_thunk(target, out_dir),
        },
        {
            "name": "gitleaks",
            "langs": None,
            "available": lambda: have("gitleaks"),
            "factory": lambda: _gitleaks_thunk(target, out_dir),
        },
        {
            "name": "trufflehog",
            "langs": None,
            "available": lambda: have("trufflehog"),
            "factory": lambda: _trufflehog_thunk(target, out_dir),
        },
        # --- Python ---
        {
            "name": "bandit",
            "langs": {"python"},
            "available": lambda: have("bandit"),
            "factory": lambda: _tool_thunk(
                "bandit",
                ["bandit", "-r", target, "-f", "json", "-o",
                 os.path.join(out_dir, "bandit.json"),
                 "-x", "*/tests/*,*/venv/*,*/.venv/*"],
            ),
        },
        # --- Go ---
        {
            "name": "gosec",
            "langs": {"go"},
            "available": lambda: have("gosec"),
            "factory": lambda: _tool_thunk(
                "gosec",
                ["gosec", "-fmt=sarif",
                 f"-out={os.path.join(out_dir, 'gosec.sarif')}", "./..."],
                cwd=target,
            ),
        },
        # --- C/C++ ---
        {
            "name": "flawfinder",
            "langs": {"c_cpp"},
            "available": lambda: have("flawfinder"),
            "factory": lambda: _tool_thunk(
                "flawfinder",
                ["flawfinder", "--sarif", target],
                output_file=os.path.join(out_dir, "flawfinder.sarif"),
            ),
        },
        {
            "name": "cppcheck",
            "langs": {"c_cpp"},
            "available": lambda: have("cppcheck"),
            "factory": lambda: _tool_thunk(
                "cppcheck",
                ["cppcheck", "--enable=warning,portability",
                 "--xml", "--xml-version=2", target],
                output_file=os.path.join(out_dir, "cppcheck.xml"),
                output_stream="stderr",
            ),
        },
        # --- Ruby ---
        {
            "name": "brakeman",
            "langs": {"ruby"},
            "available": lambda: have("brakeman"),
            "factory": lambda: _tool_thunk(
                "brakeman",
                ["brakeman", "-f", "sarif", "-o",
                 os.path.join(out_dir, "brakeman.sarif"), target],
            ),
            # Dynamic skip: brakeman exits non-zero on non-Ruby projects.
            # Use detect_info["has_gemfile"] instead of a redundant directory
            # walk (_has_ruby_code) — the detection step already has this info.
            "skip_reason": (lambda: None if has_gemfile else
                            "no Ruby files or Gemfile found — brakeman only works on Ruby projects"),
        },
        # --- PHP ---
        {
            "name": "psalm",
            "langs": {"php"},
            "available": lambda: have("psalm") or os.path.exists(
                os.path.join(target, "vendor/bin/psalm")),
            "factory": lambda: _tool_thunk(
                "psalm",
                ["psalm" if have("psalm") else "vendor/bin/psalm",
                 "--taint-analysis",
                 f"--report={os.path.join(out_dir, 'psalm.sarif')}"],
                cwd=target,
            ),
            "skip_reason": "not installed or no composer.json — relying on semgrep's PHP ruleset",
        },
        # --- Java (always skipped — needs project build wiring) ---
        {
            "name": "findsecbugs",
            "langs": {"java"},
            "available": lambda: False,
            "factory": lambda: None,
            "skip_reason": "needs project-specific build wiring — see references/tools.md, not auto-run",
        },
        # --- .NET (always skipped — needs Roslyn analyzer wiring) ---
        {
            "name": "security-code-scan",
            "langs": {"dotnet"},
            "available": lambda: False,
            "factory": lambda: None,
            "skip_reason": "Roslyn analyzer, needs to be added to the .csproj — see references/tools.md, not auto-run",
        },
        # --- Rust ---
        {
            "name": "cargo-audit",
            "langs": {"rust"},
            "available": lambda: _cargo_audit_available(),
            "factory": lambda: _tool_thunk(
                "cargo-audit",
                ["cargo", "audit", "--json"],
                cwd=target,
                output_file=os.path.join(out_dir, "cargo-audit.json"),
            ),
            "skip_reason": "not installed — run `cargo install cargo-audit`",
        },
        # --- JavaScript/TypeScript ---
        {
            "name": "njsscan",
            "langs": {"javascript"},
            "available": lambda: have("njsscan"),
            "factory": lambda: _tool_thunk(
                "njsscan",
                ["njsscan", "--sarif", target],
                output_file=os.path.join(out_dir, "njsscan.sarif"),
            ),
        },
        {
            "name": "eslint-security",
            "langs": {"javascript"},
            "available": lambda: _eslint_security_configured(target),
            "factory": lambda: _tool_thunk(
                "eslint-security",
                ["npx", "--no-install", "eslint", "--format", "json",
                 "--output-file", os.path.join(out_dir, "eslint-security.json"), "."],
                cwd=target,
            ),
            "skip_reason": "eslint config not found or eslint-plugin-security not wired — see references/tools.md",
        },
        {
            "name": "retire",
            "langs": {"javascript"},
            "available": lambda: have("retire"),
            "factory": lambda: _retire_thunk(target, out_dir),
        },
        # --- IaC (Terraform/Kubernetes/Docker/CloudFormation) ---
        {
            "name": "checkov",
            "langs": {"iac"},
            "available": lambda: have("checkov"),
            "factory": lambda: _checkov_thunk(target, out_dir),
        },
        {
            "name": "tfsec",
            "langs": {"iac"},
            "available": lambda: have("tfsec"),
            "factory": lambda: _tfsec_thunk(target, out_dir),
        },
        # --- AI-powered code review (opt-in) ---
        # OCR adds an LLM-driven review layer on top of deterministic SAST.
        # Disabled by default because it requires external LLM API access
        # (unless ocr_delegate is set). Enable via --ocr or --ocr-delegate.
        {
            "name": "ocr",
            "langs": None,
            "available": lambda: (ocr or ocr_delegate) and have("ocr"),
            "factory": lambda: _ocr_thunk(
                target, out_dir,
                "review" if ocr_delegate else "scan",
                ocr_background=ocr_background,
                ocr_delay=ocr_delay,
                ocr_retry=ocr_retry,
                ocr_timeout=ocr_timeout,
            ),
            "skip_reason": "opt-in — pass --ocr or --ocr-delegate to enable AI code review",
        },
    ]


def _dispatch_registry(registry, langs):
    """Walk the registry and build (tasks, skipped) lists.

    For each entry:
    - If langs don't match → skip silently (tool not relevant).
    - If skip_reason is dynamic (callable) and returns a string → skip.
    - If available() → add to tasks.
    - Else → add to skipped with skip_reason or default "not installed".
    """
    tasks = []
    skipped = []
    lang_set = set(langs)

    for entry in registry:
        required = entry.get("langs")
        if required is not None and not (required & lang_set):
            continue  # language not detected — skip silently

        # Dynamic skip check (e.g. brakeman needs Ruby code / Gemfile).
        skip_fn = entry.get("skip_reason")
        if callable(skip_fn):
            dynamic_reason = skip_fn()
            if dynamic_reason:
                skipped.append({"tool": entry["name"], "reason": dynamic_reason})
                continue

        if entry["available"]():
            thunk = entry["factory"]()
            if thunk is not None:
                tasks.append((entry["name"], thunk))
        else:
            reason = skip_fn if isinstance(skip_fn, str) else "not installed — run install_tools.sh"
            skipped.append({"tool": entry["name"], "reason": reason})

    return tasks, skipped


def _get_changed_files(target, since="HEAD~1"):
    """Get list of changed files via git diff. Returns None if not a git repo.

    Used by --diff-only mode to restrict scanning to files modified since a
    given git ref. Returns absolute paths so downstream tools can match them
    against their scan targets.
    """
    try:
        proc = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", since],
            cwd=target, capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return None
        files = []
        for line in proc.stdout.strip().splitlines():
            line = line.strip()
            if line:
                files.append(os.path.join(target, line))
        return files if files else None
    except Exception:
        return None


def _file_hash_cache_path(target):
    """Return the path to the file hash cache for a given project.

    Cache is stored in ~/.tiangang/cache/<project-hash>/ where <project-hash>
    is a SHA256 of the project's absolute path (deterministic, unique per
    project). The cache contains file-hashes.json mapping (path -> sha256).
    """
    proj_hash = hashlib.sha256(os.path.abspath(target).encode()).hexdigest()[:16]
    return os.path.join(
        os.path.expanduser("~"), ".tiangang", "cache", proj_hash
    )


def _load_file_hash_cache(target):
    """Load the file hash cache from disk. Returns (cache_dict, manifest_dict).

    cache_dict: {file_path: sha256_hash}
    manifest_dict: {"last_full_scan": ISO timestamp, "last_diff_scan": ISO timestamp}
    """
    cache_dir = _file_hash_cache_path(target)
    hash_path = os.path.join(cache_dir, "file-hashes.json")
    manifest_path = os.path.join(cache_dir, "cache-manifest.json")
    cache = {}
    manifest = {}
    if os.path.exists(hash_path):
        try:
            with open(hash_path) as f:
                cache = json.load(f)
        except Exception:
            cache = {}
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except Exception:
            manifest = {}
    return cache, manifest


def _save_file_hash_cache(target, cache, manifest):
    """Persist file hash cache and manifest to disk."""
    cache_dir = _file_hash_cache_path(target)
    os.makedirs(cache_dir, exist_ok=True)
    with open(os.path.join(cache_dir, "file-hashes.json"), "w") as f:
        json.dump(cache, f, indent=2)
    with open(os.path.join(cache_dir, "cache-manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)


def _sha256_file(path):
    """Compute SHA256 hash of a file's contents."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _ci_exit_code(findings_by_severity, gate):
    """Compute CI exit code based on finding severities and gate threshold.

    Exit codes: 0=clean, 1=low/info, 2=medium, 3=high, 4=critical.
    ``gate`` determines which severity level triggers a non-zero exit:
      - 'critical': exit 4 only when critical findings exist
      - 'high': exit 3+ when high or critical findings exist
      - 'medium': exit 2+ when medium+ findings exist
      - 'low': exit 1+ when any findings exist
      - 'none': always exit 0 (report-only mode)
    """
    if gate == "none":
        return 0
    gate_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    gate_rank = gate_levels.get(gate, 4)
    severity_ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1, "unknown": 1}
    max_sev = 0
    for sev, count in findings_by_severity.items():
        if count > 0:
            max_sev = max(max_sev, severity_ranks.get(sev, 1))
    if max_sev >= gate_rank:
        return max_sev
    return 0


def _write_github_annotations(findings, out_dir):
    """Write GitHub Actions annotation file for PR inline commenting.

    Generates a file with ::error/::warning lines that GitHub Actions parses
    to display inline annotations on PR diffs. Each finding becomes one
    annotation line.
    """
    annotations_path = os.path.join(out_dir, "github-annotations.txt")
    severity_to_cmd = {"critical": "error", "high": "error", "medium": "warning", "low": "warning", "info": "notice"}
    lines = []
    for f in findings:
        cmd = severity_to_cmd.get(f.get("severity", "unknown"), "warning")
        file_path = f.get("file", "")
        line = f.get("line", "")
        if isinstance(line, int) or (isinstance(line, str) and line.isdigit()):
            line_part = f",line={line}"
        else:
            line_part = ""
        msg = f"[{f.get('tool', '?')}:{f.get('rule', '?')}] {f.get('message', '')}"
        lines.append(f"::{cmd} file={file_path}{line_part}::{msg}")
    with open(annotations_path, "w") as f:
        f.write("\n".join(lines))
    return annotations_path


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
    parser.add_argument(
        "--max-depth",
        type=int, default=0,
        help="Maximum directory depth for language detection (0 = unlimited). "
        "Useful for large monorepos.",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: exit code reflects finding severity, write GitHub Actions "
        "annotations. Use with --gate to control the blocking threshold.",
    )
    parser.add_argument(
        "--gate",
        choices=["critical", "high", "medium", "low", "none"],
        default="critical",
        help="CI gate threshold: exit non-zero only when findings at or above "
        "this severity are found (default: critical). Only effective with --ci.",
    )
    parser.add_argument(
        "--diff-only",
        action="store_true",
        help="Incremental mode: only scan files changed since --since ref. "
        "Falls back to full scan if git is not available.",
    )
    parser.add_argument(
        "--since",
        default="HEAD~1",
        help="Git ref for --diff-only (default: HEAD~1). "
        "E.g. main, HEAD~5, abc1234.",
    )
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Run all scanners sequentially (useful for resource-constrained CI).",
    )
    parser.add_argument(
        "--ocr",
        action="store_true",
        help="Enable AI-powered code review via open-code-review (ocr scan). "
        "Opt-in: requires ocr CLI + LLM API configuration (AGNES_TOKEN or OCR_LLM_TOKEN).",
    )
    parser.add_argument(
        "--ocr-delegate",
        action="store_true",
        help="Enable AI code review in delegate mode (ocr review). "
        "Uses git diff-based review. Priority over --ocr when both set.",
    )
    parser.add_argument(
        "--ocr-background",
        default="",
        help="Additional review context appended to the auto-detected project "
        "background. E.g. --ocr-background 'focus on auth module'.",
    )
    parser.add_argument(
        "--ocr-delay",
        type=int, default=5,
        help="Delay in seconds between OCR batch scans (default: 5). "
        "Prevents rate limiting with RPM=20.",
    )
    parser.add_argument(
        "--ocr-retry",
        type=int, default=2,
        help="Max retry rounds for failed OCR files (default: 2).",
    )
    parser.add_argument(
        "--ocr-timeout",
        type=int, default=60,
        help="Per-file timeout in minutes for OCR scans (default: 60).",
    )
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.abspath(args.out) if args.out else _default_out_dir(target)
    os.makedirs(out_dir, exist_ok=True)

    # T-P1-7: strip whitespace from each language token to avoid silent skip
    if args.langs:
        langs = [x.strip() for x in args.langs.split(",") if x.strip()]
        # When ruby is explicitly listed, check for actual Ruby files/Gemfile
        # so brakeman's skip_reason is accurate (not just "not installed").
        has_gemfile = "ruby" in langs and _has_ruby_code(target)
        detect_info = {"languages": langs, "has_gemfile": has_gemfile}
    else:
        detect_info = detect_languages(target, max_depth=args.max_depth)
        langs = detect_info["languages"]

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

    # Build the scan plan via the tool registry (data-driven dispatch).
    # Order is preserved in the manifest via task-index reassembly in
    # _run_concurrently.
    registry = _build_registry(
        target, out_dir, args.agent_rules, detect_info,
        ocr=args.ocr, ocr_delegate=args.ocr_delegate,
        ocr_background=args.ocr_background,
        ocr_delay=args.ocr_delay,
        ocr_retry=args.ocr_retry,
        ocr_timeout=args.ocr_timeout,
    )
    tasks, skipped = _dispatch_registry(registry, langs)

    # Incremental scan: filter tasks to only scan changed files when --diff-only.
    diff_mode = False
    if args.diff_only:
        changed = _get_changed_files(target, since=args.since)
        if changed is not None:
            diff_mode = True
            print(f"Incremental scan: {len(changed)} changed file(s) since {args.since}")
            # Update file hash cache — only run tools on changed files.
            cache, cache_manifest = _load_file_hash_cache(target)
            now_iso = datetime.now(timezone.utc).isoformat()
            changed_set = set(changed)
            # Check which changed files actually have new content (hash diff).
            truly_changed = []
            for fpath in changed:
                new_hash = _sha256_file(fpath)
                old_hash = cache.get(fpath)
                if new_hash != old_hash:
                    truly_changed.append(fpath)
                    if new_hash:
                        cache[fpath] = new_hash
            if not truly_changed and not args.ci:
                print("No file content changed since last scan — skipping.")
            cache_manifest["last_diff_scan"] = now_iso
            _save_file_hash_cache(target, cache, cache_manifest)
        else:
            print(
                "warning: --diff-only requested but git not available or not a git repo — "
                "falling back to full scan",
                file=sys.stderr,
            )

    ran = _run_concurrently(tasks, sequential=args.sequential)

    manifest = {
        "target": target,
        "out_dir": out_dir,
        "languages": langs,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ran": ran,
        "skipped": skipped,
        "diff_mode": diff_mode,
        "ci_mode": args.ci,
        "gate": args.gate if args.ci else None,
    }
    manifest_path = os.path.join(out_dir, "scan_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # Update full-scan cache timestamp when not in diff mode.
    if not diff_mode:
        cache, cache_manifest = _load_file_hash_cache(target)
        cache_manifest["last_full_scan"] = datetime.now(timezone.utc).isoformat()
        _save_file_hash_cache(target, cache, cache_manifest)

    print(f"\nRan {len(ran)} tool(s), skipped {len(skipped)}.")
    for s in skipped:
        print(f"  skipped: {s['tool']} — {s['reason']}")
    print(f"\nResults + manifest written to {out_dir}")

    # CI mode: generate annotations and compute exit code.
    if args.ci:
        # Import generate_report to parse findings for CI exit code.
        sys.path.insert(0, SCRIPT_DIR)
        from generate_report import collect_findings
        findings, _ = collect_findings(out_dir)
        if findings:
            annotations_path = _write_github_annotations(findings, out_dir)
            print(f"GitHub annotations written to {annotations_path}")
            # Also emit annotations to stdout so GitHub Actions picks them up.
            with open(annotations_path) as af:
                for line in af:
                    print(line.rstrip())
        # Compute severity counts for exit code.
        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        exit_code = _ci_exit_code(sev_counts, args.gate)
        print(f"\nCI gate={args.gate}, exit_code={exit_code}")
        print(
            f"      python3 {os.path.join(SCRIPT_DIR, 'generate_report.py')} {out_dir!r}"
        )
        sys.exit(exit_code)
    else:
        print(f"Next: python3 {os.path.join(SCRIPT_DIR, 'generate_report.py')} {out_dir!r}")
        print(
            f"      python3 {os.path.join(SCRIPT_DIR, 'sarif_report.py')} {out_dir!r} --output {os.path.join(out_dir, 'report.sarif')}"
        )


if __name__ == "__main__":
    main()
