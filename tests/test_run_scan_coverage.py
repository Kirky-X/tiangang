#!/usr/bin/env python3
"""Coverage tests for run_scan.py — targets 95%+ line coverage.

All external commands (semgrep/bandit/trivy/etc.) are mocked via
unittest.mock.patch; no real scanner is ever invoked. Tests verify
meaningful behavior: return values, side effects (files written),
error-branch handling, and call contracts — not just "doesn't crash".
"""
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import run_scan


# ---------------------------------------------------------------------------
# _max_workers
# ---------------------------------------------------------------------------
class TestMaxWorkers(unittest.TestCase):
    """_max_workers: env var TIANGANG_MAX_WORKERS overrides default."""

    def test_env_valid_number(self):
        with mock.patch.dict(os.environ, {"TIANGANG_MAX_WORKERS": "16"}):
            self.assertEqual(run_scan._max_workers(), 16)

    def test_env_invalid_string(self):
        with mock.patch.dict(os.environ, {"TIANGANG_MAX_WORKERS": "abc"}):
            self.assertEqual(run_scan._max_workers(), run_scan.DEFAULT_MAX_WORKERS)

    def test_env_zero(self):
        with mock.patch.dict(os.environ, {"TIANGANG_MAX_WORKERS": "0"}):
            self.assertEqual(run_scan._max_workers(), run_scan.DEFAULT_MAX_WORKERS)

    def test_env_negative(self):
        with mock.patch.dict(os.environ, {"TIANGANG_MAX_WORKERS": "-5"}):
            self.assertEqual(run_scan._max_workers(), run_scan.DEFAULT_MAX_WORKERS)

    def test_no_env_var(self):
        env = {k: v for k, v in os.environ.items() if k != "TIANGANG_MAX_WORKERS"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(run_scan._max_workers(), run_scan.DEFAULT_MAX_WORKERS)

    def test_env_empty_string(self):
        with mock.patch.dict(os.environ, {"TIANGANG_MAX_WORKERS": "  "}):
            self.assertEqual(run_scan._max_workers(), run_scan.DEFAULT_MAX_WORKERS)


# ---------------------------------------------------------------------------
# sh
# ---------------------------------------------------------------------------
class TestSh(unittest.TestCase):
    """sh: runs command as list (shell=False), never raises."""

    def test_list_command_success(self):
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="hello", stderr="warn"
            )
            rc, out = run_scan.sh(["echo", "hello"])
            self.assertEqual(rc, 0)
            self.assertIn("hello", out)
            self.assertIn("warn", out)
            mock_run.assert_called_once()
            # shell must not be True (default is False)
            self.assertFalse(mock_run.call_args.kwargs.get("shell", False))

    def test_timeout_expired(self):
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=[], timeout=30)
            rc, out = run_scan.sh(["sleep", "100"], timeout=30)
            self.assertEqual(rc, -1)
            self.assertIn("timed out", out)
            self.assertIn("30", out)

    def test_generic_exception(self):
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("no such command")
            rc, out = run_scan.sh(["nonexistent-cmd"])
            self.assertEqual(rc, -1)
            self.assertIn("no such command", out)

    def test_no_shell_true_in_source(self):
        """Source code must not use shell=True (security: command injection)."""
        source = inspect.getsource(run_scan.sh)
        self.assertNotIn("shell=True", source)

    def test_stdout_none_handled(self):
        """CompletedProcess with stdout=None should not crash."""
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=None, stderr=None
            )
            rc, out = run_scan.sh(["cmd"])
            self.assertEqual(rc, 0)
            self.assertEqual(out, "")


# ---------------------------------------------------------------------------
# have
# ---------------------------------------------------------------------------
class TestHave(unittest.TestCase):
    """have: shutil.which-based availability check."""

    def test_existing_command(self):
        self.assertTrue(run_scan.have("ls"))

    def test_nonexistent_command(self):
        self.assertFalse(run_scan.have("nonexistent-cmd-xyz-12345"))


# ---------------------------------------------------------------------------
# detect_languages
# ---------------------------------------------------------------------------
class TestDetectLanguages(unittest.TestCase):
    """detect_languages: returns dict with languages/has_gemfile on success, empty dict on failure."""

    def test_rc_nonzero_returns_empty(self):
        with mock.patch("run_scan.sh", return_value=(-1, "error: missing module")):
            result = run_scan.detect_languages("/tmp")
            self.assertEqual(result["languages"], [])
            self.assertFalse(result["has_gemfile"])

    def test_json_parse_failure_returns_empty(self):
        with mock.patch("run_scan.sh", return_value=(0, "not json")):
            result = run_scan.detect_languages("/tmp")
            self.assertEqual(result["languages"], [])

    def test_missing_languages_key_returns_empty(self):
        with mock.patch("run_scan.sh", return_value=(0, json.dumps({}))):
            result = run_scan.detect_languages("/tmp")
            self.assertEqual(result["languages"], [])

    def test_valid_json_returns_languages(self):
        payload = json.dumps({"languages": ["python", "go"]})
        with mock.patch("run_scan.sh", return_value=(0, payload)):
            result = run_scan.detect_languages("/tmp")
            self.assertEqual(result["languages"], ["python", "go"])


# ---------------------------------------------------------------------------
# run_tool
# ---------------------------------------------------------------------------
class TestRunTool(unittest.TestCase):
    """run_tool: runs subprocess, writes output_file, never raises."""

    def test_normal_execution(self):
        ran = []
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="output", stderr="err"
            )
            run_scan.run_tool("test-tool", ran, ["test-tool"])
            self.assertEqual(len(ran), 1)
            self.assertEqual(ran[0]["tool"], "test-tool")
            self.assertEqual(ran[0]["returncode"], 0)
            self.assertIn("output", ran[0]["log_tail"])
            self.assertIn("err", ran[0]["log_tail"])

    def test_output_file_written_stdout(self):
        ran = []
        with tempfile.TemporaryDirectory() as tmp:
            out_file = os.path.join(tmp, "out.txt")
            with mock.patch("run_scan.subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="stdout-content", stderr=""
                )
                run_scan.run_tool("test", ran, ["test"], output_file=out_file)
                self.assertEqual(ran[0]["returncode"], 0)
                with open(out_file) as f:
                    self.assertEqual(f.read(), "stdout-content")

    def test_output_file_write_failure(self):
        ran = []
        out_file = "/nonexistent/path/deep/out.txt"
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="content", stderr=""
            )
            run_scan.run_tool("test", ran, ["test"], output_file=out_file)
            self.assertEqual(ran[0]["returncode"], -2)
            self.assertIn("output write failed", ran[0]["log_tail"])

    def test_timeout(self):
        ran = []
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=[], timeout=30)
            run_scan.run_tool("test", ran, ["test"], timeout=30)
            self.assertEqual(ran[0]["returncode"], -1)
            self.assertIn("timed out", ran[0]["log_tail"])

    def test_output_stream_stderr(self):
        ran = []
        with tempfile.TemporaryDirectory() as tmp:
            out_file = os.path.join(tmp, "err.txt")
            with mock.patch("run_scan.subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="stdout-content", stderr="stderr-content"
                )
                run_scan.run_tool(
                    "test", ran, ["test"], output_file=out_file, output_stream="stderr"
                )
                with open(out_file) as f:
                    self.assertEqual(f.read(), "stderr-content")

    def test_generic_exception(self):
        ran = []
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("cmd not found")
            run_scan.run_tool("test", ran, ["test"])
            self.assertEqual(ran[0]["returncode"], -1)
            self.assertIn("cmd not found", ran[0]["log_tail"])

    def test_empty_content_not_written(self):
        """If content is empty, output file should not be created."""
        ran = []
        with tempfile.TemporaryDirectory() as tmp:
            out_file = os.path.join(tmp, "empty.txt")
            with mock.patch("run_scan.subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                )
                run_scan.run_tool("test", ran, ["test"], output_file=out_file)
                self.assertFalse(os.path.exists(out_file))

    def test_command_recorded_as_string(self):
        ran = []
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            run_scan.run_tool("t", ran, ["echo", "hi"])
            self.assertEqual(ran[0]["command"], "echo hi")


# ---------------------------------------------------------------------------
# _cargo_audit_available
# ---------------------------------------------------------------------------
class TestCargoAuditAvailable(unittest.TestCase):
    """_cargo_audit_available: checks cargo audit --version."""

    def test_available(self):
        with mock.patch("run_scan.sh", return_value=(0, "cargo-audit 0.17")):
            self.assertTrue(run_scan._cargo_audit_available())

    def test_not_available(self):
        with mock.patch("run_scan.sh", return_value=(1, "error")):
            self.assertFalse(run_scan._cargo_audit_available())

    def test_exception_returns_false(self):
        with mock.patch("run_scan.sh", side_effect=RuntimeError("boom")):
            self.assertFalse(run_scan._cargo_audit_available())


# ---------------------------------------------------------------------------
# _has_ruby_code
# ---------------------------------------------------------------------------
class TestHasRubyCode(unittest.TestCase):
    """_has_ruby_code: detects Ruby via Gemfile or .rb files."""

    def test_gemfile_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "Gemfile"), "w").close()
            self.assertTrue(run_scan._has_ruby_code(tmp))

    def test_rb_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "app.rb"), "w").close()
            self.assertTrue(run_scan._has_ruby_code(tmp))

    def test_rb_in_skip_dir_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            node_modules = os.path.join(tmp, "node_modules")
            os.makedirs(node_modules)
            open(os.path.join(node_modules, "lib.rb"), "w").close()
            self.assertFalse(run_scan._has_ruby_code(tmp))

    def test_rb_in_dot_dir_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            dot_dir = os.path.join(tmp, ".hidden")
            os.makedirs(dot_dir)
            open(os.path.join(dot_dir, "secret.rb"), "w").close()
            self.assertFalse(run_scan._has_ruby_code(tmp))

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(run_scan._has_ruby_code(tmp))


# ---------------------------------------------------------------------------
# _run_semgrep
# ---------------------------------------------------------------------------
class TestRunSemgrep(unittest.TestCase):
    """_run_semgrep: main + offline fallback + optional agent rules."""

    def test_main_success(self):
        ran = []
        with mock.patch("run_scan.sh", return_value=(0, "scan complete")):
            run_scan._run_semgrep("/target", "/out", ran)
            self.assertEqual(len(ran), 1)
            self.assertEqual(ran[0]["tool"], "semgrep")
            self.assertEqual(ran[0]["returncode"], 0)
            self.assertIn("scan complete", ran[0]["log_tail"])

    def test_fallback_on_network_error(self):
        ran = []
        with mock.patch(
            "run_scan.sh",
            side_effect=[
                (-1, "Error: network connection failed"),
                (0, "fallback scan complete"),
            ],
        ):
            run_scan._run_semgrep("/target", "/out", ran)
            self.assertEqual(len(ran), 1)
            self.assertEqual(ran[0]["returncode"], 0)
            self.assertIn("[first attempt", ran[0]["log_tail"])
            self.assertIn("[fallback", ran[0]["log_tail"])
            self.assertIn("network connection failed", ran[0]["log_tail"])
            self.assertIn("fallback scan complete", ran[0]["log_tail"])

    def test_fallback_on_timeout_keyword(self):
        ran = []
        with mock.patch(
            "run_scan.sh",
            side_effect=[(-1, "Error: timeout reaching registry"), (0, "ok")],
        ):
            run_scan._run_semgrep("/target", "/out", ran)
            self.assertEqual(ran[0]["returncode"], 0)
            self.assertIn("[fallback", ran[0]["log_tail"])

    def test_no_fallback_without_keyword(self):
        ran = []
        with mock.patch("run_scan.sh", return_value=(-1, "some other error")):
            run_scan._run_semgrep("/target", "/out", ran)
            self.assertEqual(len(ran), 1)
            self.assertEqual(ran[0]["returncode"], -1)
            self.assertNotIn("[fallback", ran[0]["log_tail"])

    def test_agent_rules_file_exists(self):
        ran = []
        with tempfile.TemporaryDirectory() as tmp:
            agent_rules = os.path.join(tmp, "rules.yml")
            open(agent_rules, "w").close()
            with mock.patch("run_scan.sh", return_value=(0, "ok")):
                with mock.patch("run_scan.run_tool") as mock_rt:
                    run_scan._run_semgrep(
                        "/target", "/out", ran, agent_rules=agent_rules
                    )
                    # semgrep entry appended directly; run_tool called for agent
                    self.assertEqual(len(ran), 1)
                    mock_rt.assert_called_once()
                    self.assertEqual(mock_rt.call_args.args[0], "semgrep-agent")
                    self.assertEqual(mock_rt.call_args.args[1], ran)
                    self.assertEqual(mock_rt.call_args.kwargs.get("timeout"), 900)

    def test_agent_rules_file_not_exists(self):
        ran = []
        with mock.patch("run_scan.sh", return_value=(0, "ok")):
            run_scan._run_semgrep(
                "/target", "/out", ran, agent_rules="/nonexistent/rules.yml"
            )
            self.assertEqual(len(ran), 1)
            # No agent entry added — only the main semgrep entry.

    def test_no_agent_rules(self):
        ran = []
        with mock.patch("run_scan.sh", return_value=(0, "ok")):
            run_scan._run_semgrep("/target", "/out", ran, agent_rules=None)
            self.assertEqual(len(ran), 1)


# ---------------------------------------------------------------------------
# Thunks
# ---------------------------------------------------------------------------
class TestThunks(unittest.TestCase):
    """Each thunk wraps run_tool / _run_semgrep as a closure returning ran."""

    @staticmethod
    def _fake_run_tool(name, ran, cmd, **kwargs):
        ran.append(
            {
                "tool": name,
                "command": " ".join(cmd),
                "returncode": 0,
                "log_tail": "",
            }
        )

    def test_tool_thunk(self):
        thunk = run_scan._tool_thunk("test-tool", ["test-tool", "--flag"])
        with mock.patch("run_scan.run_tool", side_effect=self._fake_run_tool) as mock_rt:
            result = thunk()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["tool"], "test-tool")
            mock_rt.assert_called_once()

    def test_tool_thunk_forwards_kwargs(self):
        thunk = run_scan._tool_thunk(
            "t", ["t"], output_file="/tmp/x", timeout=120
        )
        with mock.patch("run_scan.run_tool", side_effect=self._fake_run_tool) as mock_rt:
            thunk()
            self.assertEqual(mock_rt.call_args.kwargs.get("output_file"), "/tmp/x")
            self.assertEqual(mock_rt.call_args.kwargs.get("timeout"), 120)

    def test_semgrep_thunk(self):
        thunk = run_scan._semgrep_thunk("/target", "/out", None)
        with mock.patch("run_scan._run_semgrep") as mock_rs:
            mock_rs.side_effect = (
                lambda target, out_dir, ran, agent_rules=None: ran.append(
                    {"tool": "semgrep", "returncode": 0}
                )
            )
            result = thunk()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["tool"], "semgrep")
            mock_rs.assert_called_once_with("/target", "/out", mock.ANY, agent_rules=None)

    def test_trivy_thunk(self):
        thunk = run_scan._trivy_thunk("/target", "/out")
        with mock.patch("run_scan.run_tool", side_effect=self._fake_run_tool) as mock_rt:
            result = thunk()
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["tool"], "trivy-version")
            self.assertEqual(result[1]["tool"], "trivy")
            self.assertEqual(mock_rt.call_count, 2)

    def test_gitleaks_thunk_rc1_normalized(self):
        """rc=1 + output file exists → normalized to 0."""
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "gitleaks.json")
            open(out_path, "w").close()
            thunk = run_scan._gitleaks_thunk("/target", tmp)

            def fake_run_tool(name, ran, cmd, **kwargs):
                ran.append(
                    {
                        "tool": name,
                        "command": " ".join(cmd),
                        "returncode": 1,
                        "log_tail": "found secrets",
                    }
                )

            with mock.patch("run_scan.run_tool", side_effect=fake_run_tool):
                result = thunk()
                self.assertEqual(result[0]["returncode"], 0)
                self.assertIn("normalized", result[0]["log_tail"])

    def test_gitleaks_thunk_rc1_no_file_not_normalized(self):
        """rc=1 but no output file → stays 1."""
        with tempfile.TemporaryDirectory() as tmp:
            thunk = run_scan._gitleaks_thunk("/target", tmp)

            def fake_run_tool(name, ran, cmd, **kwargs):
                ran.append(
                    {
                        "tool": name,
                        "command": " ".join(cmd),
                        "returncode": 1,
                        "log_tail": "found secrets",
                    }
                )

            with mock.patch("run_scan.run_tool", side_effect=fake_run_tool):
                result = thunk()
                self.assertEqual(result[0]["returncode"], 1)

    def test_gitleaks_thunk_rc0(self):
        """rc=0 → no normalization."""
        with tempfile.TemporaryDirectory() as tmp:
            thunk = run_scan._gitleaks_thunk("/target", tmp)
            with mock.patch("run_scan.run_tool", side_effect=self._fake_run_tool):
                result = thunk()
                self.assertEqual(result[0]["returncode"], 0)

    def test_trufflehog_thunk(self):
        thunk = run_scan._trufflehog_thunk("/target", "/out")
        with mock.patch("run_scan.run_tool", side_effect=self._fake_run_tool) as mock_rt:
            result = thunk()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["tool"], "trufflehog")
            self.assertEqual(mock_rt.call_count, 1)

    def test_retire_thunk(self):
        thunk = run_scan._retire_thunk("/target", "/out")
        with mock.patch("run_scan.run_tool", side_effect=self._fake_run_tool) as mock_rt:
            result = thunk()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["tool"], "retire")
            self.assertEqual(mock_rt.call_count, 1)


# ---------------------------------------------------------------------------
# _eslint_security_configured
# ---------------------------------------------------------------------------
class TestEslintSecurityConfigured(unittest.TestCase):
    """_eslint_security_configured: detects eslint-plugin-security wiring."""

    def test_eslint_config_js_with_plugin_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "eslint.config.js"), "w") as f:
                f.write("module.exports = { plugins: ['eslint-plugin-security'] }")
            self.assertTrue(run_scan._eslint_security_configured(tmp))

    def test_eslintrc_json_with_plugin_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".eslintrc.json"), "w") as f:
                f.write('{"extends": ["plugin:security/recommended"]}')
            self.assertTrue(run_scan._eslint_security_configured(tmp))

    def test_eslintrc_yml_with_double_quote_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".eslintrc.yml"), "w") as f:
                f.write('plugins:\n  - "security"')
            self.assertTrue(run_scan._eslint_security_configured(tmp))

    def test_eslintrc_with_single_quote_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".eslintrc.js"), "w") as f:
                f.write("plugins: ['security']")
            self.assertTrue(run_scan._eslint_security_configured(tmp))

    def test_config_without_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "eslint.config.mjs"), "w") as f:
                f.write("export default { rules: { 'no-undef': 'error' } }")
            self.assertFalse(run_scan._eslint_security_configured(tmp))

    def test_no_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(run_scan._eslint_security_configured(tmp))

    def test_config_read_error_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "eslint.config.js"), "w").close()
            with mock.patch("builtins.open", side_effect=OSError("permission denied")):
                self.assertFalse(run_scan._eslint_security_configured(tmp))


# ---------------------------------------------------------------------------
# _default_out_dir
# ---------------------------------------------------------------------------
class TestDefaultOutDir(unittest.TestCase):
    """_default_out_dir: ~/.tiangang/scans/ or tempfile fallback on OSError."""

    def test_normal_path(self):
        with tempfile.TemporaryDirectory() as fake_home:
            target = os.path.join(fake_home, "myproject")
            os.makedirs(target)
            with mock.patch("run_scan.os.path.expanduser", return_value=fake_home):
                result = run_scan._default_out_dir(target)
            self.assertIn(".tiangang", result)
            self.assertIn("scans", result)
            self.assertIn("myproject", result)
            self.assertTrue(os.path.isdir(result))

    def test_fallback_on_oserror(self):
        with mock.patch("run_scan.os.makedirs", side_effect=OSError("permission denied")):
            result = run_scan._default_out_dir("/target")
            self.assertIn("tiangang-", result)
            self.assertTrue(os.path.isdir(result))
            shutil.rmtree(result, ignore_errors=True)


# ---------------------------------------------------------------------------
# _run_concurrently
# ---------------------------------------------------------------------------
class TestRunConcurrently(unittest.TestCase):
    """_run_concurrently: order-preserving, exception-tolerant."""

    def test_empty_tasks(self):
        self.assertEqual(run_scan._run_concurrently([]), [])

    def test_order_preserved_regardless_of_completion(self):
        """Results must be in task-declaration order, not completion order."""
        tasks = [
            ("a", lambda: [{"tool": "a", "returncode": 0, "log_tail": "", "command": ""}]),
            ("b", lambda: [{"tool": "b", "returncode": 0, "log_tail": "", "command": ""}]),
            ("c", lambda: [{"tool": "c", "returncode": 0, "log_tail": "", "command": ""}]),
        ]
        result = run_scan._run_concurrently(tasks)
        self.assertEqual([r["tool"] for r in result], ["a", "b", "c"])

    def test_thunk_exception_recorded_as_failed(self):
        def boom():
            raise RuntimeError("scanner crashed")

        tasks = [("crash", boom)]
        result = run_scan._run_concurrently(tasks)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["returncode"], -3)
        self.assertEqual(result[0]["tool"], "crash")
        self.assertIn("scanner task crashed", result[0]["log_tail"])
        self.assertIn("RuntimeError", result[0]["log_tail"])
        self.assertIn("scanner crashed", result[0]["log_tail"])

    def test_multiple_entries_per_thunk(self):
        """A thunk may return multiple ran entries; all preserved."""
        tasks = [
            ("multi", lambda: [
                {"tool": "t1", "returncode": 0, "log_tail": "", "command": ""},
                {"tool": "t2", "returncode": 1, "log_tail": "", "command": ""},
            ]),
        ]
        result = run_scan._run_concurrently(tasks)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["tool"], "t1")
        self.assertEqual(result[1]["tool"], "t2")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
class TestMain(unittest.TestCase):
    """main: argparse, task building, manifest writing."""

    @staticmethod
    def _setup_mocks(stack, have_map=None, ruby_code=False, cargo_audit=False,
                     eslint=False, langs_auto=None, capture_tasks=False):
        """Wire up common mocks for main(). Returns (mocks_dict, captured_tasks)."""
        have_map = have_map or {}
        captured = []

        def have_fn(cmd):
            return have_map.get(cmd, False)

        def detect_fn(target, **kwargs):
            return {
                "languages": langs_auto or [],
                "ext_counts": {},
                "manifest_matches": ["ruby"] if ruby_code else [],
                "has_gemfile": ruby_code,
            }

        def run_concurrently_fn(tasks, sequential=False):
            if capture_tasks:
                captured.extend(tasks)
            return []

        mocks = {
            "have": stack.enter_context(
                mock.patch("run_scan.have", side_effect=have_fn)
            ),
            "detect_languages": stack.enter_context(
                mock.patch("run_scan.detect_languages", side_effect=detect_fn)
            ),
            "_has_ruby_code": stack.enter_context(
                mock.patch("run_scan._has_ruby_code", return_value=ruby_code)
            ),
            "_cargo_audit_available": stack.enter_context(
                mock.patch("run_scan._cargo_audit_available", return_value=cargo_audit)
            ),
            "_eslint_security_configured": stack.enter_context(
                mock.patch("run_scan._eslint_security_configured", return_value=eslint)
            ),
            "_run_concurrently": stack.enter_context(
                mock.patch("run_scan._run_concurrently", side_effect=run_concurrently_fn)
            ),
        }
        return mocks, captured

    def test_non_directory_exits_1(self):
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(sys, "argv", ["run_scan.py", "/nonexistent/pathxyz"])
            )
            self._setup_mocks(stack)
            with self.assertRaises(SystemExit) as ctx:
                run_scan.main()
            self.assertEqual(ctx.exception.code, 1)

    def test_all_tools_absent_all_skipped(self):
        """Every tool skipped when none installed; manifest records all skips."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "run_scan.py", target, "--out", out_dir,
                        "--langs",
                        "python,go,c_cpp,ruby,php,java,dotnet,rust,javascript",
                    ],
                )
            )
            mocks, _ = self._setup_mocks(
                stack, ruby_code=True, cargo_audit=False, eslint=False
            )
            run_scan.main()

            manifest_path = os.path.join(out_dir, "scan_manifest.json")
            self.assertTrue(os.path.exists(manifest_path))
            with open(manifest_path) as f:
                manifest = json.load(f)
            skipped_tools = {s["tool"] for s in manifest["skipped"]}
            # Every tool should be in skipped
            for tool in ("semgrep", "trivy", "gitleaks", "trufflehog",
                         "bandit", "gosec", "flawfinder", "cppcheck",
                         "brakeman", "psalm", "findsecbugs",
                         "security-code-scan", "cargo-audit",
                         "njsscan", "eslint-security", "retire"):
                self.assertIn(tool, skipped_tools, f"{tool} should be skipped")
            self.assertEqual(manifest["ran"], [])

    def test_all_tools_present_all_tasked(self):
        """Every tool becomes a task when all are installed."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "run_scan.py", target, "--out", out_dir,
                        "--langs",
                        "python,go,c_cpp,ruby,php,java,dotnet,rust,javascript",
                    ],
                )
            )
            all_present = {
                "semgrep", "trivy", "gitleaks", "trufflehog",
                "bandit", "gosec", "flawfinder", "cppcheck",
                "brakeman", "psalm", "njsscan", "retire",
            }
            _, captured = self._setup_mocks(
                stack, have_map={t: True for t in all_present},
                ruby_code=True, cargo_audit=True, eslint=True,
                capture_tasks=True,
            )
            run_scan.main()

            tasked_tools = {name for name, _ in captured}
            for tool in ("semgrep", "trivy", "gitleaks", "trufflehog",
                         "bandit", "gosec", "flawfinder", "cppcheck",
                         "brakeman", "psalm", "cargo-audit",
                         "njsscan", "eslint-security", "retire"):
                self.assertIn(tool, tasked_tools, f"{tool} should be tasked")

    def test_ruby_no_ruby_code_skips_brakeman(self):
        """When no Ruby code present, brakeman skipped with specific reason."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv",
                    ["run_scan.py", target, "--out", out_dir, "--langs", "ruby"],
                )
            )
            self._setup_mocks(stack, ruby_code=False)
            run_scan.main()
            with open(os.path.join(out_dir, "scan_manifest.json")) as f:
                manifest = json.load(f)
            brakeman_skips = [
                s for s in manifest["skipped"] if s["tool"] == "brakeman"
            ]
            self.assertEqual(len(brakeman_skips), 1)
            self.assertIn("no Ruby files", brakeman_skips[0]["reason"])

    def test_unknown_lang_filtered_with_warning(self):
        """Unknown --langs entries are filtered out and warned on stderr."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv",
                    ["run_scan.py", target, "--out", out_dir,
                     "--langs", "python,unknownlang"],
                )
            )
            self._setup_mocks(stack)
            with mock.patch("sys.stderr") as mock_stderr:
                run_scan.main()
            with open(os.path.join(out_dir, "scan_manifest.json")) as f:
                manifest = json.load(f)
            self.assertEqual(manifest["languages"], ["python"])
            self.assertNotIn("unknownlang", manifest["languages"])

    def test_auto_detect_languages_called(self):
        """When --langs omitted, detect_languages is invoked."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv", ["run_scan.py", target, "--out", out_dir],
                )
            )
            mocks, _ = self._setup_mocks(stack, langs_auto=["python", "go"])
            run_scan.main()
            mocks["detect_languages"].assert_called_once()

    def test_agent_rules_passed_to_semgrep_thunk(self):
        """--agent-rules is forwarded to _semgrep_thunk."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv",
                    ["run_scan.py", target, "--out", out_dir,
                     "--agent-rules", "/path/to/rules.yml"],
                )
            )
            mocks, captured = self._setup_mocks(
                stack, have_map={"semgrep": True}, capture_tasks=True
            )
            # Mock _semgrep_thunk to capture agent_rules arg
            with mock.patch("run_scan._semgrep_thunk") as mock_st:
                mock_st.return_value = lambda: []
                run_scan.main()
                mock_st.assert_called_once()
                self.assertEqual(
                    mock_st.call_args.args[2], "/path/to/rules.yml"
                )

    def test_manifest_written_with_correct_fields(self):
        """scan_manifest.json must contain target, out_dir, languages, ran, skipped."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv",
                    ["run_scan.py", target, "--out", out_dir, "--langs", "python"],
                )
            )
            self._setup_mocks(stack)
            run_scan.main()
            with open(os.path.join(out_dir, "scan_manifest.json")) as f:
                manifest = json.load(f)
            self.assertEqual(manifest["target"], os.path.abspath(target))
            self.assertEqual(manifest["out_dir"], os.path.abspath(out_dir))
            self.assertEqual(manifest["languages"], ["python"])
            self.assertIn("timestamp", manifest)
            self.assertIsInstance(manifest["ran"], list)
            self.assertIsInstance(manifest["skipped"], list)

    def test_php_vendor_bin_psalm_used(self):
        """When psalm not on PATH but vendor/bin/psalm exists, use vendor path."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            # Create vendor/bin/psalm in target
            os.makedirs(os.path.join(target, "vendor", "bin"))
            open(os.path.join(target, "vendor", "bin", "psalm"), "w").close()
            stack.enter_context(
                mock.patch.object(
                    sys, "argv",
                    ["run_scan.py", target, "--out", out_dir, "--langs", "php"],
                )
            )
            _, captured = self._setup_mocks(
                stack, have_map={"psalm": False}, capture_tasks=True
            )
            run_scan.main()
            # psalm should be tasked (via vendor/bin/psalm)
            psalm_tasks = [t for t in captured if t[0] == "psalm"]
            self.assertEqual(len(psalm_tasks), 1)

    def test_php_psalm_not_installed_skipped(self):
        """When psalm not on PATH and no vendor/bin/psalm, skip with guidance."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv",
                    ["run_scan.py", target, "--out", out_dir, "--langs", "php"],
                )
            )
            self._setup_mocks(stack, have_map={"psalm": False})
            run_scan.main()
            with open(os.path.join(out_dir, "scan_manifest.json")) as f:
                manifest = json.load(f)
            psalm_skips = [s for s in manifest["skipped"] if s["tool"] == "psalm"]
            self.assertEqual(len(psalm_skips), 1)

    def test_java_always_skipped(self):
        """Java/findsecbugs is always skipped (needs project-specific wiring)."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv",
                    ["run_scan.py", target, "--out", out_dir, "--langs", "java"],
                )
            )
            self._setup_mocks(stack)
            run_scan.main()
            with open(os.path.join(out_dir, "scan_manifest.json")) as f:
                manifest = json.load(f)
            findsecbugs = [s for s in manifest["skipped"] if s["tool"] == "findsecbugs"]
            self.assertEqual(len(findsecbugs), 1)
            self.assertIn("build wiring", findsecbugs[0]["reason"])

    def test_dotnet_always_skipped(self):
        """.NET/security-code-scan is always skipped (needs .csproj wiring)."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv",
                    ["run_scan.py", target, "--out", out_dir, "--langs", "dotnet"],
                )
            )
            self._setup_mocks(stack)
            run_scan.main()
            with open(os.path.join(out_dir, "scan_manifest.json")) as f:
                manifest = json.load(f)
            scs = [s for s in manifest["skipped"] if s["tool"] == "security-code-scan"]
            self.assertEqual(len(scs), 1)
            self.assertIn("csproj", scs[0]["reason"])

    def test_default_out_dir_used_when_no_out(self):
        """When --out omitted, _default_out_dir is called."""
        with tempfile.TemporaryDirectory() as target, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv", ["run_scan.py", target, "--langs", "python"],
                )
            )
            self._setup_mocks(stack)
            with mock.patch("run_scan._default_out_dir") as mock_dod:
                mock_dod.return_value = tempfile.mkdtemp()
                try:
                    run_scan.main()
                    mock_dod.assert_called_once()
                finally:
                    shutil.rmtree(mock_dod.return_value, ignore_errors=True)

    def test_empty_langs_prints_none_message(self):
        """When no languages detected, summary prints '(none detected — semgrep only)'."""
        with tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as out_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv", ["run_scan.py", target, "--out", out_dir],
                )
            )
            self._setup_mocks(stack, langs_auto=[])
            run_scan.main()
            with open(os.path.join(out_dir, "scan_manifest.json")) as f:
                manifest = json.load(f)
            self.assertEqual(manifest["languages"], [])


# ---------------------------------------------------------------------------
# _scan_timeout / _max_workers
# ---------------------------------------------------------------------------
class TestEnvConfig(unittest.TestCase):
    """Environment variable configuration: TIANGANG_SCAN_TIMEOUT, TIANGANG_MAX_WORKERS."""

    def test_scan_timeout_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            # Remove the env var if set
            os.environ.pop("TIANGANG_SCAN_TIMEOUT", None)
            result = run_scan._scan_timeout()
        self.assertEqual(result, run_scan.DEFAULT_SCAN_TIMEOUT)

    def test_scan_timeout_from_env(self):
        with mock.patch.dict(os.environ, {"TIANGANG_SCAN_TIMEOUT": "120"}):
            result = run_scan._scan_timeout()
        self.assertEqual(result, 120)

    def test_scan_timeout_invalid_falls_back(self):
        with mock.patch.dict(os.environ, {"TIANGANG_SCAN_TIMEOUT": "not-a-number"}):
            result = run_scan._scan_timeout()
        self.assertEqual(result, run_scan.DEFAULT_SCAN_TIMEOUT)

    def test_max_workers_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("TIANGANG_MAX_WORKERS", None)
            result = run_scan._max_workers()
        self.assertEqual(result, run_scan.DEFAULT_MAX_WORKERS)

    def test_max_workers_from_env(self):
        with mock.patch.dict(os.environ, {"TIANGANG_MAX_WORKERS": "4"}):
            result = run_scan._max_workers()
        self.assertEqual(result, 4)


# ---------------------------------------------------------------------------
# IaC thunks (checkov / tfsec)
# ---------------------------------------------------------------------------
class TestIaCThunks(unittest.TestCase):
    """IaC scanner thunks: checkov and tfsec produce correct ran entries."""

    def test_checkov_thunk_runs_tool(self):
        with tempfile.TemporaryDirectory() as out_dir:
            thunk = run_scan._checkov_thunk("/tmp/target", out_dir)
            with mock.patch("run_scan.run_tool") as mock_rt:
                result = thunk()
                mock_rt.assert_called_once()
                args = mock_rt.call_args
                self.assertEqual(args[0][0], "checkov")
                cmd = args[0][2]
                self.assertIn("--directory", cmd)
                self.assertIn("/tmp/target", cmd)

    def test_tfsec_thunk_runs_tool(self):
        with tempfile.TemporaryDirectory() as out_dir:
            thunk = run_scan._tfsec_thunk("/tmp/target", out_dir)
            with mock.patch("run_scan.run_tool") as mock_rt:
                result = thunk()
                mock_rt.assert_called_once()
                args = mock_rt.call_args
                self.assertEqual(args[0][0], "tfsec")
                cmd = args[0][2]
                self.assertIn("--format", cmd)
                self.assertIn("json", cmd)

    def test_checkov_in_registry(self):
        """checkov appears in registry when iac is detected."""
        detect_info = {"languages": ["iac"], "has_gemfile": False}
        registry = run_scan._build_registry(
            "/tmp", "/tmp/out", None, detect_info
        )
        names = [e["name"] for e in registry]
        self.assertIn("checkov", names)
        self.assertIn("tfsec", names)


if __name__ == "__main__":
    unittest.main()
