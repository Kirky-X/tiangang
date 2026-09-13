"""Tests for new optimization features added in v0.2.0.

Covers:
- Secret detection: new patterns + entropy fallback (redact.py)
- Language detection: expanded SKIP_DIRS + Makefile downgrade (detect_languages.py)
- CI/CD integration: _ci_exit_code, _write_github_annotations (run_scan.py)
- Parallelism: _run_concurrently sequential mode (run_scan.py)
- Incremental scanning: _get_changed_files, _sha256_file, hash cache (run_scan.py)
- Cross-tool correlation: _merge_confirmation, _proximity_match (generate_report.py)
- HTML/JSON report: render_html_report, render_json_report (generate_report.py)
- Triage prompt: generate_triage_prompt (generate_report.py)
- Trend tracking: save_trend_entry, load_trend_history, render_trend_section (generate_report.py)
- Plugin architecture: ToolPlugin, register_plugin, get_plugins (run_scan.py)
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import redact
import detect_languages
import run_scan
import generate_report


# ---------------------------------------------------------------------------
# Secret detection: new patterns + entropy fallback
# ---------------------------------------------------------------------------
class TestNewSecretPatterns(unittest.TestCase):
    """New secret patterns added in v0.2.0."""

    def test_alibaba_cloud_accesskey(self):
        text = "access_key_id=LTAIabcdef1234567890ab"
        result = redact.redact_secrets(text)
        self.assertIn(redact.REDACTED, result)
        self.assertNotIn("LTAIabcdef1234567890ab", result)

    def test_tencent_cloud_secret_id(self):
        text = "secret_id=AKIDabcdef1234567890abcdef"
        result = redact.redact_secrets(text)
        self.assertIn(redact.REDACTED, result)
        self.assertNotIn("AKIDabcdef1234567890abcdef", result)

    def test_openai_api_key(self):
        text = "api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = redact.redact_secrets(text)
        self.assertIn(redact.REDACTED, result)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz1234567890", result)

    def test_database_connection_string(self):
        text = "DATABASE_URL=postgresql://admin:secretpass123@db.example.com:5432/mydb"
        result = redact.redact_secrets(text)
        # Password portion should be redacted
        self.assertIn(redact.REDACTED, result)
        self.assertNotIn("secretpass123", result)
        # Connection structure should be preserved
        self.assertIn("postgresql://admin:", result)

    def test_mongodb_connection_string(self):
        text = "mongodb+srv://user:mypassword@cluster.mongodb.net/db"
        result = redact.redact_secrets(text)
        self.assertIn(redact.REDACTED, result)
        self.assertNotIn("mypassword", result)


class TestEntropyDetection(unittest.TestCase):
    """Shannon entropy-based fallback secret detection."""

    def test_shannon_entropy_high_entropy_string(self):
        # Random-looking string with many unique chars should have high entropy
        s = "aB3xK9mP2qR7wZ5nY8vL4cJ6dF1h"
        entropy = redact._shannon_entropy(s)
        self.assertGreater(entropy, 4.0)

    def test_shannon_entropy_low_entropy_string(self):
        # Repeated characters should have low entropy
        s = "aaaaaaaaaaaaaaa"
        entropy = redact._shannon_entropy(s)
        self.assertEqual(entropy, 0.0)

    def test_shannon_entropy_empty_string(self):
        self.assertEqual(redact._shannon_entropy(""), 0.0)

    def test_high_entropy_token_redacted(self):
        # A high-entropy token with mixed case and digits should be redacted
        text = "token=Xk9mP2qR7wZ5nB3xY8vL"
        result = redact._redact_high_entropy(text)
        self.assertIn(redact.REDACTED, result)

    def test_low_entropy_token_not_redacted(self):
        # All-lowercase words should NOT be redacted
        text = "this_is_a_normal_variable_name"
        result = redact._redact_high_entropy(text)
        self.assertNotIn(redact.REDACTED, result)

    def test_file_paths_not_redacted(self):
        # Paths with / should not be redacted
        text = "/usr/local/bin/something"
        result = redact._redact_high_entropy(text)
        self.assertNotIn(redact.REDACTED, result)

    def test_already_redacted_not_double_redacted(self):
        text = f"key={redact.REDACTED}"
        result = redact._redact_high_entropy(text)
        self.assertEqual(result, text)


# ---------------------------------------------------------------------------
# Language detection: SKIP_DIRS + Makefile
# ---------------------------------------------------------------------------
class TestLanguageDetectionEnhancements(unittest.TestCase):
    """Expanded SKIP_DIRS and Makefile downgrade."""

    def test_skip_dirs_includes_tool_caches(self):
        for d in [".mypy_cache", ".ruff_cache", ".gradle", ".idea", ".vscode",
                  ".eslintcache", ".pytest_cache", ".nyc_output", "eggs", ".eggs"]:
            self.assertIn(d, detect_languages.SKIP_DIRS, f"{d} should be in SKIP_DIRS")

    def test_makefile_not_in_manifest_map(self):
        # Makefile should NOT be in MANIFEST_MAP (downgraded from strong signal)
        self.assertNotIn("Makefile", detect_languages.MANIFEST_MAP)

    def test_cmake_still_strong_signal(self):
        self.assertEqual(detect_languages.MANIFEST_MAP.get("CMakeLists.txt"), "c_cpp")


# ---------------------------------------------------------------------------
# CI/CD integration
# ---------------------------------------------------------------------------
class TestCIExitCode(unittest.TestCase):
    """CI exit code computation based on gate threshold."""

    def test_gate_none_always_zero(self):
        self.assertEqual(run_scan._ci_exit_code({"critical": 5}, "none"), 0)

    def test_gate_critical_with_critical_findings(self):
        self.assertEqual(run_scan._ci_exit_code({"critical": 1}, "critical"), 4)

    def test_gate_critical_without_critical(self):
        self.assertEqual(run_scan._ci_exit_code({"high": 5}, "critical"), 0)

    def test_gate_high_with_high(self):
        self.assertEqual(run_scan._ci_exit_code({"high": 1}, "high"), 3)

    def test_gate_high_with_critical(self):
        self.assertEqual(run_scan._ci_exit_code({"critical": 1}, "high"), 4)

    def test_gate_medium_with_medium(self):
        self.assertEqual(run_scan._ci_exit_code({"medium": 1}, "medium"), 2)

    def test_gate_low_with_any(self):
        self.assertEqual(run_scan._ci_exit_code({"low": 1}, "low"), 1)

    def test_gate_low_with_info(self):
        self.assertEqual(run_scan._ci_exit_code({"info": 1}, "low"), 1)

    def test_no_findings_returns_zero(self):
        self.assertEqual(run_scan._ci_exit_code({}, "critical"), 0)


class TestGithubAnnotations(unittest.TestCase):
    """GitHub Actions annotation file generation."""

    def test_writes_annotation_file(self):
        with tempfile.TemporaryDirectory() as d:
            findings = [
                {"severity": "high", "tool": "semgrep", "rule": "B608",
                 "file": "app.py", "line": 42, "message": "SQL injection"},
            ]
            path = run_scan._write_github_annotations(findings, d)
            self.assertTrue(os.path.exists(path))
            content = open(path).read()
            self.assertIn("::error", content)
            self.assertIn("file=app.py", content)
            self.assertIn("line=42", content)

    def test_low_severity_uses_warning(self):
        with tempfile.TemporaryDirectory() as d:
            findings = [
                {"severity": "low", "tool": "bandit", "rule": "B101",
                 "file": "test.py", "line": 1, "message": "assert used"},
            ]
            path = run_scan._write_github_annotations(findings, d)
            content = open(path).read()
            self.assertIn("::warning", content)

    def test_info_severity_uses_notice(self):
        with tempfile.TemporaryDirectory() as d:
            findings = [
                {"severity": "info", "tool": "semgrep", "rule": "X001",
                 "file": "x.py", "line": 1, "message": "info"},
            ]
            path = run_scan._write_github_annotations(findings, d)
            content = open(path).read()
            self.assertIn("::notice", content)


# ---------------------------------------------------------------------------
# Parallelism: sequential mode
# ---------------------------------------------------------------------------
class TestRunConcurrentlySequential(unittest.TestCase):
    """_run_concurrently sequential mode."""

    def test_sequential_runs_all_tasks(self):
        results = []
        tasks = [
            ("a", lambda: [{"tool": "a", "command": "a", "returncode": 0}]),
            ("b", lambda: [{"tool": "b", "command": "b", "returncode": 0}]),
        ]
        result = run_scan._run_concurrently(tasks, sequential=True)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["tool"], "a")
        self.assertEqual(result[1]["tool"], "b")

    def test_sequential_handles_exception(self):
        def bad():
            raise RuntimeError("boom")
        tasks = [("bad", bad)]
        result = run_scan._run_concurrently(tasks, sequential=True)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["returncode"], -3)
        self.assertIn("boom", result[0]["log_tail"])

    def test_empty_tasks(self):
        self.assertEqual(run_scan._run_concurrently([], sequential=True), [])


# ---------------------------------------------------------------------------
# Incremental scanning helpers
# ---------------------------------------------------------------------------
class TestIncrementalHelpers(unittest.TestCase):
    """File hash cache and SHA256 helpers."""

    def test_sha256_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("hello world")
            f.flush()
            h = run_scan._sha256_file(f.name)
            self.assertIsNotNone(h)
            self.assertEqual(len(h), 64)  # SHA256 hex digest length
            os.unlink(f.name)

    def test_sha256_file_nonexistent(self):
        self.assertIsNone(run_scan._sha256_file("/nonexistent/path"))

    def test_file_hash_cache_path_deterministic(self):
        p1 = run_scan._file_hash_cache_path("/project/a")
        p2 = run_scan._file_hash_cache_path("/project/a")
        self.assertEqual(p1, p2)

    def test_file_hash_cache_path_different_projects(self):
        p1 = run_scan._file_hash_cache_path("/project/a")
        p2 = run_scan._file_hash_cache_path("/project/b")
        self.assertNotEqual(p1, p2)

    def test_save_and_load_hash_cache(self):
        with tempfile.TemporaryDirectory() as d:
            # Override the cache path to use temp dir
            cache = {"file.py": "abc123"}
            manifest = {"last_full_scan": "2024-01-01T00:00:00Z"}
            run_scan._save_file_hash_cache(d, cache, manifest)
            loaded_cache, loaded_manifest = run_scan._load_file_hash_cache(d)
            self.assertEqual(loaded_cache, cache)
            self.assertEqual(loaded_manifest, manifest)


# ---------------------------------------------------------------------------
# Cross-tool finding correlation
# ---------------------------------------------------------------------------
class TestCrossToolCorrelation(unittest.TestCase):
    """_merge_confirmation and _proximity_match."""

    def test_merge_confirmation_adds_tool(self):
        deduped = [{"tool": "semgrep", "rule": "B608", "file": "a.py", "line": 10}]
        f = {"tool": "bandit", "rule": "B608", "file": "a.py", "line": 10}
        generate_report._merge_confirmation(deduped, f)
        self.assertIn("bandit", deduped[0].get("confirmed_by", []))

    def test_merge_confirmation_no_duplicate(self):
        deduped = [{"tool": "semgrep", "confirmed_by": ["bandit"]}]
        f = {"tool": "bandit"}
        generate_report._merge_confirmation(deduped, f)
        self.assertEqual(deduped[0]["confirmed_by"].count("bandit"), 1)

    def test_merge_confirmation_same_tool_not_added(self):
        deduped = [{"tool": "semgrep"}]
        f = {"tool": "semgrep"}
        generate_report._merge_confirmation(deduped, f)
        self.assertNotIn("semgrep", deduped[0].get("confirmed_by", []))

    def test_merge_confirmation_empty_deduped(self):
        # Should not raise
        generate_report._merge_confirmation([], {"tool": "x"})

    def test_proximity_match_within_window(self):
        deduped = [{"file": "a.py", "line": 10}]
        proximity = [("a.py", 10, "CWE-89", 0)]
        f = {"file": "a.py", "line": 13, "cwe": "CWE-89"}
        self.assertTrue(generate_report._proximity_match(deduped, proximity, f))

    def test_proximity_match_outside_window(self):
        proximity = [("a.py", 10, "CWE-89", 0)]
        f = {"file": "a.py", "line": 20, "cwe": "CWE-89"}
        self.assertFalse(generate_report._proximity_match([], proximity, f))

    def test_proximity_match_different_file(self):
        proximity = [("a.py", 10, "CWE-89", 0)]
        f = {"file": "b.py", "line": 10, "cwe": "CWE-89"}
        self.assertFalse(generate_report._proximity_match([], proximity, f))

    def test_proximity_match_different_cwe(self):
        proximity = [("a.py", 10, "CWE-89", 0)]
        f = {"file": "a.py", "line": 10, "cwe": "CWE-79"}
        self.assertFalse(generate_report._proximity_match([], proximity, f))

    def test_proximity_match_non_numeric_line(self):
        proximity = [("a.py", 10, "CWE-89", 0)]
        f = {"file": "a.py", "line": "?", "cwe": "CWE-89"}
        self.assertFalse(generate_report._proximity_match([], proximity, f))


# ---------------------------------------------------------------------------
# HTML/JSON report
# ---------------------------------------------------------------------------
class TestHtmlReport(unittest.TestCase):
    """render_html_report output."""

    def test_html_report_contains_doctype(self):
        report = generate_report.render_html_report("/tmp", [], [], {"target": "/test"})
        self.assertIn("<!DOCTYPE html>", report)

    def test_html_report_contains_target(self):
        report = generate_report.render_html_report("/tmp", [], [], {"target": "/myproject"})
        self.assertIn("/myproject", report)

    def test_html_report_with_findings(self):
        findings = [
            {"severity": "high", "tool": "semgrep", "rule": "B608",
             "file": "a.py", "line": 10, "message": "SQL injection"},
        ]
        report = generate_report.render_html_report("/tmp", findings, [], {"target": "/test"})
        self.assertIn("SQL injection", report)
        self.assertIn("HIGH", report)

    def test_html_report_escapes_html(self):
        findings = [
            {"severity": "low", "tool": "x", "rule": "y",
             "file": "a.py", "line": 1, "message": "<script>alert(1)</script>"},
        ]
        report = generate_report.render_html_report("/tmp", findings, [], {"target": "/test"})
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)


class TestJsonReport(unittest.TestCase):
    """render_json_report output."""

    def test_json_report_valid_json(self):
        report = generate_report.render_json_report("/tmp", [], [], {"target": "/test"})
        data = json.loads(report)
        self.assertIn("target", data)
        self.assertIn("findings", data)

    def test_json_report_with_findings(self):
        findings = [
            {"severity": "critical", "tool": "semgrep", "rule": "X",
             "file": "a.py", "line": 1, "message": "test"},
        ]
        report = generate_report.render_json_report("/tmp", findings, [], {"target": "/test"})
        data = json.loads(report)
        self.assertEqual(data["summary"]["total"], 1)
        self.assertEqual(data["summary"]["critical"], 1)


# ---------------------------------------------------------------------------
# Triage prompt
# ---------------------------------------------------------------------------
class TestTriagePrompt(unittest.TestCase):
    """generate_triage_prompt output."""

    def test_prompt_contains_findings(self):
        findings = [
            {"severity": "high", "tool": "semgrep", "rule": "B608",
             "file": "a.py", "line": 10, "message": "SQL injection"},
        ]
        prompt = generate_report.generate_triage_prompt(findings)
        self.assertIn("SQL injection", prompt)
        self.assertIn("semgrep", prompt)
        self.assertIn("B608", prompt)

    def test_prompt_shows_confirmed_by(self):
        findings = [
            {"severity": "high", "tool": "semgrep", "rule": "B608",
             "file": "a.py", "line": 10, "message": "test",
             "confirmed_by": ["bandit"]},
        ]
        prompt = generate_report.generate_triage_prompt(findings)
        self.assertIn("confirmed by: bandit", prompt)

    def test_prompt_empty_findings(self):
        prompt = generate_report.generate_triage_prompt([])
        self.assertIn("Findings:", prompt)


# ---------------------------------------------------------------------------
# Trend tracking
# ---------------------------------------------------------------------------
class TestTrendTracking(unittest.TestCase):
    """save_trend_entry, load_trend_history, render_trend_section."""

    def test_save_and_load_trend(self):
        import time
        with tempfile.TemporaryDirectory() as d:
            unique_target = f"/test/project_{int(time.time() * 1000)}"
            manifest = {"target": unique_target, "timestamp": "2024-01-01T00:00:00Z"}
            # Create a scan manifest so load_trend_history can find the target
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "scan_manifest.json"), "w") as f:
                json.dump(manifest, f)
            findings = [{"severity": "high"}]
            generate_report.save_trend_entry(d, findings, manifest)
            history = generate_report.load_trend_history(d)
            self.assertGreaterEqual(len(history), 1)
            self.assertEqual(history[-1]["total"], 1)

    def test_render_trend_section_empty(self):
        result = generate_report.render_trend_section([], [])
        self.assertEqual(result, "")

    def test_render_trend_section_with_history(self):
        history = [
            {"timestamp": "2024-01-01T00:00:00Z", "total": 5,
             "by_severity": {"high": 3, "low": 2}},
        ]
        current = [{"severity": "high"}, {"severity": "medium"}]
        result = generate_report.render_trend_section(history, current)
        self.assertIn("Scan Trend", result)
        self.assertIn("2024-01-01", result)
        self.assertIn("Current", result)


# ---------------------------------------------------------------------------
# Plugin architecture
# ---------------------------------------------------------------------------
class TestPluginArchitecture(unittest.TestCase):
    """ToolPlugin base class and registry."""

    def test_tool_plugin_base_class(self):
        plugin = run_scan.ToolPlugin()
        self.assertEqual(plugin.name, "")
        self.assertEqual(plugin.languages, set())

    def test_tool_plugin_subclass(self):
        class TestPlugin(run_scan.ToolPlugin):
            name = "test-plugin"
            languages = {"python"}
            def check_available(self, detect_info):
                return True
            def build_thunk(self, target, out_dir, detect_info):
                return lambda: [{"tool": "test-plugin", "command": "", "returncode": 0}]

        p = TestPlugin()
        self.assertEqual(p.name, "test-plugin")
        self.assertTrue(p.check_available({}))

    def test_register_and_get_plugin(self):
        class TempPlugin(run_scan.ToolPlugin):
            name = "temp-test-plugin"
            languages = {"python"}
            def check_available(self, detect_info):
                return True
            def build_thunk(self, target, out_dir, detect_info):
                return lambda: []

        run_scan.register_plugin(TempPlugin())
        plugins = run_scan.get_plugins()
        self.assertIn("temp-test-plugin", plugins)
        # Cleanup
        del run_scan._PLUGIN_REGISTRY["temp-test-plugin"]


if __name__ == "__main__":
    unittest.main()
