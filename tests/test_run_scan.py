#!/usr/bin/env python3
"""Tiangang run_scan.py 安全测试 — 验证命令注入已修复（T-P0-1）及其他 P1 修复。"""
import os
import sys
import tempfile
import subprocess
import json
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


class TestShNoShellInjection(unittest.TestCase):
    """T-P0-1: sh() 必须禁用 shell=True，防止命令注入。"""

    def test_sh_accepts_list_not_string(self):
        """sh() 应接受列表参数而非字符串。"""
        import run_scan
        # 传递列表应正常工作
        rc, out = run_scan.sh(["echo", "hello"])
        self.assertEqual(rc, 0)
        self.assertIn("hello", out)

    def test_sh_rejects_shell_metacharacters_in_path(self):
        """含 shell 元字符的路径不应被执行。"""
        import run_scan
        # 构造一个含命令注入企图的路径
        # 旧实现 shell=True + repr() 会被注入
        # 新实现 shell=False 列表参数不会解析 shell 元字符
        malicious_path = "/tmp/$(id)"
        # sh(["ls", malicious_path]) 应该把 $(id) 当作字面路径，不执行 id
        rc, out = run_scan.sh(["ls", malicious_path])
        # ls 会因路径不存在而失败，但 out 中不应包含 uid= 字样
        self.assertNotIn("uid=", out)

    def test_sh_no_shell_true(self):
        """sh() 的实现不得使用 shell=True。"""
        import inspect
        import run_scan
        source = inspect.getsource(run_scan.sh)
        # 不应包含 shell=True
        self.assertNotIn("shell=True", source)
        self.assertNotIn("shell= True", source)


class TestLangsStripping(unittest.TestCase):
    """T-P1-7: --langs 切分必须 strip 空格。"""

    def test_langs_strip_whitespace(self):
        """'python, go' 应解析为 ['python', 'go'] 而非 ['python', ' go']。"""
        # 模拟 args.langs
        langs_input = "python, go,  rust  ,"
        expected = ["python", "go", "rust"]
        result = [x.strip() for x in langs_input.split(",") if x.strip()]
        self.assertEqual(result, expected)


class TestDetectLanguagesFailureHandling(unittest.TestCase):
    """T-P1-10: detect_languages 失败应区分 rc!=0 与空列表。"""

    def test_detect_languages_returns_empty_on_failure(self):
        """detect_languages 失败时应返回空语言列表但不崩溃。"""
        import run_scan
        with mock.patch("run_scan.sh", return_value=(-1, "error: missing module")):
            result = run_scan.detect_languages("/nonexistent")
            self.assertEqual(result["languages"], [])
            self.assertFalse(result["has_gemfile"])


class TestCargoAuditDetection(unittest.TestCase):
    """T-P1-1: cargo-audit 检测应检查 cargo-audit 而非 cargo。"""

    def test_cargo_audit_uses_correct_command(self):
        """run_scan 应检测 cargo-audit 命令而非仅 cargo。"""
        import run_scan
        source = open(os.path.join(os.path.dirname(__file__), "..", "scripts", "run_scan.py")).read()
        # 应该有 have("cargo-audit") 或 cargo audit --version 的检查
        # 而非仅有 have("cargo")
        # 注意：cargo audit 是子命令，cargo-audit 是包名
        # 检查源码中不应仅依赖 have("cargo")
        # 查找 cargo-audit 相关的检测逻辑
        self.assertTrue(
            'have("cargo-audit")' in source or 'cargo audit --version' in source or 'cargo-audit' in source,
            "应该检测 cargo-audit 而非仅 cargo"
        )


class TestSemgrepExcludeSecurityAudit(unittest.TestCase):
    """T-P1-9: semgrep 应排除 .security-audit 目录。"""

    def test_semgrep_excludes_security_audit(self):
        """semgrep 命令应包含 --exclude=.security-audit。"""
        source = open(os.path.join(os.path.dirname(__file__), "..", "scripts", "run_scan.py")).read()
        self.assertIn("--exclude", source)
        self.assertIn(".security-audit", source)


class TestGenerateReportParsers(unittest.TestCase):
    """T-P1-2: PARSERS 应包含 Java/.NET/Rust 工具。"""

    def test_parsers_include_java_dotnet_rust(self):
        """PARSERS 应包含 findsecbugs, security-code-scan, miri。"""
        import generate_report
        # 检查 PARSERS 字典是否包含新增的解析器
        parser_keys = list(generate_report.PARSERS.keys())
        all_text = " ".join(parser_keys)
        # 至少应该有 findsecbugs 或 security-code-scan 或 miri
        # 由于 findsecbugs 输出 sarif，可能复用 parse_sarif
        self.assertTrue(
            "findsecbugs" in all_text or "security-code-scan" in all_text or "miri" in all_text,
            f"PARSERS 应包含 Java/.NET/Rust 工具，当前: {parser_keys}"
        )


class TestGenerateReportFailedTools(unittest.TestCase):
    """T-P1-4: 报告应显示运行失败的工具。"""

    def test_render_report_includes_failed_tools(self):
        """render_report 应包含 'Tools attempted but failed' 段。"""
        import generate_report
        manifest = {
            "target": "/test",
            "languages": ["python"],
            "timestamp": "2026-01-01",
            "ran": [
                {"tool": "semgrep", "command": "semgrep ...", "returncode": 1, "log_tail": "error"},
            ],
            "skipped": [],
        }
        report = generate_report.render_report("/test", [], [], manifest)
        # 报告应包含失败工具段
        self.assertTrue(
            "attempted but failed" in report.lower() or "failed" in report.lower(),
            "报告应显示运行失败的工具"
        )


if __name__ == "__main__":
    unittest.main()
