#!/usr/bin/env python3
"""Tiangang P2 修复的单元测试。

覆盖 13 个 P2 bug 的修复验证。每个测试验证有意义的属性（值、结构、副作用），
而非仅"函数有返回值"。测试通过 import scripts/ 下的模块来访问被测代码。
"""
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

TIANGANG_ROOT = os.path.join(os.path.dirname(__file__), "..")


class TestCppcheckSeverityMapping(unittest.TestCase):
    """P2-1: cppcheck severity 应按 error→HIGH, warning→MEDIUM, style/performance→LOW 映射。"""

    def test_norm_severity_maps_cppcheck_styles_to_low(self):
        """style/performance/portability 应映射为 low，而非 unknown 或 high。"""
        import generate_report
        self.assertEqual(generate_report.norm_severity("error"), "high")
        self.assertEqual(generate_report.norm_severity("warning"), "medium")
        self.assertEqual(generate_report.norm_severity("style"), "low")
        self.assertEqual(generate_report.norm_severity("performance"), "low")
        self.assertEqual(generate_report.norm_severity("portability"), "low")

    def test_parse_cppcheck_preserves_severity_distinction(self):
        """parse_cppcheck 应保留 error/warning/style 的区分，不全部标 HIGH。"""
        import generate_report
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <errors>
    <error id="nullPointer" severity="error" msg="Null pointer dereference">
      <location file="src/a.c" line="10"/>
    </error>
    <error id="unusedVariable" severity="style" msg="Unused variable">
      <location file="src/b.c" line="20"/>
    </error>
    <error id="redundantAssignment" severity="performance" msg="Redundant">
      <location file="src/c.c" line="30"/>
    </error>
  </errors>
</results>"""
        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
            f.write(xml)
            path = f.name
        try:
            findings, err = generate_report.parse_cppcheck(path)
            self.assertIsNone(err)
            by_msg = {f["message"]: f["severity"] for f in findings}
            # error→high，不能是 low
            self.assertEqual(by_msg["Null pointer dereference"], "high")
            # style→low，不能是 high（这是修复前的 bug）
            self.assertEqual(by_msg["Unused variable"], "low")
            # performance→low
            self.assertEqual(by_msg["Redundant"], "low")
        finally:
            os.unlink(path)


class TestCargoAuditSeverity(unittest.TestCase):
    """P2-2: cargo-audit 无 severity 字段时应默认 MEDIUM，不应夸大为 HIGH。"""

    def test_missing_severity_defaults_to_medium(self):
        """无 severity 字段的 RUSTSEC 漏洞应为 medium，而非 high。"""
        import generate_report
        data = {
            "vulnerabilities": {
                "list": [
                    {"advisory": {"id": "RUSTSEC-001", "title": "no severity field"},
                     "package": {"name": "foo", "version": "1.0"}}
                ]
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_cargo_audit(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            # 关键属性：无 severity 时为 medium，不是 high
            self.assertEqual(findings[0]["severity"], "medium")
        finally:
            os.unlink(path)

    def test_explicit_high_severity_preserved(self):
        """有 severity=High 字段时应正确映射为 high。"""
        import generate_report
        data = {
            "vulnerabilities": {
                "list": [
                    {"advisory": {"id": "RUSTSEC-002", "severity": "High", "title": "high sev"},
                     "package": {"name": "bar", "version": "2.0"}}
                ]
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_cargo_audit(path)
            self.assertEqual(findings[0]["severity"], "high")
        finally:
            os.unlink(path)


class TestRunToolNoSkippedParam(unittest.TestCase):
    """P2-3: run_tool 函数不应再有 skipped 死参。"""

    def test_run_tool_signature_has_no_skipped(self):
        """run_tool 签名不得包含 skipped 参数。"""
        import run_scan
        sig = inspect.signature(run_scan.run_tool)
        self.assertNotIn("skipped", sig.parameters,
                         "run_tool 不应再有 skipped 死参")

    def test_run_tool_signature_has_required_params(self):
        """run_tool 应保留 name/ran/cmd 参数。"""
        import run_scan
        sig = inspect.signature(run_scan.run_tool)
        self.assertIn("name", sig.parameters)
        self.assertIn("ran", sig.parameters)
        self.assertIn("cmd", sig.parameters)


class TestCrossToolDedup(unittest.TestCase):
    """P2-4: collect_findings 应按 file:line:rule 跨工具去重。"""

    def test_dedup_keeps_one_for_same_file_line_rule(self):
        """两个工具报同一 file:line:rule 应只保留一个。"""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            # semgrep 和 bandit 都报同一个 SQL 注入
            semgrep_sarif = {
                "runs": [{
                    "tool": {"driver": {"rules": [{"id": "sql-injection"}]}},
                    "results": [{
                        "ruleId": "sql-injection",
                        "level": "error",
                        "message": {"text": "SQL injection"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "db.py"},
                            "region": {"startLine": 42}}}]}]
                }]
            }
            with open(os.path.join(d, "semgrep.sarif"), "w") as f:
                json.dump(semgrep_sarif, f)
            bandit_json = {
                "results": [{
                    "test_id": "sql-injection",
                    "issue_severity": "HIGH",
                    "filename": "db.py",
                    "line_number": 42,
                    "issue_text": "SQL injection (bandit)"
                }]
            }
            with open(os.path.join(d, "bandit.json"), "w") as f:
                json.dump(bandit_json, f)
            findings, _ = generate_report.collect_findings(d)
            # 同一 file:line:rule 只保留一个
            self.assertEqual(len(findings), 1, f"应去重为 1 条，实际 {len(findings)}: {findings}")

    def test_dedup_preserves_different_lines(self):
        """不同 file:line 的发现应全部保留。"""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            semgrep_sarif = {
                "runs": [{
                    "tool": {"driver": {"rules": [{"id": "r1"}]}},
                    "results": [
                        {"ruleId": "r1", "level": "error",
                         "message": {"text": "a"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "f.py"},
                             "region": {"startLine": 1}}}]},
                        {"ruleId": "r1", "level": "error",
                         "message": {"text": "b"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "f.py"},
                             "region": {"startLine": 2}}}]}
                    ]
                }]
            }
            with open(os.path.join(d, "semgrep.sarif"), "w") as f:
                json.dump(semgrep_sarif, f)
            findings, _ = generate_report.collect_findings(d)
            self.assertEqual(len(findings), 2, "不同行号的发现不应被去重")


class TestSarifRuleIndexSafety(unittest.TestCase):
    """P2-5: parse_sarif 应安全处理 ruleIndex 越界，不抛 KeyError/IndexError。"""

    def test_out_of_range_rule_index_does_not_crash(self):
        """ruleIndex 越界时应回退到 unknown-rule，不抛异常。"""
        import generate_report
        sarif = {
            "runs": [{
                "tool": {"driver": {"rules": [{"id": "r0"}]}},
                "results": [{
                    "ruleIndex": 999,  # 越界
                    "level": "error",
                    "message": {"text": "x"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "f.py"},
                        "region": {"startLine": 1}}}]
                }]
            }]
        }
        with tempfile.NamedTemporaryFile(suffix=".sarif", mode="w", delete=False) as f:
            json.dump(sarif, f)
            path = f.name
        try:
            findings, err = generate_report.parse_sarif(path, "test")
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "unknown-rule")
        finally:
            os.unlink(path)

    def test_valid_rule_index_resolves_id(self):
        """ruleIndex 在范围内时应正确解析为对应 rule id。"""
        import generate_report
        sarif = {
            "runs": [{
                "tool": {"driver": {"rules": [{"id": "first"}, {"id": "second"}]}},
                "results": [{
                    "ruleIndex": 1,  # 指向 rules[1] = "second"
                    "level": "note",
                    "message": {"text": "y"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "g.py"},
                        "region": {"startLine": 5}}}]
                }]
            }]
        }
        with tempfile.NamedTemporaryFile(suffix=".sarif", mode="w", delete=False) as f:
            json.dump(sarif, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_sarif(path, "test")
            self.assertEqual(findings[0]["rule"], "second")
        finally:
            os.unlink(path)


class TestLangsValidation(unittest.TestCase):
    """P2-7: run_scan.py 应有 SUPPORTED_LANGS 集合用于校验 --langs。"""

    def test_supported_langs_set_exists(self):
        """SUPPORTED_LANGS 应包含所有支持的语言。"""
        import run_scan
        self.assertTrue(hasattr(run_scan, "SUPPORTED_LANGS"))
        for lang in ("python", "go", "ruby", "rust", "java", "c_cpp", "php", "dotnet"):
            self.assertIn(lang, run_scan.SUPPORTED_LANGS,
                          f"{lang} 应在 SUPPORTED_LANGS 中")

    def test_unknown_lang_not_in_supported(self):
        """拼写错误的语言名不应在支持列表中。"""
        import run_scan
        self.assertNotIn("foo", run_scan.SUPPORTED_LANGS)
        self.assertNotIn("pyton", run_scan.SUPPORTED_LANGS)  # 拼写错误
        self.assertNotIn("rustt", run_scan.SUPPORTED_LANGS)


class TestToolCountDeclaration(unittest.TestCase):
    """P2-8: skill.json / README.md / README_EN.md 应声明 10 种语言专属扫描器。"""

    def test_skill_json_declares_10_scanners(self):
        with open(os.path.join(TIANGANG_ROOT, "skill.json")) as f:
            content = f.read()
        self.assertIn("10 种语言专属扫描器", content)
        self.assertNotIn("9 种语言专属扫描器", content)

    def test_readme_md_declares_10_scanners(self):
        with open(os.path.join(TIANGANG_ROOT, "README.md")) as f:
            content = f.read()
        self.assertIn("10 种语言专属扫描器", content)
        self.assertNotIn("9 种语言专属扫描器", content)

    def test_readme_en_declares_10_scanners(self):
        with open(os.path.join(TIANGANG_ROOT, "README_EN.md")) as f:
            content = f.read()
        self.assertIn("10 language-specific scanners", content)

    def test_actual_parser_count_matches(self):
        """PARSERS 字典中的语言专属工具数应与声明一致（10 个语言专属 + semgrep 通用）。"""
        import generate_report
        # PARSERS 包含 semgrep（通用）和 semgrep-agent（同源），其余为语言专属
        lang_specific = [k for k in generate_report.PARSERS
                         if not k.startswith("semgrep")]
        # 10 个语言专属：bandit, gosec, flawfinder, brakeman, psalm, findsecbugs,
        # cppcheck, cargo-audit, security-code-scan, miri
        self.assertEqual(len(lang_specific), 10,
                         f"应有 10 个语言专属解析器，实际 {len(lang_specific)}: {lang_specific}")


class TestGitignoreSecurityAudit(unittest.TestCase):
    """P2-9: .gitignore 应忽略 .security-audit 目录。"""

    def test_security_audit_ignored(self):
        with open(os.path.join(TIANGANG_ROOT, ".gitignore")) as f:
            content = f.read()
        self.assertIn(".security-audit", content)


class TestAgentSemgrepRulesNarrowed(unittest.TestCase):
    """P2-10: agent-semgrep-rules.md 的 Rule 2/3/4 应已缩小范围。"""

    def setUp(self):
        with open(os.path.join(TIANGANG_ROOT, "references", "agent-semgrep-rules.md")) as f:
            self.content = f.read()

    def test_rule_2_uses_metavariable_regex(self):
        """Rule 2 应使用 metavariable-regex 限制 $TEXT 为变量，排除字面字符串。"""
        # 不应再是简单的单行 pattern
        # 应包含 metavariable-regex 限制
        self.assertIn("metavariable-regex", self.content)
        self.assertIn("$TEXT", self.content)

    def test_rule_3_targets_specific_classes(self):
        """Rule 3 应针对 StateGraph/Crew/Flow 等具体类，而非整个 langgraph/crewai 包。"""
        # 应包含具体的类名
        self.assertIn("StateGraph", self.content)
        # YAML pattern 行不应再使用宽泛的 `from langgraph import ...`
        # (说明文字中引用旧模式作为对比是允许的，但 pattern: 行不能再用)
        self.assertNotIn("pattern: from langgraph import ...", self.content)
        self.assertNotIn("pattern: from crewai import ...", self.content)
        self.assertNotIn("pattern: import langgraph\n", self.content)
        self.assertNotIn("pattern: import crewai\n", self.content)

    def test_rule_4_filters_llm_calls(self):
        """Rule 4 应通过 metavariable-regex 过滤为 LLM/agent 调用，而非所有 try/except。"""
        # 应限制 $CALL 为 LLM/agent 相关
        self.assertIn("llm|agent|chain|model", self.content)

    def test_yaml_rules_file_in_sync_with_docs(self):
        """rules/agent-antipatterns.yml 应与文档同步，不再用宽泛的旧模式。"""
        yml_path = os.path.join(TIANGANG_ROOT, "rules", "agent-antipatterns.yml")
        if not os.path.exists(yml_path):
            self.skipTest("rules/agent-antipatterns.yml 不存在")
        with open(yml_path) as f:
            yml = f.read()
        # yml 文件也不应再用宽泛模式
        self.assertNotIn("pattern: from langgraph import ...", yml)
        self.assertNotIn("pattern: from crewai import ...", yml)
        # 应包含缩小后的具体类
        self.assertIn("StateGraph", yml)
        # Rule 4 应有 LLM 调用过滤
        self.assertIn("llm|agent|chain|model", yml)


class TestSkipDirsNoTestDir(unittest.TestCase):
    """P2-11: detect_languages.py 的 SKIP_DIRS 不应包含 test/tests。"""

    def test_skip_dirs_excludes_test_dirs(self):
        """test/tests 不应在 SKIP_DIRS 中（测试代码也应被扫描）。"""
        import detect_languages
        self.assertNotIn("test", detect_languages.SKIP_DIRS)
        self.assertNotIn("tests", detect_languages.SKIP_DIRS)

    def test_skip_dirs_keeps_ignored_dirs(self):
        """__pycache__/node_modules/.git 等仍应被忽略。"""
        import detect_languages
        for d in ("__pycache__", "node_modules", ".git", "venv"):
            self.assertIn(d, detect_languages.SKIP_DIRS)


class TestBrakemanRubyCheck(unittest.TestCase):
    """P2-12: run_scan 应在调用 brakeman 前检查是否有 Ruby 代码。"""

    def test_has_ruby_code_function_exists(self):
        """_has_ruby_code 辅助函数应存在。"""
        import run_scan
        self.assertTrue(hasattr(run_scan, "_has_ruby_code"))
        self.assertTrue(callable(run_scan._has_ruby_code))

    def test_no_ruby_returns_false(self):
        """无 .rb 文件和 Gemfile 时应返回 False。"""
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            # 创建一个纯 Python 文件
            with open(os.path.join(d, "main.py"), "w") as f:
                f.write("print('hello')")
            self.assertFalse(run_scan._has_ruby_code(d))

    def test_gemfile_returns_true(self):
        """有 Gemfile 时应返回 True。"""
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Gemfile"), "w") as f:
                f.write("source 'https://rubygems.org'")
            self.assertTrue(run_scan._has_ruby_code(d))

    def test_ruby_file_returns_true(self):
        """有 .rb 文件时应返回 True。"""
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "app"))
            with open(os.path.join(d, "app", "controller.rb"), "w") as f:
                f.write("class Controller; end")
            self.assertTrue(run_scan._has_ruby_code(d))


class TestDefusedXmlFallback(unittest.TestCase):
    """P2-6: defusedxml 不可用时应回退到标准库 xml.etree.ElementTree。"""

    def test_defusedxml_import_has_fallback(self):
        """generate_report 应有 try/except ImportError 回退逻辑。"""
        import generate_report
        # 模块应已成功导入（无论 defusedxml 是否安装）
        self.assertTrue(hasattr(generate_report, "ET"))
        # 验证回退逻辑存在于源码中
        source = inspect.getsource(generate_report)
        self.assertIn("defusedxml", source)
        self.assertIn("ImportError", source)


if __name__ == "__main__":
    unittest.main()
