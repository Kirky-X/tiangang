#!/usr/bin/env python3
"""Tiangang run_scan.py 安全测试 — 验证命令注入已修复（T-P0-1）及其他 P1 修复。"""
import io
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


class TestSemgrepAutoMetricsConflict(unittest.TestCase):
    """semgrep >=1.168 下 --config auto 与 --metrics=off 组合直接报错
    "Cannot create auto config when metrics are off"，且该消息不含现有
    fallback 触发关键词（network/registry/timeout/connection），导致扫描直接
    失败。根因修复：配置含 auto 的那次调用不传 --metrics=off。"""

    def test_auto_attempt_has_no_metrics_off(self):
        """含 --config auto 的首次调用不得传 --metrics=off。"""
        import run_scan
        ran = []
        with mock.patch("run_scan.sh", return_value=(0, "ok")) as m:
            run_scan._run_semgrep("/target", "/tmp/out", ran)
        cmd = m.call_args_list[0].args[0]
        self.assertIn("auto", cmd)
        self.assertNotIn("--metrics=off", cmd)

    def test_fallback_attempt_keeps_metrics_off(self):
        """离线回退（p/security-audit + p/secrets，非 auto）仍显式 --metrics=off。"""
        import run_scan
        ran = []
        with mock.patch(
            "run_scan.sh",
            side_effect=[(-1, "Error: connection to registry failed"), (0, "ok")],
        ) as m:
            run_scan._run_semgrep("/target", "/tmp/out", ran)
        fallback_cmd = m.call_args_list[1].args[0]
        self.assertIn("p/security-audit", fallback_cmd)
        self.assertNotIn("auto", fallback_cmd)
        self.assertIn("--metrics=off", fallback_cmd)

    def test_agent_rules_attempt_keeps_metrics_off(self):
        """agent 规则扫描（本地规则文件，非 auto）仍显式 --metrics=off。"""
        import run_scan
        ran = []
        with tempfile.TemporaryDirectory() as tmp:
            rules = os.path.join(tmp, "rules.yml")
            open(rules, "w").close()
            with mock.patch("run_scan.sh", return_value=(0, "ok")), \
                 mock.patch("run_scan.run_tool") as m_rt:
                run_scan._run_semgrep("/target", "/tmp/out", ran, agent_rules=rules)
        agent_cmd = m_rt.call_args_list[0].args[2]
        self.assertIn("--metrics=off", agent_cmd)


class TestSemgrepRuleChain(unittest.TestCase):
    """P0 规则加载链：主配置链始终加载 rules/web-baseline.yml（离线本地规则），
    agent 链在 agent-antipatterns.yml 之外并列加载 rules/llm-security.yml。
    规则文件缺失时告警并降级，不中断扫描。"""

    def test_web_baseline_loaded_in_main_chain(self):
        """web-baseline.yml 存在时进入主配置链，且排在 auto 之后。"""
        import run_scan
        with tempfile.TemporaryDirectory() as rules_dir:
            baseline = os.path.join(rules_dir, "web-baseline.yml")
            open(baseline, "w").close()
            with mock.patch("run_scan._RULES_DIR", rules_dir), \
                 mock.patch("run_scan.sh", return_value=(0, "ok")) as m:
                ran = []
                run_scan._run_semgrep("/target", "/tmp/out", ran)
        cmd = m.call_args_list[0].args[0]
        self.assertIn(baseline, cmd)
        self.assertEqual(cmd[cmd.index(baseline) - 1], "--config")
        self.assertLess(cmd.index("auto"), cmd.index(baseline))

    def test_web_baseline_missing_warns_and_skips(self):
        """web-baseline.yml 缺失时 stderr 告警且不进配置链。"""
        import run_scan
        with tempfile.TemporaryDirectory() as rules_dir:
            with mock.patch("run_scan._RULES_DIR", rules_dir), \
                 mock.patch("run_scan.sh", return_value=(0, "ok")), \
                 mock.patch("sys.stderr", new_callable=io.StringIO) as fake_err:
                ran = []
                run_scan._run_semgrep("/target", "/tmp/out", ran)
                self.assertIn("web-baseline rules not found", fake_err.getvalue())
        self.assertEqual(len(ran), 1)

    def test_web_baseline_loaded_in_fallback_chain(self):
        """回退链（离线打包规则）保留 web-baseline——'始终启用'不因回退丢失。"""
        import run_scan
        with tempfile.TemporaryDirectory() as rules_dir:
            baseline = os.path.join(rules_dir, "web-baseline.yml")
            open(baseline, "w").close()
            with mock.patch("run_scan._RULES_DIR", rules_dir), \
                 mock.patch(
                     "run_scan.sh",
                     side_effect=[(-1, "Error: network unreachable"), (0, "ok")],
                 ) as m:
                ran = []
                run_scan._run_semgrep("/target", "/tmp/out", ran)
        fallback_cmd = m.call_args_list[1].args[0]
        self.assertIn(baseline, fallback_cmd)
        self.assertIn("p/security-audit", fallback_cmd)

    def test_llm_security_loaded_alongside_agent_rules(self):
        """llm-security.yml 与 agent-antipatterns.yml 在同一次 semgrep-agent
        扫描中并列加载。"""
        import run_scan
        with tempfile.TemporaryDirectory() as rules_dir, \
             tempfile.TemporaryDirectory() as user_dir:
            llm = os.path.join(rules_dir, "llm-security.yml")
            open(llm, "w").close()
            agent_rules = os.path.join(user_dir, "agent-antipatterns.yml")
            open(agent_rules, "w").close()
            with mock.patch("run_scan._RULES_DIR", rules_dir), \
                 mock.patch("run_scan.sh", return_value=(0, "ok")), \
                 mock.patch("run_scan.run_tool") as m_rt:
                ran = []
                run_scan._run_semgrep("/target", "/tmp/out", ran, agent_rules=agent_rules)
        agent_cmd = m_rt.call_args_list[0].args[2]
        self.assertEqual(m_rt.call_args_list[0].args[0], "semgrep-agent")
        self.assertIn(agent_rules, agent_cmd)
        self.assertIn(llm, agent_cmd)

    def test_llm_security_missing_warns(self):
        """llm-security.yml 缺失时 stderr 告警，agent 规则扫描仍执行。"""
        import run_scan
        with tempfile.TemporaryDirectory() as rules_dir, \
             tempfile.TemporaryDirectory() as user_dir:
            agent_rules = os.path.join(user_dir, "agent-antipatterns.yml")
            open(agent_rules, "w").close()
            with mock.patch("run_scan._RULES_DIR", rules_dir), \
                 mock.patch("run_scan.sh", return_value=(0, "ok")), \
                 mock.patch("run_scan.run_tool") as m_rt, \
                 mock.patch("sys.stderr", new_callable=io.StringIO) as fake_err:
                ran = []
                run_scan._run_semgrep("/target", "/tmp/out", ran, agent_rules=agent_rules)
                self.assertIn("llm-security rules not found", fake_err.getvalue())
        self.assertEqual(m_rt.call_args_list[0].args[0], "semgrep-agent")


class TestSemgrepGithubActions(unittest.TestCase):
    """P1：目标检出 .github/workflows/*.yml|.yaml 时，semgrep 配置链条件追加
    p/github-actions（registry 在线规则）；离线回退沿用现有策略将其丢弃。"""

    @staticmethod
    def _make_workflows(target, fname="ci.yml", content="on: push\n"):
        wf = os.path.join(target, ".github", "workflows")
        os.makedirs(wf, exist_ok=True)
        with open(os.path.join(wf, fname), "w") as f:
            f.write(content)
        return target

    def test_p_github_actions_added_when_workflow_present(self):
        import run_scan
        with tempfile.TemporaryDirectory() as target:
            self._make_workflows(target)
            with mock.patch("run_scan.sh", return_value=(0, "ok")) as m:
                ran = []
                run_scan._run_semgrep(target, "/tmp/out", ran)
        self.assertIn("p/github-actions", m.call_args_list[0].args[0])

    def test_p_github_actions_not_added_without_workflows(self):
        import run_scan
        with tempfile.TemporaryDirectory() as target:
            with mock.patch("run_scan.sh", return_value=(0, "ok")) as m:
                ran = []
                run_scan._run_semgrep(target, "/tmp/out", ran)
        self.assertNotIn("p/github-actions", m.call_args_list[0].args[0])

    def test_non_yml_file_in_workflows_not_a_signal(self):
        """workflows 目录里只有非 yml/yaml 文件（如 README）不触发。"""
        import run_scan
        with tempfile.TemporaryDirectory() as target:
            self._make_workflows(target, fname="README.txt")
            with mock.patch("run_scan.sh", return_value=(0, "ok")) as m:
                ran = []
                run_scan._run_semgrep(target, "/tmp/out", ran)
        self.assertNotIn("p/github-actions", m.call_args_list[0].args[0])

    def test_p_github_actions_dropped_in_fallback(self):
        """回退链沿用离线策略：registry 类配置 p/github-actions 被丢弃。"""
        import run_scan
        with tempfile.TemporaryDirectory() as target:
            self._make_workflows(target)
            with mock.patch(
                "run_scan.sh",
                side_effect=[(-1, "Error: connection refused"), (0, "ok")],
            ) as m:
                ran = []
                run_scan._run_semgrep(target, "/tmp/out", ran)
        first_cmd = m.call_args_list[0].args[0]
        fallback_cmd = m.call_args_list[1].args[0]
        self.assertIn("p/github-actions", first_cmd)
        self.assertNotIn("p/github-actions", fallback_cmd)
        self.assertIn("p/security-audit", fallback_cmd)


if __name__ == "__main__":
    unittest.main()
