#!/usr/bin/env python3
"""Tiangang fix-bugs 变更的单元测试。

覆盖 6 个隐性 bug 的修复验证（B1-B6）。每个测试验证有意义的属性
（returncode、log_tail 内容、排序顺序、shell 源码结构），而非仅
"函数有返回值"。测试通过 import scripts/ 下的模块来访问被测代码。
"""
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

TIANGANG_ROOT = os.path.join(os.path.dirname(__file__), "..")


class TestRunToolOutputWriteFailure(unittest.TestCase):
    """B1: run_tool 中 output_file 写入失败不应被静默吞掉。

    修复前 except Exception: pass 使 returncode=0 但输出文件未生成，
    generate_report.py:212 因文件不存在跳过解析，安全发现被丢弃。
    """

    def test_output_write_failure_recorded_in_ran(self):
        """output_file 写入失败时，ran 条目应记录非零 rc 和写入失败信息。"""
        import run_scan
        ran = []
        # mock open 抛 OSError，模拟磁盘满/权限错误
        with mock.patch("builtins.open", side_effect=OSError("disk full")):
            run_scan.run_tool(
                "test-tool", ran, ["echo", "hello"],
                output_file="/tmp/should-not-be-written",
            )
        self.assertEqual(len(ran), 1, "ran 应记录一次调用")
        # 关键属性：returncode 不应为 0（写入失败必须显性化）
        self.assertNotEqual(ran[0]["returncode"], 0,
                            "output_file 写入失败时 returncode 不应为 0")
        # 关键属性：log_tail 应包含写入失败信息
        self.assertIn("output write failed", ran[0]["log_tail"].lower(),
                      "log_tail 应包含 'output write failed' 标记")


class TestAgentRulesMissingFileWarning(unittest.TestCase):
    """B2: --agent-rules 指向不存在文件时应输出 stderr warning。

    修复前 if agent_rules and os.path.exists(agent_rules): 无 else 分支，
    用户显式请求被静默忽略，误以为 agent 规则已应用。
    """

    def test_missing_agent_rules_file_warns(self):
        """agent_rules 文件不存在时，stderr 应输出 warning。"""
        import run_scan
        ran = []
        # mock sh 让 semgrep 第一次（--config auto）就成功，避免 fallback 干扰
        with mock.patch("run_scan.sh", return_value=(0, "scan complete")), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as fake_stderr:
            run_scan._run_semgrep("/target", "/tmp/out", ran,
                                  agent_rules="/nonexistent/rules.yml")
            stderr_content = fake_stderr.getvalue()
        # 关键属性：stderr 应包含 warning 和文件未找到的提示
        self.assertIn("warning", stderr_content.lower(),
                      "stderr 应包含 'warning' 关键词")
        self.assertIn("--agent-rules file not found", stderr_content,
                      "stderr 应明确告知 agent 规则文件未找到")


class TestHasRubyCodeSkipDirsConsistency(unittest.TestCase):
    """B3: _has_ruby_code 的 SKIP_DIRS 应与 detect_languages.py 完全一致。

    修复前 _has_ruby_code 用内联元组 ("node_modules", "vendor", "target",
    "build", "dist")，缺失 __pycache__/venv/.venv/.tox/bin/obj 等，
    导致缓存/虚拟环境目录中的 .rb 文件误触发 brakeman。
    """

    def test_skips_pycache_dir(self):
        """__pycache__ 中的 .rb 文件不应触发 brakeman。

        修复前 __pycache__ 不以 . 开头且不在内联元组中，会被扫描。
        """
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "__pycache__"))
            with open(os.path.join(d, "__pycache__", "cached.rb"), "w") as f:
                f.write("class Cached; end")
            # 关键属性：__pycache__ 应被跳过，与 detect_languages.SKIP_DIRS 一致
            self.assertFalse(run_scan._has_ruby_code(d),
                             "__pycache__ 中的 .rb 不应触发 _has_ruby_code")

    def test_skips_venv_dir(self):
        """venv 目录中的 .rb 文件不应触发 brakeman。

        修复前 venv 不在内联元组中，会被扫描。
        """
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "venv", "lib"))
            with open(os.path.join(d, "venv", "lib", "lib.rb"), "w") as f:
                f.write("class Lib; end")
            # 关键属性：venv 应被跳过，与 detect_languages.SKIP_DIRS 一致
            self.assertFalse(run_scan._has_ruby_code(d),
                             "venv 中的 .rb 不应触发 _has_ruby_code")

    def test_imports_skip_dirs_from_detect_languages(self):
        """run_scan 应从 detect_languages 导入 SKIP_DIRS，消除两处定义。"""
        import detect_languages
        import run_scan
        # 关键属性：run_scan 模块应引用 detect_languages.SKIP_DIRS（同一对象）
        self.assertTrue(
            hasattr(run_scan, "SKIP_DIRS"),
            "run_scan 应从 detect_languages 导入 SKIP_DIRS"
        )
        # 应是同一对象，而非复制
        self.assertIs(run_scan.SKIP_DIRS, detect_languages.SKIP_DIRS,
                      "run_scan.SKIP_DIRS 应与 detect_languages.SKIP_DIRS 是同一对象")

    def test_legit_ruby_still_detected(self):
        """合法 Ruby 代码（非缓存/venv 目录）仍应被检测到——回归保护。"""
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "app"))
            with open(os.path.join(d, "app", "controller.rb"), "w") as f:
                f.write("class Controller; end")
            self.assertTrue(run_scan._has_ruby_code(d),
                            "app/controller.rb 应触发 _has_ruby_code")


class TestSemgrepFallbackPreservesFirstError(unittest.TestCase):
    """B4: semgrep fallback 时原始错误必须保留在 log_tail 中。

    修复前 out 和 semgrep_cmd 被 reassign，原始 --config auto 失败详情
    从 manifest 丢失，调试离线环境问题时无法看到网络错误细节。
    """

    def test_first_attempt_error_in_log_tail(self):
        """fallback 触发时，ran[-1]['log_tail'] 应同时包含原始错误和 fallback 输出。"""
        import run_scan
        ran = []
        # 第一次 sh 返回网络错误（触发 fallback），第二次返回成功
        first_out = "network error: cannot reach registry.semgrep.com"
        second_out = "scan complete"
        with mock.patch("run_scan.sh",
                        side_effect=[(1, first_out), (0, second_out)]), \
             mock.patch("sys.stderr", new_callable=io.StringIO):
            run_scan._run_semgrep("/target", "/tmp/out", ran)
        self.assertEqual(len(ran), 1, "ran 应只有一条 semgrep 条目（不分裂为两条）")
        # 关键属性：log_tail 应同时含原始错误和 fallback 输出
        self.assertIn("network error", ran[0]["log_tail"],
                      "原始网络错误应保留在 log_tail 中")
        self.assertIn("scan complete", ran[0]["log_tail"],
                      "fallback 输出应在 log_tail 中")
        # 应有结构化标记区分两次尝试
        self.assertIn("[first attempt", ran[0]["log_tail"].lower(),
                      "log_tail 应有 [first attempt ...] 标记")
        self.assertIn("[fallback", ran[0]["log_tail"].lower(),
                      "log_tail 应有 [fallback ...] 标记")

    def test_command_field_records_both_attempts(self):
        """ran[-1]['command'] 应同时记录两次命令。"""
        import run_scan
        ran = []
        with mock.patch("run_scan.sh",
                        side_effect=[(1, "network timeout"), (0, "ok")]), \
             mock.patch("sys.stderr", new_callable=io.StringIO):
            run_scan._run_semgrep("/target", "/tmp/out", ran)
        cmd = ran[0]["command"]
        # 关键属性：command 字段应同时含 first 和 fallback 标记
        self.assertIn("first:", cmd,
                      "command 应记录 first attempt 命令")
        self.assertIn("fallback:", cmd,
                      "command 应记录 fallback 命令")
        # 应包含 --config auto（首次）和 p/security-audit（fallback）
        self.assertIn("--config auto", cmd,
                      "first 命令应包含 --config auto")
        self.assertIn("p/security-audit", cmd,
                      "fallback 命令应包含 p/security-audit")

    def test_no_fallback_keeps_single_output(self):
        """非 fallback 路径（rc==0 一次成功）行为不变，log_tail 仅含单次输出。"""
        import run_scan
        ran = []
        with mock.patch("run_scan.sh", return_value=(0, "scan complete")), \
             mock.patch("sys.stderr", new_callable=io.StringIO):
            run_scan._run_semgrep("/target", "/tmp/out", ran)
        self.assertEqual(len(ran), 1)
        # 关键属性：非 fallback 时 log_tail 不应含 [first attempt]/[fallback] 标记
        self.assertNotIn("[first attempt", ran[0]["log_tail"].lower(),
                         "非 fallback 路径不应有 [first attempt] 标记")
        self.assertNotIn("[fallback", ran[0]["log_tail"].lower(),
                         "非 fallback 路径不应有 [fallback] 标记")
        self.assertEqual(ran[0]["log_tail"], "scan complete")


class TestFindingsNumericLineSort(unittest.TestCase):
    """B5: findings_sorted 必须按数字行号排序，而非字符串字典序。

    修复前 str(f["line"]) 使 "1"/"10"/"2" 排成 "1" → "10" → "2"，
    报告可读性差且掩盖真实顺序。
    """

    def _render_with_findings(self, findings):
        """辅助：用给定 findings 渲染报告，返回报告文本。"""
        import generate_report
        manifest = {
            "target": "/test", "languages": ["python"], "timestamp": "2026-01-01",
            "ran": [], "skipped": [],
        }
        return generate_report.render_report("/test", findings, [], manifest)

    def test_lines_sorted_numerically(self):
        """同文件中行号 1/10/2 的三个 finding，报告中顺序应为 1 → 2 → 10。"""
        import generate_report
        findings = [
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": "10", "message": "m10"},
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": "1", "message": "m1"},
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": "2", "message": "m2"},
        ]
        report = self._render_with_findings(findings)
        # 提取 f.py:<line> 出现的顺序
        order = []
        for line in report.splitlines():
            # finding 行格式: - **[tool:rule]** `f.py:line` — msg
            if "`f.py:" in line:
                # 抽取 `f.py:N` 中的 N
                seg = line.split("`f.py:")[1].split("`")[0]
                order.append(seg)
        # 关键属性：顺序应为 1 → 2 → 10（非 1 → 10 → 2）
        self.assertEqual(order, ["1", "2", "10"],
                         f"行号应按数字升序排列，实际顺序: {order}")

    def test_question_mark_line_sorts_last(self):
        """line='?' 的 finding 应排在所有数字行号之后。"""
        findings = [
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": "?", "message": "m?"},
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": "100", "message": "m100"},
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": "1", "message": "m1"},
        ]
        report = self._render_with_findings(findings)
        order = []
        for line in report.splitlines():
            if "`f.py:" in line:
                seg = line.split("`f.py:")[1].split("`")[0]
                order.append(seg)
        # 关键属性：数字在前（1 → 100），"?" 在最后
        self.assertEqual(order, ["1", "100", "?"],
                         f"'?' 应排在数字行号之后，实际顺序: {order}")

    def test_int_line_sorted_numerically(self):
        """line 为 int 类型时也应按数值排序（generate_report line 字段可能为 int 或 str）。"""
        findings = [
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": 10, "message": "m10"},
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": 1, "message": "m1"},
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": 2, "message": "m2"},
        ]
        report = self._render_with_findings(findings)
        order = []
        for line in report.splitlines():
            if "`f.py:" in line:
                seg = line.split("`f.py:")[1].split("`")[0]
                order.append(seg)
        # 关键属性：int 行号也按数值升序
        self.assertEqual(order, ["1", "2", "10"],
                         f"int 行号应按数值升序，实际顺序: {order}")

    def test_severity_priority_unchanged(self):
        """行号排序仅是第三级键，severity/file 优先级不变。"""
        findings = [
            {"tool": "bandit", "rule": "r1", "severity": "low",
             "file": "f.py", "line": "1", "message": "MSG_LOW_LINE_1"},
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": "10", "message": "MSG_HIGH_LINE_10"},
            {"tool": "bandit", "rule": "r1", "severity": "high",
             "file": "f.py", "line": "1", "message": "MSG_HIGH_LINE_1"},
        ]
        report = self._render_with_findings(findings)
        # 提取 finding 行中 message 出现的顺序（而非用 find 命中 Summary 表格）
        finding_order = []
        for line in report.splitlines():
            if "MSG_" in line:
                for msg in ("MSG_LOW_LINE_1", "MSG_HIGH_LINE_10", "MSG_HIGH_LINE_1"):
                    if msg in line:
                        finding_order.append(msg)
                        break
        # 关键属性：两个 high（行号 1 → 10）应在 low（行号 1）之前，
        # 验证 severity 是第一级排序键，行号只是第三级
        self.assertEqual(finding_order,
                         ["MSG_HIGH_LINE_1", "MSG_HIGH_LINE_10", "MSG_LOW_LINE_1"],
                         f"severity 应优先于行号，实际顺序: {finding_order}")


class TestInstallToolsMktempUsage(unittest.TestCase):
    """B6: install_tools.sh 应使用 mktemp 创建不可预测的日志路径。

    修复前 `/tmp/install_${name// /_}.log` 是可预测路径，存在符号链接
    攻击风险（攻击者预创建符号链接指向系统文件，脚本以 root 运行时
    覆盖该文件）。安全工具自身的安全姿态必须修复。
    """

    def setUp(self):
        with open(os.path.join(TIANGANG_ROOT, "scripts", "install_tools.sh")) as f:
            self.source = f.read()

    def test_uses_mktemp_for_logs(self):
        """check_or_install 应使用 mktemp 创建日志文件路径。"""
        # 关键属性：源码应包含 mktemp 调用
        self.assertIn("mktemp", self.source,
                      "install_tools.sh 应使用 mktemp 创建日志路径")
        # 关键属性：mktemp 模板应包含 XXXXXX（至少 6 个 X，mktemp 要求）
        self.assertIn("XXXXXX", self.source,
                      "mktemp 模板应包含至少 6 个 X")
        # 关键属性：不再有硬编码的重定向到固定 /tmp/install_*.log 路径
        # (即 `>/tmp/install_${name// /_}.log` 这种不带 XXXXXX 的模式)
        self.assertNotIn(">/tmp/install_${name// /_}.log", self.source,
                         "不应再硬编码重定向到固定 /tmp/install_*.log 路径")

    def test_log_path_passed_to_failure_message(self):
        """FAILED 提示行应引用 $logfile 变量，而非硬编码 /tmp 路径。"""
        # 关键属性：FAILED 行应引用 $logfile 变量
        self.assertIn("FAILED", self.source)
        # 应有 "see $logfile" 这样的引用
        self.assertIn("see $logfile", self.source,
                      "FAILED 提示应引用 $logfile 变量而非硬编码路径")
        # 不应再有 "see /tmp/install_${name// /_}.log" 这样的硬编码
        self.assertNotIn("see /tmp/install_${name// /_}.log", self.source,
                         "FAILED 提示不应硬编码 /tmp/install_*.log 路径")

    def test_logfile_declared_as_local(self):
        """logfile 应在 check_or_install 内声明为 local 变量。"""
        # 关键属性：应有 `local logfile` 声明
        self.assertIn("local logfile", self.source,
                      "logfile 应在 check_or_install 内声明为 local")

    def test_redirection_uses_quoted_logfile_var(self):
        """重定向应使用引用的 $logfile 变量（>"$logfile"），防注入。"""
        # 关键属性：重定向应使用 "$logfile"（带引号，防 word splitting）
        self.assertIn('>"$logfile"', self.source,
                      '重定向应使用 >"$logfile"（带引号）防 word splitting')


if __name__ == "__main__":
    unittest.main()
