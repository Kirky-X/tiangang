#!/usr/bin/env python3
"""Tiangang 吸收 fp-check（误报模式知识库）与 strix（多形态报告工件）机制的测试。

覆盖三块：
- references/false-positive-patterns.md 知识库存在且结构完整（10 类模式、
  识别特征 + 判定方法、拒绝合理化表、魔鬼代言人闸门）。
- --triage 提示词内置同一纪律：FP 判定须指认模式类别 + 证据行、
  拒绝合理化条目、true_positive 放行前的魔鬼代言人复核。
- --details 一漏洞一文件工件 + CSV 公式注入防护 + 反引号围栏防逃逸 +
  再生成确定性 + secret 不落盘；报告 Run metadata 小节的向后兼容。
"""
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import generate_report  # noqa: E402
import run_scan  # noqa: E402

FP_DOC = os.path.join(REPO_ROOT, "references", "false-positive-patterns.md")


def _finding(**overrides):
    base = {
        "severity": "high",
        "tool": "semgrep",
        "rule": "sql-injection",
        "file": "db.py",
        "line": "42",
        "message": "user input flows into SQL execute",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 上游 1：误报模式知识库文档
# ---------------------------------------------------------------------------
class TestFalsePositivePatternsDoc(unittest.TestCase):
    """知识库必须存在且覆盖承诺的模式类别与两道纪律。"""

    @classmethod
    def setUpClass(cls):
        cls.assertTrue(os.path.isfile(FP_DOC), FP_DOC)
        with open(FP_DOC, encoding="utf-8") as f:
            cls.text = f.read()

    def test_all_ten_pattern_classes_present(self):
        for marker in (
            "测试与夹具代码",
            "防御式编程",
            "不可达路径",
            "框架",
            "已消毒的数据流",
            "文档、示例与配置样例",
            "攻击者不可控的输入源",
            "整数边界数学上不可行",
            "无并发可能的竞态申报",
            "纵深防御层失效",
        ):
            self.assertIn(marker, self.text)

    def test_every_pattern_has_recognition_and_verdict_method(self):
        # 10 个「### N.」小节，每节必须同时给出识别特征与判定方法。
        sections = [
            s for s in self.text.split("\n### ") if s.strip() and s[0].isdigit()
        ]
        self.assertGreaterEqual(len(sections), 10)
        for s in sections:
            self.assertIn("识别特征", s, s[:40])
            self.assertIn("判定方法", s, s[:40])

    def test_rationalization_table_and_devils_advocate_gate_present(self):
        self.assertIn("拒绝合理化表", self.text)
        self.assertIn("魔鬼代言人复核", self.text)
        # 关键反方闸门语义：true_positive 放行前必须构造反方论证并记录。
        self.assertIn("true_positive", self.text)

    def test_uncertainty_maps_to_needs_validation_not_pass(self):
        self.assertIn("needs_validation", self.text)


# ---------------------------------------------------------------------------
# 上游 1：triage 提示词挂载同一纪律
# ---------------------------------------------------------------------------
class TestTriagePromptFPDiscipline(unittest.TestCase):
    """generate_triage_prompt 必须内置 FP 模式核对 + 拒绝合理化 + 反方闸门。"""

    def test_fp_discipline_requires_class_and_proof_line(self):
        prompt = generate_report.generate_triage_prompt([_finding()])
        self.assertIn("False-positive discipline", prompt)
        self.assertIn("Name the pattern class", prompt)
        self.assertIn("cite", prompt)
        # 指认不出类别 → needs_validation 而非误报放行。
        self.assertIn("needs_validation", prompt)

    def test_fp_class_list_matches_knowledge_base_one_to_one(self):
        # 结构性护栏：提示词的类别清单唯一手维护来源是
        # generate_report.FP_PATTERN_CLASSES，必须与知识库 `### N.` 小节
        # 一一对应（数量一致；SKILL.md 只是散文摘要，不参与断言）。
        with open(FP_DOC, encoding="utf-8") as f:
            doc_classes = re.findall(r"^### \d+\.\s*(.+?)\s*$", f.read(), re.M)
        self.assertEqual(len(doc_classes), 10)
        self.assertEqual(
            len(generate_report.FP_PATTERN_CLASSES), len(doc_classes)
        )

    def test_prompt_lists_every_canonical_class(self):
        # 提示词由常量拼装：常量里每个类别都要出现在提示词正文中
        # （按空白归一后匹配，容忍自动换行拆行）。
        prompt = generate_report.generate_triage_prompt([_finding()])
        flat = " ".join(prompt.split())
        for cls in generate_report.FP_PATTERN_CLASSES:
            self.assertIn(cls, flat)

    def test_rationalization_rejections_present(self):
        prompt = generate_report.generate_triage_prompt([_finding()])
        self.assertIn("Rationalizations to reject", prompt)
        self.assertIn("Probably a false positive, let it pass", prompt)
        self.assertIn("The rule flagged it, so it must be real", prompt)
        self.assertIn("The framework probably handles it", prompt)
        self.assertIn("This feels critical", prompt)

    def test_devils_advocate_gate_for_true_positive(self):
        prompt = generate_report.generate_triage_prompt([_finding()])
        self.assertIn("Devil's advocate gate", prompt)
        self.assertIn("strongest case", prompt)
        # 复核必须留痕：没记录的复核等于没做。
        self.assertIn("record in the reasoning", prompt)

    def test_three_state_verdict_intact(self):
        prompt = generate_report.generate_triage_prompt([_finding()])
        self.assertIn(
            '"verdict": "true_positive|false_positive|needs_validation"', prompt
        )


# ---------------------------------------------------------------------------
# 上游 2：一漏洞一文件详情工件
# ---------------------------------------------------------------------------
class TestFindingDetails(unittest.TestCase):
    """write_details：F-####.md + index.csv，确定性、防逃逸、secret 不落盘。"""

    def _write_results(self, d, findings, target=None):
        manifest = {"target": target}
        count, details_dir = generate_report.write_details(d, findings, manifest)
        return count, details_dir

    def test_one_file_per_finding_plus_index(self):
        with tempfile.TemporaryDirectory() as d:
            findings = [_finding(), _finding(file="a.py", line=7, severity="low")]
            count, details_dir = self._write_results(d, findings)
            self.assertEqual(count, 2)
            names = sorted(os.listdir(details_dir))
            self.assertEqual(names, ["F-0001.md", "F-0002.md", "index.csv"])
            with open(os.path.join(details_dir, "index.csv")) as f:
                header = f.readline().strip()
            self.assertEqual(
                header, "id,severity,tool,rule,file,line,cwe,detail_file"
            )

    def test_ids_follow_report_sort_order_and_are_stable(self):
        with tempfile.TemporaryDirectory() as d:
            findings = [
                _finding(file="z.py", severity="low"),
                _finding(file="a.py", severity="critical"),
            ]
            _, details_dir = self._write_results(d, findings)
            with open(os.path.join(details_dir, "F-0001.md")) as f:
                self.assertIn("[critical]", f.readline())
            # 再生成一次：内容逐字节一致（同一 results dir 稳定 ID 的前提）。
            with open(os.path.join(details_dir, "F-0001.md"), "rb") as f:
                before = hashlib.sha256(f.read()).hexdigest()
            generate_report.write_details(d, findings, {"target": None})
            with open(os.path.join(details_dir, "F-0001.md"), "rb") as f:
                after = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(before, after)

    def test_detail_carries_triage_pointer_and_cwe(self):
        with tempfile.TemporaryDirectory() as d:
            f = _finding(cwe="CWE-89", cwe_url="https://cwe.mitre.org/data/definitions/89.html")
            _, details_dir = self._write_results(d, [f])
            with open(os.path.join(details_dir, "F-0001.md")) as fh:
                text = fh.read()
            self.assertIn("references/false-positive-patterns.md", text)
            self.assertIn("CWE-89", text)
            self.assertIn("## Message", text)

    def test_csv_formula_guard(self):
        # CWE-1236：以 = + - @ 开头的单元格会被表格软件当公式执行。
        self.assertEqual(generate_report._csv_safe("=cmd|' /C'"), "'=cmd|' /C'")
        self.assertEqual(generate_report._csv_safe("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(generate_report._csv_safe("plain"), "plain")

    def test_index_csv_quotes_embedded_separators(self):
        # RFC 4180 quoting：值里的逗号/引号/换行必须留在单元格内，
        # 不得错位成额外列或额外行（手工 join 的回归点）。
        with tempfile.TemporaryDirectory() as d:
            f = _finding(rule='say "hi"', file="a,b.py", message="line1\nline2")
            _, details_dir = generate_report.write_details(
                d, [f], {"target": None}
            )
            with open(
                os.path.join(details_dir, "index.csv"),
                newline="",
                encoding="utf-8",
            ) as fh:
                rows = list(csv.reader(fh))
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            rows[0],
            ["id", "severity", "tool", "rule", "file", "line", "cwe", "detail_file"],
        )
        self.assertEqual(rows[1][3], 'say "hi"')
        self.assertEqual(rows[1][4], "a,b.py")

    def test_detail_files_written_as_utf8(self):
        # Windows locale（gbk/cp1252）下非 ASCII 内容不得崩溃或乱码：
        # detail md 与 index.csv 都按 utf-8 落盘。
        with tempfile.TemporaryDirectory() as d:
            f = _finding(message="用户输入流入 SQL 执行")
            _, details_dir = generate_report.write_details(
                d, [f], {"target": None}
            )
            with open(
                os.path.join(details_dir, "F-0001.md"), encoding="utf-8"
            ) as fh:
                self.assertIn("用户输入流入 SQL 执行", fh.read())

    def test_cwe_url_whitelisted_to_mitre_only(self):
        # detail 工件含扫描目标影响的字段：cwe_url 仅放行 cwe.mitre.org，
        # 其他来源不渲染为链接（markdown 链注注入面收敛）。
        with tempfile.TemporaryDirectory() as d:
            f = _finding(
                cwe="CWE-89",
                cwe_url="https://evil.example/definitions/89.html",
            )
            _, details_dir = generate_report.write_details(
                d, [f], {"target": None}
            )
            with open(os.path.join(details_dir, "F-0001.md")) as fh:
                text = fh.read()
        self.assertIn("- **CWE:** CWE-89\n", text)
        self.assertNotIn("](https://evil.example", text)

    def test_safe_fence_survives_backtick_content(self):
        # 代码片段可能自带 ``` 围栏——开栏必须不短于内容内最长反引号串
        # （CommonMark：围栏只被不短于开栏的反引号串闭合）。
        self.assertEqual(generate_report._safe_fence("no ticks"), "```")
        self.assertEqual(generate_report._safe_fence("a``b`c"), "```")
        self.assertEqual(
            generate_report._safe_fence("```py\nx\n```"), "````"
        )

    def test_snippet_secrets_redacted_on_disk(self):
        # 片段里出现的凭证必须先脱敏再落盘（P0 secret-on-disk 纪律）。
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as results:
            src = os.path.join(target, "creds.py")
            with open(src, "w") as f:
                f.write('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
            f = _finding(file="creds.py", line=1, message="hardcoded key")
            count, details_dir = generate_report.write_details(
                results, [f], {"target": target}
            )
            self.assertEqual(count, 1)
            with open(os.path.join(details_dir, "F-0001.md")) as fh:
                text = fh.read()
            self.assertIn("[REDACTED]", text)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)

    def test_main_details_flag_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bandit.json"), "w") as f:
                json.dump(
                    {
                        "results": [
                            {
                                "test_id": "B602",
                                "issue_severity": "HIGH",
                                "filename": "app.py",
                                "line_number": 3,
                                "issue_text": "shell=True",
                            }
                        ]
                    },
                    f,
                )
            proc = subprocess.run(
                [
                    sys.executable,
                    generate_report.__file__,
                    d,
                    "--details",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(
                os.path.isfile(os.path.join(d, "findings", "F-0001.md"))
            )
            self.assertTrue(os.path.isfile(os.path.join(d, "findings", "index.csv")))
            self.assertIn("Finding details written", proc.stdout)

    def test_main_without_details_writes_no_findings_dir(self):
        with tempfile.TemporaryDirectory() as d:
            proc = subprocess.run(
                [sys.executable, generate_report.__file__, d],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(os.path.exists(os.path.join(d, "findings")))


# ---------------------------------------------------------------------------
# 上游 2：run 元数据（版本/耗时）进 manifest 与报告
# ---------------------------------------------------------------------------
class TestRunMetadata(unittest.TestCase):
    """scan_manifest 的 tool_versions/duration_ms 及报告 Run metadata 小节。"""

    def test_run_tool_records_duration(self):
        ran = []
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="ok", stderr=""
            )
            run_scan.run_tool("t", ran, ["t"])
        self.assertIn("duration_ms", ran[0])
        self.assertIsInstance(ran[0]["duration_ms"], int)
        self.assertGreaterEqual(ran[0]["duration_ms"], 0)

    def test_run_tool_records_duration_on_timeout(self):
        ran = []
        with mock.patch("run_scan.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=[], timeout=5)
            run_scan.run_tool("t", ran, ["t"], timeout=5)
        self.assertIn("duration_ms", ran[0])

    def test_collect_versions_success_and_failure_explicit(self):
        with mock.patch.object(run_scan, "sh") as mock_sh:
            mock_sh.side_effect = [(0, "bandit 1.7.5\n"), (1, "traceback")]
            versions = run_scan._collect_tool_versions(["bandit", "gosec"])
        self.assertEqual(versions["bandit"], "bandit 1.7.5")
        # 失败是显式 null，不是缺键。
        self.assertIsNone(versions["gosec"])

    def test_collect_versions_cargo_audit_override(self):
        with mock.patch.object(run_scan, "sh") as mock_sh:
            mock_sh.return_value = (0, "cargo-audit 0.21.2\n")
            run_scan._collect_tool_versions(["cargo-audit"])
            cmd = mock_sh.call_args[0][0]
        self.assertEqual(cmd[:3], ["cargo", "audit", "--version"])

    def test_report_renders_run_metadata_when_present(self):
        manifest = {
            "target": "/t",
            "ran": [
                {"tool": "bandit", "returncode": 0, "duration_ms": 1234},
                {"tool": "semgrep", "returncode": 0, "duration_ms": 5600},
            ],
            "tool_versions": {"bandit": "1.7.5", "ocr": None},
        }
        report = generate_report.render_report("/r", [], [], manifest)
        self.assertIn("## Run metadata", report)
        self.assertIn("- **bandit**: 1.7.5", report)
        self.assertIn("(version unknown)", report)
        self.assertIn("| bandit | 0 | 1234 |", report)

    def test_report_omits_run_metadata_for_legacy_manifests(self):
        # 旧 manifest（无耗时/版本）渲染结果不变——向后兼容。
        report = generate_report.render_report(
            "/r", [], [], {"target": "/t", "ran": [{"tool": "b", "returncode": 0}]}
        )
        self.assertNotIn("## Run metadata", report)


if __name__ == "__main__":
    unittest.main()
