#!/usr/bin/env python3
"""sarif_report.py 单元测试 — 覆盖率从 0% 提升到 95%+。

每个测试验证有意义的属性（值、结构、副作用、确定性），而非仅"函数有返回值"。
覆盖 9 个被测单元：_severity_to_level / _rule_id / _fingerprint / _location /
_result_from_finding / _build_rules / to_sarif / validate_sarif / main。
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import sarif_report  # noqa: E402


# ---------------------------------------------------------------------------
# 1. _severity_to_level
# ---------------------------------------------------------------------------
class TestSeverityToLevel(unittest.TestCase):
    """severity → SARIF level 映射；保守策略仅 critical/high 才升级 error。"""

    def test_critical_high_map_to_error(self):
        self.assertEqual(sarif_report._severity_to_level("critical"), "error")
        self.assertEqual(sarif_report._severity_to_level("high"), "error")

    def test_medium_maps_to_warning(self):
        self.assertEqual(sarif_report._severity_to_level("medium"), "warning")

    def test_low_info_map_to_note(self):
        self.assertEqual(sarif_report._severity_to_level("low"), "note")
        self.assertEqual(sarif_report._severity_to_level("info"), "note")

    def test_unknown_maps_to_none(self):
        self.assertEqual(sarif_report._severity_to_level("unknown"), "none")

    def test_none_severity_maps_to_none(self):
        # SARIF level 必须是 error|warning|note|none 之一；None 不能炸
        self.assertEqual(sarif_report._severity_to_level(None), "none")

    def test_empty_string_maps_to_none(self):
        # `if not severity` 命中空串短路
        self.assertEqual(sarif_report._severity_to_level(""), "none")

    def test_uppercase_normalized_via_lower(self):
        # "HIGH" 应通过 .lower() 走到 _LEVEL_MAP["high"]
        self.assertEqual(sarif_report._severity_to_level("HIGH"), "error")
        self.assertEqual(sarif_report._severity_to_level("Critical"), "error")

    def test_unknown_value_falls_through_to_none(self):
        # 不在映射表里的任意字符串 → "none"
        self.assertEqual(sarif_report._severity_to_level("weird"), "none")
        self.assertEqual(sarif_report._severity_to_level("BLOCKER"), "none")


# ---------------------------------------------------------------------------
# 2. _rule_id
# ---------------------------------------------------------------------------
class TestRuleId(unittest.TestCase):
    """ruleId 命名空间构造；空/None/空白规则回退到 unknown。"""

    def test_normal_input(self):
        self.assertEqual(sarif_report._rule_id("bandit", "B602"), "bandit/B602")

    def test_empty_string_rule(self):
        # 防止聚合时不同工具的空 rule 互相覆盖
        self.assertEqual(sarif_report._rule_id("gosec", ""), "gosec/unknown")

    def test_none_rule(self):
        self.assertEqual(sarif_report._rule_id("gosec", None), "gosec/unknown")

    def test_whitespace_only_rule(self):
        # strip() 后为空 → unknown
        self.assertEqual(sarif_report._rule_id("gosec", "   "), "gosec/unknown")

    def test_rule_with_surrounding_whitespace_is_stripped(self):
        # 真实场景：semgrep 偶尔带尾空格，应被 strip 掉再拼接
        self.assertEqual(sarif_report._rule_id("semgrep", "  SCS001  "), "semgrep/SCS001")


# ---------------------------------------------------------------------------
# 3. _fingerprint
# ---------------------------------------------------------------------------
class TestFingerprint(unittest.TestCase):
    """fingerprint 必须 deterministic、16 字符、对输入敏感。"""

    def test_deterministic_same_input_same_output(self):
        # 规则 5：确定性逻辑不能交给模型；同输入同输出是契约
        fp1 = sarif_report._fingerprint("src/a.py", "bandit/B602", 10)
        fp2 = sarif_report._fingerprint("src/a.py", "bandit/B602", 10)
        self.assertEqual(fp1, fp2)

    def test_different_input_different_output(self):
        fp1 = sarif_report._fingerprint("src/a.py", "bandit/B602", 10)
        fp2 = sarif_report._fingerprint("src/b.py", "bandit/B602", 10)
        fp3 = sarif_report._fingerprint("src/a.py", "bandit/B602", 11)
        self.assertNotEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)

    def test_length_is_16(self):
        # SARIF fingerprint 长度契约；切到 32 会破坏 GitHub Code Scanning 去重
        fp = sarif_report._fingerprint("x", "y", 1)
        self.assertEqual(len(fp), 16)

    def test_line_none_is_deterministic(self):
        # 找不到行号的 finding 也要能产生稳定 id
        fp = sarif_report._fingerprint("x.py", "rule", None)
        self.assertEqual(len(fp), 16)
        self.assertEqual(fp, sarif_report._fingerprint("x.py", "rule", None))


# ---------------------------------------------------------------------------
# 4. _location
# ---------------------------------------------------------------------------
class TestLocation(unittest.TestCase):
    """SARIF physicalLocation 构造；line 可能是 int/数字串/占位符。"""

    def test_int_line_becomes_region_startLine(self):
        loc = sarif_report._location("src/a.py", 10)
        self.assertEqual(loc["physicalLocation"]["artifactLocation"]["uri"], "src/a.py")
        self.assertEqual(loc["physicalLocation"]["region"]["startLine"], 10)

    def test_zero_line_clamped_to_one(self):
        # max(1, 0) → 1，避免 SARIF viewer 报 startLine=0 非法
        loc = sarif_report._location("x.py", 0)
        self.assertEqual(loc["physicalLocation"]["region"]["startLine"], 1)

    def test_negative_line_clamped_to_one(self):
        # 同上，防御性边界
        loc = sarif_report._location("x.py", -5)
        self.assertEqual(loc["physicalLocation"]["region"]["startLine"], 1)

    def test_numeric_string_line_parsed(self):
        # 数字字符串 "42" 应被解析为 int
        loc = sarif_report._location("x.py", "42")
        self.assertEqual(loc["physicalLocation"]["region"]["startLine"], 42)

    def test_question_mark_no_region(self):
        # 工具找不到行号时常用 "?" 占位；不应被当作数字
        loc = sarif_report._location("x.py", "?")
        self.assertNotIn("region", loc["physicalLocation"])

    def test_non_numeric_string_no_region(self):
        # 任意非数字字符串 → 无 region
        loc = sarif_report._location("x.py", "abc")
        self.assertNotIn("region", loc["physicalLocation"])

    def test_none_line_no_region(self):
        loc = sarif_report._location("x.py", None)
        self.assertNotIn("region", loc["physicalLocation"])

    def test_numeric_string_zero_clamped(self):
        # "0" 是数字串 → int 0 → max(1, 0) = 1
        loc = sarif_report._location("x.py", "0")
        self.assertEqual(loc["physicalLocation"]["region"]["startLine"], 1)


# ---------------------------------------------------------------------------
# 5. _result_from_finding
# ---------------------------------------------------------------------------
class TestResultFromFinding(unittest.TestCase):
    """finding dict → SARIF result；无 file 跳过、CWE/Fix 拼接、最小结果。"""

    def test_no_file_returns_none(self):
        # SARIF 要求 artifactLocation.uri；无 file 不能伪造
        self.assertIsNone(sarif_report._result_from_finding({"rule": "B602"}))
        self.assertIsNone(sarif_report._result_from_finding({"file": "", "rule": "B602"}))
        self.assertIsNone(sarif_report._result_from_finding({"file": None, "rule": "B602"}))

    def test_full_finding_stitches_cwe_and_fix_into_message(self):
        # message 应同时含 CWE 行和 Fix 行（viewer 可能不看 properties）
        f = {
            "tool": "bandit",
            "rule": "B602",
            "severity": "high",
            "file": "src/subprocess_call.py",
            "line": 42,
            "message": "subprocess call with shell=True",
            "cwe": "CWE-78",
            "cwe_url": "https://cwe.mitre.org/data/definitions/78.html",
            "fix": "Use shell=False and pass args as list",
        }
        res = sarif_report._result_from_finding(f)
        self.assertIsNotNone(res)
        msg = res["message"]["text"]
        self.assertIn("subprocess call with shell=True", msg)
        self.assertIn("CWE: CWE-78", msg)
        self.assertIn("https://cwe.mitre.org/data/definitions/78.html", msg)
        self.assertIn("Fix: Use shell=False and pass args as list", msg)
        # 多行结构：原始 message 在第一行，CWE/Fix 在后续行
        self.assertEqual(msg.split("\n")[0], "subprocess call with shell=True")

    def test_full_finding_emits_structured_properties(self):
        # 同时把 cwe/cweUrl 写入 properties，供读 properties 的工具用
        f = {
            "tool": "bandit",
            "rule": "B602",
            "severity": "high",
            "file": "a.py",
            "line": 1,
            "message": "msg",
            "cwe": "CWE-78",
            "cwe_url": "https://example.org/78",
            "fix": "fix text",
        }
        res = sarif_report._result_from_finding(f)
        self.assertEqual(res["properties"]["cwe"], "CWE-78")
        self.assertEqual(res["properties"]["cweUrl"], "https://example.org/78")
        self.assertEqual(res["properties"]["tool"], "bandit")
        self.assertEqual(res["properties"]["severity"], "high")

    def test_minimal_finding_only_file_and_rule(self):
        # 没有 cwe/cwe_url/fix/message → message 回退到 rule 字符串；properties 不含 cwe 键
        # 回退链：message → rule → rule_id（源码 line 122）
        f = {"tool": "gosec", "rule": "G104", "file": "main.go", "line": 5}
        res = sarif_report._result_from_finding(f)
        self.assertIsNotNone(res)
        self.assertEqual(res["ruleId"], "gosec/G104")
        # message 缺失 → 走 f.get("rule") = "G104"
        self.assertEqual(res["message"]["text"], "G104")
        self.assertNotIn("cwe", res["properties"])
        self.assertNotIn("cweUrl", res["properties"])

    def test_message_falls_back_to_rule_id_when_rule_missing(self):
        # rule 也缺失 → message 走 rule_id（tool/unknown 形态）
        f = {"tool": "gosec", "file": "main.go", "line": 5}
        res = sarif_report._result_from_finding(f)
        self.assertEqual(res["message"]["text"], "gosec/unknown")

    def test_level_and_fingerprint_populated(self):
        f = {"tool": "t", "rule": "r", "severity": "critical", "file": "x.py", "line": 1, "message": "m"}
        res = sarif_report._result_from_finding(f)
        self.assertEqual(res["level"], "error")
        self.assertIn("primary", res["fingerprints"])
        self.assertEqual(len(res["fingerprints"]["primary"]), 16)

    def test_message_falls_back_to_rule_when_message_missing(self):
        f = {"tool": "t", "rule": "R1", "file": "x.py", "line": 1}
        res = sarif_report._result_from_finding(f)
        # message 缺失 → 用 rule 字符串 "R1"
        self.assertEqual(res["message"]["text"], "R1")

    def test_fix_only_no_cwe(self):
        # 只有 fix 没有 cwe → message 只拼 Fix 行，不拼 CWE 行
        f = {"tool": "t", "rule": "r", "file": "x.py", "line": 1, "message": "m", "fix": "do X"}
        res = sarif_report._result_from_finding(f)
        msg = res["message"]["text"]
        self.assertIn("Fix: do X", msg)
        self.assertNotIn("CWE:", msg)


# ---------------------------------------------------------------------------
# 6. _build_rules
# ---------------------------------------------------------------------------
class TestBuildRules(unittest.TestCase):
    """rules 表去重、shortDescription 取 message 第一行、sorted 顺序。"""

    def test_distinct_ruleids_produce_distinct_entries(self):
        results = [
            {"ruleId": "bandit/B602", "message": {"text": "subprocess shell"}},
            {"ruleId": "gosec/G104", "message": {"text": "errors unhandled"}},
        ]
        rules = sarif_report._build_rules(results)
        ids = [r["id"] for r in rules]
        self.assertEqual(sorted(ids), ["bandit/B602", "gosec/G104"])
        # name 字段是 rule_id 去掉 tool 前缀
        names = {r["id"]: r["name"] for r in rules}
        self.assertEqual(names["bandit/B602"], "B602")
        self.assertEqual(names["gosec/G104"], "G104")

    def test_duplicate_ruleid_deduped_to_one_entry(self):
        # 同 ruleId 多次出现 → 仅一条规则
        results = [
            {"ruleId": "bandit/B602", "message": {"text": "first occurrence"}},
            {"ruleId": "bandit/B602", "message": {"text": "second occurrence"}},
        ]
        rules = sarif_report._build_rules(results)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "bandit/B602")
        # shortDescription 取首次出现的 message 第一行
        self.assertEqual(rules[0]["shortDescription"]["text"], "first occurrence")

    def test_short_description_takes_first_line_of_message(self):
        # 多行 message（含 CWE/Fix 拼接）→ shortDescription 只取首行
        results = [
            {
                "ruleId": "bandit/B602",
                "message": {"text": "main issue\nCWE: CWE-78\nFix: use shell=False"},
            }
        ]
        rules = sarif_report._build_rules(results)
        self.assertEqual(rules[0]["shortDescription"]["text"], "main issue")

    def test_empty_message_falls_back_to_ruleid(self):
        # message.text 为空 → desc or rid 走 rid 分支
        results = [{"ruleId": "t/r", "message": {"text": ""}}]
        rules = sarif_report._build_rules(results)
        self.assertEqual(rules[0]["shortDescription"]["text"], "t/r")

    def test_empty_results_returns_empty_rules(self):
        self.assertEqual(sarif_report._build_rules([]), [])

    def test_rules_sorted_by_id(self):
        results = [
            {"ruleId": "z/last", "message": {"text": "z"}},
            {"ruleId": "a/first", "message": {"text": "a"}},
            {"ruleId": "m/mid", "message": {"text": "m"}},
        ]
        rules = sarif_report._build_rules(results)
        ids = [r["id"] for r in rules]
        self.assertEqual(ids, ["a/first", "m/mid", "z/last"])


# ---------------------------------------------------------------------------
# 7. to_sarif
# ---------------------------------------------------------------------------
class TestToSarif(unittest.TestCase):
    """聚合 findings → SARIF 2.1.0 文档；无 file 跳过、结构完整。"""

    def test_empty_findings_produces_empty_results(self):
        doc = sarif_report.to_sarif([])
        self.assertEqual(doc["runs"][0]["results"], [])
        # rules 表也空
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"], [])

    def test_finding_without_file_is_skipped(self):
        # SARIF 不能表达无 file 的 finding；显式跳过（规则 12：失败必须显性化）
        findings = [
            {"tool": "t", "rule": "r1", "file": "a.py", "line": 1, "message": "m1"},
            {"tool": "t", "rule": "r2", "file": "", "line": 2, "message": "m2"},
            {"tool": "t", "rule": "r3", "line": 3, "message": "m3"},  # 无 file 键
        ]
        doc = sarif_report.to_sarif(findings)
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "t/r1")

    def test_all_valid_findings_become_results(self):
        findings = [
            {"tool": "bandit", "rule": "B602", "file": "a.py", "line": 1, "message": "m1", "severity": "high"},
            {"tool": "gosec", "rule": "G104", "file": "b.go", "line": 2, "message": "m2", "severity": "medium"},
        ]
        doc = sarif_report.to_sarif(findings)
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        rule_ids = {r["ruleId"] for r in results}
        self.assertEqual(rule_ids, {"bandit/B602", "gosec/G104"})

    def test_top_level_keys_present(self):
        doc = sarif_report.to_sarif([])
        self.assertEqual(doc["$schema"], sarif_report.SARIF_SCHEMA)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("runs", doc)
        self.assertEqual(len(doc["runs"]), 1)

    def test_tool_driver_metadata(self):
        doc = sarif_report.to_sarif([])
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "tiangang")
        self.assertEqual(driver["version"], sarif_report.TOOL_VERSION)
        self.assertEqual(driver["informationUri"], sarif_report.TOOL_INFO_URI)

    def test_rules_table_built_from_results(self):
        findings = [
            {"tool": "t", "rule": "r1", "file": "a.py", "line": 1, "message": "first"},
            {"tool": "t", "rule": "r1", "file": "b.py", "line": 2, "message": "second"},
            {"tool": "t", "rule": "r2", "file": "c.py", "line": 3, "message": "third"},
        ]
        doc = sarif_report.to_sarif(findings)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        self.assertEqual(ids, ["t/r1", "t/r2"])  # sorted, deduped


# ---------------------------------------------------------------------------
# 8. validate_sarif
# ---------------------------------------------------------------------------
class TestValidateSarif(unittest.TestCase):
    """结构性验证（无网络 schema fetch）；覆盖所有错误分支。"""

    def _valid_doc(self):
        """返回一份合法 SARIF 文档作为修改基底。"""
        return sarif_report.to_sarif([
            {"tool": "t", "rule": "r1", "file": "a.py", "line": 1, "message": "m", "severity": "high"}
        ])

    def test_valid_sarif_returns_true_no_errors(self):
        ok, errors = sarif_report.validate_sarif(self._valid_doc())
        self.assertTrue(ok)
        self.assertEqual(errors, [])

    def test_wrong_schema_returns_false(self):
        doc = self._valid_doc()
        doc["$schema"] = "https://wrong.example/sarif.json"
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("$schema" in e for e in errors))

    def test_wrong_version_returns_false(self):
        doc = self._valid_doc()
        doc["version"] = "2.0.0"
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("version" in e for e in errors))

    def test_runs_not_list_returns_false(self):
        doc = self._valid_doc()
        doc["runs"] = "not-a-list"
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("runs" in e for e in errors))

    def test_empty_runs_returns_false(self):
        doc = self._valid_doc()
        doc["runs"] = []
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("runs" in e for e in errors))

    def test_missing_tool_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0].pop("tool")
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("tool" in e for e in errors))

    def test_tool_not_dict_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["tool"] = "string"
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("tool" in e for e in errors))

    def test_missing_driver_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["tool"].pop("driver")
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("driver" in e for e in errors))

    def test_driver_name_missing_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["tool"]["driver"].pop("name")
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("driver" in e for e in errors))

    def test_result_ruleid_missing_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"][0].pop("ruleId")
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("ruleId" in e for e in errors))

    def test_result_ruleid_empty_string_returns_false(self):
        # `if not res.get("ruleId")` 命中空串
        doc = self._valid_doc()
        doc["runs"][0]["results"][0]["ruleId"] = ""
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("ruleId" in e for e in errors))

    def test_result_invalid_level_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"][0]["level"] = "blocker"
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("level" in e for e in errors))

    def test_result_message_missing_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"][0].pop("message")
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("message" in e for e in errors))

    def test_result_message_text_missing_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"][0]["message"]["text"] = ""
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("message" in e for e in errors))

    def test_result_locations_missing_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"][0].pop("locations")
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("locations" in e for e in errors))

    def test_result_locations_empty_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"][0]["locations"] = []
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("locations" in e for e in errors))

    def test_result_locations_not_list_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"][0]["locations"] = "not-a-list"
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("locations" in e for e in errors))

    def test_result_location_missing_uri_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].pop("uri")
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        self.assertTrue(any("artifactLocation" in e for e in errors))

    def test_results_not_list_returns_false(self):
        doc = self._valid_doc()
        doc["runs"][0]["results"] = "not-a-list"
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        # 该分支 continue，但仍要被记录
        self.assertTrue(any("results" in e for e in errors))

    def test_multiple_errors_all_reported(self):
        # 多个错误同时存在 → 错误列表应包含全部（不短路）
        doc = {
            "$schema": "wrong",
            "version": "wrong",
            "runs": [],
        }
        ok, errors = sarif_report.validate_sarif(doc)
        self.assertFalse(ok)
        # 至少 3 条：$schema / version / runs
        self.assertGreaterEqual(len(errors), 3)


# ---------------------------------------------------------------------------
# 9. main() — 用 mock sys.argv + mock collect_findings
# ---------------------------------------------------------------------------
class TestMain(unittest.TestCase):
    """main() CLI 行为；非目录、--output、--validate、skipped note。"""

    def _patch_argv(self, *args):
        return mock.patch.object(sys, "argv", ["sarif_report.py", *args])

    def test_non_directory_returns_1(self):
        # 防御：路径不存在/不是目录 → 退出码 1
        with self._patch_argv("/nonexistent/path/that/does/not/exist"):
            rc = sarif_report.main()
        self.assertEqual(rc, 1)

    def test_file_path_not_directory_returns_1(self):
        # 路径是文件不是目录 → 退出码 1
        with tempfile.NamedTemporaryFile() as tmp:
            with self._patch_argv(tmp.name):
                rc = sarif_report.main()
        self.assertEqual(rc, 1)

    def test_valid_dir_with_output_writes_file(self):
        # 正常目录 + --output → 写文件，rc=0
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.sarif")
            with self._patch_argv(tmpdir, "--output", out_path):
                with mock.patch(
                    "sarif_report.collect_findings",
                    return_value=([], []),
                ):
                    rc = sarif_report.main()
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out_path))
            with open(out_path) as f:
                doc = json.load(f)
            self.assertEqual(doc["version"], "2.1.0")

    def test_validate_flag_emits_ok_to_stderr(self):
        # --validate + 合法 SARIF → stderr 含 "OK"
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmpdir:
            with self._patch_argv(tmpdir, "--validate"):
                with mock.patch(
                    "sarif_report.collect_findings",
                    return_value=([], []),
                ):
                    buf = StringIO()
                    with mock.patch("sys.stderr", buf):
                        rc = sarif_report.main()
        self.assertEqual(rc, 0)
        self.assertIn("OK", buf.getvalue())

    def test_validate_failure_lists_errors_to_stderr(self):
        # --validate + validate_sarif 返回 False → stderr 含 FAILED + 每条错误
        # （覆盖 main 中 validate FAILED 分支，避免 happy-path-only 摸鱼测试）
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmpdir:
            with self._patch_argv(tmpdir, "--validate"):
                with mock.patch(
                    "sarif_report.collect_findings",
                    return_value=([], []),
                ):
                    with mock.patch(
                        "sarif_report.validate_sarif",
                        return_value=(False, ["fake error 1", "fake error 2"]),
                    ):
                        buf = StringIO()
                        with mock.patch("sys.stderr", buf):
                            rc = sarif_report.main()
        # main() 仍返回 0（验证失败不阻断写文件，只是 stderr 提示）
        self.assertEqual(rc, 0)
        text = buf.getvalue()
        self.assertIn("FAILED", text)
        self.assertIn("fake error 1", text)
        self.assertIn("fake error 2", text)
        self.assertIn("2 error(s)", text)

    def test_skipped_findings_emits_note_to_stderr(self):
        # findings 中有无 file 的 → 跳过数 > 0 → stderr 含 "skipped" 提示
        findings = [
            {"tool": "t", "rule": "r1", "file": "a.py", "line": 1, "message": "m"},
            {"tool": "t", "rule": "r2", "file": "", "line": 2, "message": "no file"},  # skipped
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            with self._patch_argv(tmpdir):
                with mock.patch(
                    "sarif_report.collect_findings",
                    return_value=(findings, []),
                ):
                    from io import StringIO
                    buf = StringIO()
                    with mock.patch("sys.stderr", buf):
                        rc = sarif_report.main()
        self.assertEqual(rc, 0)
        stderr_text = buf.getvalue()
        self.assertIn("skipped", stderr_text)
        # 1 个 finding 被跳过
        self.assertIn("1", stderr_text)

    def test_parse_errors_emitted_to_stderr(self):
        # collect_findings 返回 parse_errors → 应逐条打印到 stderr
        with tempfile.TemporaryDirectory() as tmpdir:
            with self._patch_argv(tmpdir):
                with mock.patch(
                    "sarif_report.collect_findings",
                    return_value=([], ["parse error A", "parse error B"]),
                ):
                    from io import StringIO
                    buf = StringIO()
                    with mock.patch("sys.stderr", buf):
                        rc = sarif_report.main()
        self.assertEqual(rc, 0)
        text = buf.getvalue()
        self.assertIn("parse error A", text)
        self.assertIn("parse error B", text)

    def test_no_output_flag_writes_to_stdout(self):
        # 无 --output → SARIF 写到 stdout（JSON 可解析）
        with tempfile.TemporaryDirectory() as tmpdir:
            with self._patch_argv(tmpdir):
                with mock.patch(
                    "sarif_report.collect_findings",
                    return_value=([], []),
                ):
                    from io import StringIO
                    out = StringIO()
                    with mock.patch("sys.stdout", out):
                        rc = sarif_report.main()
        self.assertEqual(rc, 0)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
