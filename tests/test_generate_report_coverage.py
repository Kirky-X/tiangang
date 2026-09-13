#!/usr/bin/env python3
"""generate_report.py 覆盖率补全测试。

目标：将 scripts/generate_report.py 的行覆盖率从 73% 提升到 95%+。
每个测试验证有意义的属性（值、结构、副作用），遵循"测试必须有，但不是目的"原则。
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


class TestCweFromIterable(unittest.TestCase):
    """_cwe_from_iterable 边界：None/字符串/非字符串/超范围/无匹配。"""

    def test_none_input_returns_none(self):
        import generate_report
        self.assertIsNone(generate_report._cwe_from_iterable(None))

    def test_empty_list_returns_none(self):
        import generate_report
        self.assertIsNone(generate_report._cwe_from_iterable([]))

    def test_string_input_parsed_correctly(self):
        """字符串输入（非 list）应被包装为单元素列表后解析。"""
        import generate_report
        self.assertEqual(generate_report._cwe_from_iterable("cwe-78"), "CWE-78")

    def test_non_string_elements_skipped(self):
        """list 含非字符串元素应被跳过，不抛异常。"""
        import generate_report
        result = generate_report._cwe_from_iterable([123, None, 4.5, "cwe-89"])
        self.assertEqual(result, "CWE-89")

    def test_cwe_number_out_of_range_returns_none(self):
        """CWE 数字 >2000 应返回 None（防垃圾数据）。"""
        import generate_report
        self.assertIsNone(generate_report._cwe_from_iterable(["cwe-99999"]))

    def test_no_cwe_pattern_returns_none(self):
        """无 CWE 模式的字符串应返回 None。"""
        import generate_report
        self.assertIsNone(generate_report._cwe_from_iterable(["no match here"]))

    def test_various_separators_parsed(self):
        """cwe-78 / cwe_89 / cwe/22 / cwe 5 都应被识别。"""
        import generate_report
        self.assertEqual(generate_report._cwe_from_iterable(["cwe-78"]), "CWE-78")
        self.assertEqual(generate_report._cwe_from_iterable(["CWE_89"]), "CWE-89")
        self.assertEqual(generate_report._cwe_from_iterable(["cwe/22"]), "CWE-22")
        self.assertEqual(generate_report._cwe_from_iterable(["cwe 5"]), "CWE-5")


class TestCweUrl(unittest.TestCase):
    """_cwe_url 边界：None/无数字/有效输入。"""

    def test_none_returns_none(self):
        import generate_report
        self.assertIsNone(generate_report._cwe_url(None))

    def test_empty_string_returns_none(self):
        import generate_report
        self.assertIsNone(generate_report._cwe_url(""))

    def test_no_digits_returns_none(self):
        import generate_report
        self.assertIsNone(generate_report._cwe_url("CWE-abc"))

    def test_valid_cwe_returns_url(self):
        import generate_report
        self.assertEqual(
            generate_report._cwe_url("CWE-78"),
            "https://cwe.mitre.org/data/definitions/78.html",
        )

    def test_large_cwe_number_returns_url(self):
        import generate_report
        self.assertEqual(
            generate_report._cwe_url("CWE-1234"),
            "https://cwe.mitre.org/data/definitions/1234.html",
        )


class TestFixFromSarifResult(unittest.TestCase):
    """_fix_from_sarif_result：fixes/rule_fix/都没有。"""

    def test_result_fixes_description_text_returned(self):
        """result 含 fixes[].description.text 时应返回 text。"""
        import generate_report
        result = {"fixes": [{"description": {"text": "Use parameterized queries"}}]}
        rule = {}
        self.assertEqual(
            generate_report._fix_from_sarif_result(result, rule),
            "Use parameterized queries",
        )

    def test_rule_properties_fix_fallback(self):
        """result 无 fixes，rule.properties.fix 应作为 fallback 返回。"""
        import generate_report
        result = {}
        rule = {"properties": {"fix": "  sanitize input  "}}
        self.assertEqual(
            generate_report._fix_from_sarif_result(result, rule),
            "sanitize input",
        )

    def test_neither_fixes_nor_rule_fix_returns_empty(self):
        """都没有时应返回空字符串。"""
        import generate_report
        self.assertEqual(generate_report._fix_from_sarif_result({}, {}), "")

    def test_fixes_without_text_falls_through_to_rule(self):
        """fixes 存在但 description 无 text 时应 fall through 到 rule。"""
        import generate_report
        result = {"fixes": [{"description": {}}]}
        rule = {"properties": {"fix": "rule fix"}}
        self.assertEqual(
            generate_report._fix_from_sarif_result(result, rule), "rule fix"
        )


class TestNormSeverityNone(unittest.TestCase):
    """norm_severity 的 None 分支。"""

    def test_none_returns_unknown(self):
        import generate_report
        self.assertEqual(generate_report.norm_severity(None), "unknown")


class TestParseSarifBranches(unittest.TestCase):
    """parse_sarif 错误分支 + cwe/fix 赋值。"""

    def test_corrupt_json_returns_error(self):
        """corrupt JSON 应返回 ([], "could not parse ...")。"""
        import generate_report
        with tempfile.NamedTemporaryFile(
            suffix=".sarif", mode="w", delete=False
        ) as f:
            f.write("{not valid json")
            path = f.name
        try:
            findings, err = generate_report.parse_sarif(path, "test")
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
            self.assertIn(path, err)
        finally:
            os.unlink(path)

    def test_finding_with_cwe_and_fix(self):
        """含 cwe + fix 的 finding 应同时携带 cwe/cwe_url/fix。

        注：parse_sarif 将 props.get("tags")（list）作为 tag_sources 的
        单元素 append，_cwe_from_iterable 不递归进嵌套 list，所以 tags 中的
        cwe 实际不会被提取。CWE 需通过 props["cwe"]（string）或 ruleId 传入。
        """
        import generate_report
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "sql-injection",
                                    "properties": {
                                        "tags": ["security", "cwe-89", "owasp-a1"],
                                        "cwe": "cwe-89",
                                    },
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection"},
                            "fixes": [
                                {"description": {"text": "Use parameterized queries"}}
                            ],
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "db.py"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        with tempfile.NamedTemporaryFile(
            suffix=".sarif", mode="w", delete=False
        ) as f:
            json.dump(sarif, f)
            path = f.name
        try:
            findings, err = generate_report.parse_sarif(path, "semgrep")
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f0 = findings[0]
            self.assertEqual(f0["cwe"], "CWE-89")
            self.assertEqual(
                f0["cwe_url"],
                "https://cwe.mitre.org/data/definitions/89.html",
            )
            self.assertEqual(f0["fix"], "Use parameterized queries")
        finally:
            os.unlink(path)


class TestParseBanditBranches(unittest.TestCase):
    """parse_bandit 错误分支 + cwe 赋值。"""

    def test_corrupt_json_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            f.write("{not valid json")
            path = f.name
        try:
            findings, err = generate_report.parse_bandit(path)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(path)

    def test_issue_cwe_extracted(self):
        """bandit issue_cwe 应被映射为 cwe/cwe_url。"""
        import generate_report
        data = {
            "results": [
                {
                    "test_id": "B608",
                    "issue_severity": "HIGH",
                    "filename": "db.py",
                    "line_number": 10,
                    "issue_text": "SQL injection",
                    "issue_cwe": {
                        "id": 89,
                        "link": "https://cwe.mitre.org/data/definitions/89.html",
                    },
                }
            ]
        }
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_bandit(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["cwe"], "CWE-89")
            self.assertEqual(
                findings[0]["cwe_url"],
                "https://cwe.mitre.org/data/definitions/89.html",
            )
        finally:
            os.unlink(path)

    def test_issue_cwe_without_link_uses_helper(self):
        """issue_cwe 无 link 时应用 _cwe_url 生成。"""
        import generate_report
        data = {
            "results": [
                {
                    "test_id": "B608",
                    "issue_severity": "MEDIUM",
                    "filename": "db.py",
                    "line_number": 10,
                    "issue_text": "SQL injection",
                    "issue_cwe": {"id": 89},
                }
            ]
        }
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_bandit(path)
            self.assertEqual(findings[0]["cwe"], "CWE-89")
            self.assertEqual(
                findings[0]["cwe_url"],
                "https://cwe.mitre.org/data/definitions/89.html",
            )
        finally:
            os.unlink(path)


class TestParseCppcheckError(unittest.TestCase):
    """parse_cppcheck 错误分支。"""

    def test_corrupt_xml_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(
            suffix=".xml", mode="w", delete=False
        ) as f:
            f.write("<not valid xml<<<")
            path = f.name
        try:
            findings, err = generate_report.parse_cppcheck(path)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(path)


class TestParseCargoAuditError(unittest.TestCase):
    """parse_cargo_audit 错误分支。"""

    def test_corrupt_json_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            f.write("{not valid json")
            path = f.name
        try:
            findings, err = generate_report.parse_cargo_audit(path)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(path)


class TestParseSecurityCodeScan(unittest.TestCase):
    """parse_security_code_scan 完整测试。"""

    def test_standard_json_array_parsed(self):
        """标准 JSON array 输入应正确解析。"""
        import generate_report
        data = [
            {
                "ruleId": "SCS001",
                "severity": "Warning",
                "message": "XSS vulnerability",
                "file": "Controllers/HomeController.cs",
                "line": 42,
            }
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_security_code_scan(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f0 = findings[0]
            self.assertEqual(f0["tool"], "security-code-scan")
            self.assertEqual(f0["rule"], "SCS001")
            self.assertEqual(f0["severity"], "medium")
            self.assertEqual(f0["file"], "Controllers/HomeController.cs")
            self.assertEqual(f0["line"], 42)
            self.assertEqual(f0["message"], "XSS vulnerability")
        finally:
            os.unlink(path)

    def test_dict_with_results_field_parsed(self):
        """dict 含 results 字段应正确解析。"""
        import generate_report
        data = {
            "results": [
                {
                    "ruleId": "SCS002",
                    "severity": "Error",
                    "message": "SQL injection",
                    "file": "Data/Context.cs",
                    "line": 100,
                }
            ]
        }
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_security_code_scan(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "SCS002")
            self.assertEqual(findings[0]["severity"], "high")
        finally:
            os.unlink(path)

    def test_corrupt_json_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            f.write("{not valid json")
            path = f.name
        try:
            findings, err = generate_report.parse_security_code_scan(path)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(path)

    def test_missing_fields_use_defaults(self):
        """缺失字段应使用默认值，不抛异常。"""
        import generate_report
        data = [{}]
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_security_code_scan(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f0 = findings[0]
            self.assertEqual(f0["rule"], "unknown")
            self.assertEqual(f0["severity"], "unknown")
            self.assertEqual(f0["file"], "unknown file")
            self.assertEqual(f0["line"], "?")
            self.assertEqual(f0["message"], "")
        finally:
            os.unlink(path)

    def test_rule_field_fallback(self):
        """无 ruleId 但有 rule 字段时应使用 rule。"""
        import generate_report
        data = [{"rule": "SCS003", "severity": "Error", "message": "x"}]
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_security_code_scan(path)
            self.assertEqual(findings[0]["rule"], "SCS003")
        finally:
            os.unlink(path)


class TestParseMiriLog(unittest.TestCase):
    """parse_miri_log 完整测试。"""

    def test_ub_with_location_parsed(self):
        """含 'error: Undefined Behavior' + ' at file:line:col' 的行应解析。"""
        import generate_report
        log = "error: Undefined Behavior: using uninitialized data at src/main.rs:42:15\n"
        with tempfile.NamedTemporaryFile(
            suffix=".log", mode="w", delete=False
        ) as f:
            f.write(log)
            path = f.name
        try:
            findings, err = generate_report.parse_miri_log(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f0 = findings[0]
            self.assertEqual(f0["tool"], "miri")
            self.assertEqual(f0["rule"], "undefined-behavior")
            self.assertEqual(f0["severity"], "high")
            self.assertEqual(f0["file"], "src/main.rs")
            self.assertEqual(f0["line"], "42")
            self.assertIn("using uninitialized data", f0["message"])
        finally:
            os.unlink(path)

    def test_ub_without_at_defaults(self):
        """不含 ' at ' 的 UB 行应使用 file='unknown file', line='?'。"""
        import generate_report
        log = "error: Undefined Behavior: something went wrong here\n"
        with tempfile.NamedTemporaryFile(
            suffix=".log", mode="w", delete=False
        ) as f:
            f.write(log)
            path = f.name
        try:
            findings, err = generate_report.parse_miri_log(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["file"], "unknown file")
            self.assertEqual(findings[0]["line"], "?")
        finally:
            os.unlink(path)

    def test_no_ub_lines_returns_empty(self):
        """无 'error: Undefined Behavior' 行时应返回空 findings。"""
        import generate_report
        log = "warning: unused variable\nsome other line\n"
        with tempfile.NamedTemporaryFile(
            suffix=".log", mode="w", delete=False
        ) as f:
            f.write(log)
            path = f.name
        try:
            findings, err = generate_report.parse_miri_log(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_io_error_returns_error(self):
        """文件不存在时应返回 ([], "could not parse ...")。"""
        import generate_report
        findings, err = generate_report.parse_miri_log("/nonexistent/miri.log")
        self.assertEqual(findings, [])
        self.assertIsNotNone(err)
        self.assertIn("could not parse", err)

    def test_multiple_ub_lines_all_parsed(self):
        """多行 UB 应全部解析。"""
        import generate_report
        log = (
            "error: Undefined Behavior: bug1 at src/a.rs:1:1\n"
            "some normal line\n"
            "error: Undefined Behavior: bug2 at src/b.rs:2:2\n"
        )
        with tempfile.NamedTemporaryFile(
            suffix=".log", mode="w", delete=False
        ) as f:
            f.write(log)
            path = f.name
        try:
            findings, _ = generate_report.parse_miri_log(path)
            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0]["file"], "src/a.rs")
            self.assertEqual(findings[1]["file"], "src/b.rs")
        finally:
            os.unlink(path)


class TestParseEslintSecurity(unittest.TestCase):
    """parse_eslint_security 完整测试。"""

    def test_only_security_rules_collected(self):
        """标准 eslint JSON 应只收 security/* 规则。"""
        import generate_report
        data = [
            {
                "filePath": "/abs/app.js",
                "messages": [
                    {
                        "ruleId": "security/detect-eval-with-expression",
                        "severity": 2,
                        "message": "eval detected",
                        "line": 42,
                    },
                    {
                        "ruleId": "no-unused-vars",
                        "severity": 1,
                        "message": "unused var",
                        "line": 10,
                    },
                ],
            }
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_eslint_security(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "security/detect-eval-with-expression")
            self.assertEqual(findings[0]["severity"], "high")
            self.assertEqual(findings[0]["file"], "/abs/app.js")
            self.assertEqual(findings[0]["line"], 42)
        finally:
            os.unlink(path)

    def test_severity_2_maps_to_high(self):
        import generate_report
        data = [
            {
                "filePath": "x.js",
                "messages": [
                    {"ruleId": "security/x", "severity": 2, "message": "m", "line": 1}
                ],
            }
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_eslint_security(path)
            self.assertEqual(findings[0]["severity"], "high")
        finally:
            os.unlink(path)

    def test_severity_1_maps_to_low(self):
        import generate_report
        data = [
            {
                "filePath": "y.js",
                "messages": [
                    {"ruleId": "security/y", "severity": 1, "message": "m", "line": 2}
                ],
            }
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_eslint_security(path)
            self.assertEqual(findings[0]["severity"], "low")
        finally:
            os.unlink(path)

    def test_non_list_input_returns_error(self):
        """非 list 输入应返回错误。"""
        import generate_report
        data = {"not": "a list"}
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_eslint_security(path)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("unexpected eslint json shape", err)
        finally:
            os.unlink(path)

    def test_corrupt_json_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            f.write("{not valid json")
            path = f.name
        try:
            findings, err = generate_report.parse_eslint_security(path)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(path)

    def test_non_dict_file_entry_skipped(self):
        """非 dict 的 file_entry 应被跳过，不抛异常。"""
        import generate_report
        data = [
            123,
            "not a dict",
            None,
            {
                "filePath": "real.js",
                "messages": [
                    {"ruleId": "security/z", "severity": 2, "message": "m", "line": 5}
                ],
            },
        ]
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_eslint_security(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["file"], "real.js")
        finally:
            os.unlink(path)


class TestParseTrufflehogBranches(unittest.TestCase):
    """parse_trufflehog 错误分支 + non-dict record。"""

    def test_io_error_returns_error(self):
        """文件不存在时应返回 ([], "could not parse ...")。"""
        import generate_report
        findings, err = generate_report.parse_trufflehog(
            "/nonexistent/trufflehog.jsonl"
        )
        self.assertEqual(findings, [])
        self.assertIsNotNone(err)
        self.assertIn("could not parse", err)

    def test_non_dict_record_skipped(self):
        """非 dict 的 JSON 记录应被跳过。

        正常 JSON 中以 { 开头的行必为 dict，此测试通过 patch json.loads
        模拟返回 list 来触发防御性 guard。
        """
        import generate_report
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", mode="w", delete=False
        ) as f:
            f.write('{"DetectorName": "should-be-skipped"}\n')
            path = f.name
        try:
            with mock.patch.object(
                generate_report.json,
                "loads",
                return_value=["not", "a", "dict"],
            ):
                findings, err = generate_report.parse_trufflehog(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [], "非 dict 记录应被跳过")
        finally:
            os.unlink(path)

    def test_normal_jsonl_parsed(self):
        """正常 JSONL 应被解析为 finding，含 malformed JSON 行应被跳过。"""
        import generate_report
        record = {
            "DetectorName": "AWS",
            "Verified": True,
            "SourceMetadata": {
                "Data": {"Filesystem": {"path": "/repo/.env"}}
            },
        }
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", mode="w", delete=False
        ) as f:
            f.write(json.dumps(record) + "\n")
            f.write("not a json line\n")
            f.write("{malformed json line\n")
            f.write('{"DetectorName": "unverified-detector", "Verified": false}\n')
            path = f.name
        try:
            findings, err = generate_report.parse_trufflehog(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0]["tool"], "trufflehog")
            self.assertEqual(findings[0]["rule"], "AWS")
            self.assertEqual(findings[0]["severity"], "critical")
            self.assertEqual(findings[0]["file"], "/repo/.env")
            self.assertIn("verified", findings[0]["message"])
            self.assertEqual(findings[1]["severity"], "high")
            self.assertIn("unverified", findings[1]["message"])
        finally:
            os.unlink(path)


class TestCollectFindingsBranches(unittest.TestCase):
    """collect_findings：codeql-*.sarif / parse_errors / fix redaction。"""

    def test_codeql_sarif_parsed(self):
        """含 codeql-*.sarif 文件时应被解析。"""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            codeql_sarif = {
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": "cpp/codeql-rule"}]}},
                        "results": [
                            {
                                "ruleId": "cpp/codeql-rule",
                                "level": "error",
                                "message": {"text": "codeql finding"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "main.cpp"},
                                            "region": {"startLine": 10},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
            with open(os.path.join(d, "codeql-cpp.sarif"), "w") as f:
                json.dump(codeql_sarif, f)
            findings, errors = generate_report.collect_findings(d)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["tool"], "codeql")
            self.assertEqual(findings[0]["rule"], "cpp/codeql-rule")
            self.assertEqual(errors, [])

    def test_parse_errors_collected(self):
        """parser 返回错误时，parse_errors 应包含错误信息。"""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bandit.json"), "w") as f:
                f.write("{not valid json")
            findings, errors = generate_report.collect_findings(d)
            self.assertEqual(findings, [])
            self.assertEqual(len(errors), 1)
            self.assertIn("could not parse", errors[0])
            self.assertIn("bandit.json", errors[0])

    def test_fix_field_redacted(self):
        """finding 的 fix 字段应被 redact_secrets 处理。"""
        import generate_report
        secret_fix = 'password = "supersecretpass123"'
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"rules": [{"id": "r1"}]}},
                    "results": [
                        {
                            "ruleId": "r1",
                            "level": "error",
                            "message": {"text": "issue"},
                            "fixes": [{"description": {"text": secret_fix}}],
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "f.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as f:
                json.dump(sarif, f)
            findings, _ = generate_report.collect_findings(d)
            self.assertEqual(len(findings), 1)
            self.assertIn("fix", findings[0])
            self.assertNotIn("supersecretpass123", findings[0]["fix"])
            self.assertIn("[REDACTED]", findings[0]["fix"])


class TestRenderReportSections(unittest.TestCase):
    """render_report：skipped / parse_errors / cwe / fix 渲染。"""

    def _basic_manifest(self):
        return {"target": "/test", "languages": ["python"], "timestamp": "2024-01-01"}

    def test_skipped_section_rendered(self):
        """manifest 含 skipped 时，报告应包含 'Tools not run' 段。"""
        import generate_report
        manifest = self._basic_manifest()
        manifest["skipped"] = [
            {"tool": "gosec", "reason": "not a Go project"},
            {"tool": "brakeman", "reason": "not a Ruby project"},
        ]
        report = generate_report.render_report("/test", [], [], manifest)
        self.assertIn("## Tools not run", report)
        self.assertIn("**gosec**", report)
        self.assertIn("not a Go project", report)
        self.assertIn("**brakeman**", report)
        self.assertIn("not a Ruby project", report)

    def test_parse_errors_section_rendered(self):
        """parse_errors 非空时，报告应包含 'Parse errors' 段。"""
        import generate_report
        errors = [
            "could not parse bandit.json: invalid",
            "could not parse cppcheck.xml: syntax error",
        ]
        report = generate_report.render_report(
            "/test", [], errors, self._basic_manifest()
        )
        self.assertIn("## Parse errors", report)
        self.assertIn("could not parse bandit.json: invalid", report)
        self.assertIn("could not parse cppcheck.xml: syntax error", report)

    def test_cwe_link_rendered(self):
        """finding 含 cwe/cwe_url 时，报告应包含 CWE 链接。"""
        import generate_report
        findings = [
            {
                "tool": "semgrep",
                "rule": "sql-injection",
                "severity": "high",
                "file": "db.py",
                "line": "42",
                "message": "SQL injection",
                "cwe": "CWE-89",
                "cwe_url": "https://cwe.mitre.org/data/definitions/89.html",
            }
        ]
        report = generate_report.render_report(
            "/test", findings, [], self._basic_manifest()
        )
        self.assertIn(
            "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)", report
        )

    def test_fix_line_rendered(self):
        """finding 含 fix 时，报告应包含 'Fix:' 行。"""
        import generate_report
        findings = [
            {
                "tool": "semgrep",
                "rule": "r1",
                "severity": "high",
                "file": "f.py",
                "line": "1",
                "message": "issue",
                "fix": "Use parameterized queries",
            }
        ]
        report = generate_report.render_report(
            "/test", findings, [], self._basic_manifest()
        )
        self.assertIn("**Fix:** Use parameterized queries", report)

    def test_no_cwe_no_fix_no_link(self):
        """finding 无 cwe/fix 时，报告不应含 CWE 链接或 Fix 行。"""
        import generate_report
        findings = [
            {
                "tool": "semgrep",
                "rule": "r1",
                "severity": "low",
                "file": "f.py",
                "line": "1",
                "message": "minor issue",
            }
        ]
        report = generate_report.render_report(
            "/test", findings, [], self._basic_manifest()
        )
        self.assertNotIn("cwe.mitre.org", report)
        self.assertNotIn("**Fix:**", report)


class TestMain(unittest.TestCase):
    """main() 测试：写入 report.md + --out 参数。"""

    def test_main_writes_default_report(self):
        """main() 应将报告写入 results_dir/report.md。"""
        import generate_report

        with tempfile.TemporaryDirectory() as d:
            manifest = {
                "target": "/test",
                "languages": ["python"],
                "timestamp": "2024-01-01",
            }
            with open(os.path.join(d, "scan_manifest.json"), "w") as f:
                json.dump(manifest, f)

            old_argv = sys.argv
            sys.argv = ["generate_report.py", d]
            try:
                generate_report.main()
            finally:
                sys.argv = old_argv

            report_path = os.path.join(d, "report.md")
            self.assertTrue(os.path.exists(report_path))
            with open(report_path) as f:
                content = f.read()
            self.assertIn("# Security audit report", content)
            self.assertIn("Target: `/test`", content)
            self.assertIn("Languages scanned: python", content)

    def test_main_with_out_argument(self):
        """--out 参数应将报告写入指定路径。"""
        import generate_report

        with tempfile.TemporaryDirectory() as d:
            manifest = {
                "target": "/test",
                "languages": [],
                "timestamp": "",
            }
            with open(os.path.join(d, "scan_manifest.json"), "w") as f:
                json.dump(manifest, f)

            out_path = os.path.join(d, "custom_report.md")
            old_argv = sys.argv
            sys.argv = ["generate_report.py", d, "--out", out_path]
            try:
                generate_report.main()
            finally:
                sys.argv = old_argv

            self.assertTrue(os.path.exists(out_path))
            default_path = os.path.join(d, "report.md")
            self.assertFalse(
                os.path.exists(default_path),
                "--out 指定路径时不应写入默认 report.md",
            )

    def test_main_without_manifest_uses_defaults(self):
        """无 scan_manifest.json 时应使用默认值，不抛异常。"""
        import generate_report

        with tempfile.TemporaryDirectory() as d:
            old_argv = sys.argv
            sys.argv = ["generate_report.py", d]
            try:
                generate_report.main()
            finally:
                sys.argv = old_argv

            report_path = os.path.join(d, "report.md")
            self.assertTrue(os.path.exists(report_path))
            with open(report_path) as f:
                content = f.read()
            self.assertIn("# Security audit report", content)
            self.assertIn("No findings", content)

    def test_main_with_findings(self):
        """有 finding 时报告应包含 Findings 段。"""
        import generate_report

        with tempfile.TemporaryDirectory() as d:
            manifest = {
                "target": "/test",
                "languages": ["python"],
                "timestamp": "2024-01-01",
            }
            with open(os.path.join(d, "scan_manifest.json"), "w") as f:
                json.dump(manifest, f)
            bandit_data = {
                "results": [
                    {
                        "test_id": "B608",
                        "issue_severity": "HIGH",
                        "filename": "db.py",
                        "line_number": 10,
                        "issue_text": "SQL injection",
                    }
                ]
            }
            with open(os.path.join(d, "bandit.json"), "w") as f:
                json.dump(bandit_data, f)

            old_argv = sys.argv
            sys.argv = ["generate_report.py", d]
            try:
                generate_report.main()
            finally:
                sys.argv = old_argv

            with open(os.path.join(d, "report.md")) as f:
                content = f.read()
            self.assertIn("## Findings", content)
            self.assertIn("### High", content)
            self.assertIn("db.py:10", content)
            self.assertIn("SQL injection", content)


class TestLineSortKey(unittest.TestCase):
    """_line_sort_key：数字行在前，非数字行在后。"""

    def test_numeric_line_sorts_before_non_numeric(self):
        import generate_report
        numeric = generate_report._line_sort_key("42")
        non_numeric = generate_report._line_sort_key("?")
        self.assertLess(numeric, non_numeric,
                        "数字行应排在非数字行之前")

    def test_numeric_lines_sorted_ascending(self):
        import generate_report
        lines = ["10", "2", "1"]
        sorted_lines = sorted(lines, key=generate_report._line_sort_key)
        self.assertEqual(sorted_lines, ["1", "2", "10"],
                         "数字行应按数值升序排列，非字典序")

    def test_non_numeric_line_returns_group_one(self):
        import generate_report
        key = generate_report._line_sort_key("?")
        self.assertEqual(key[0], 1)


class TestParseSarifRuleIndex(unittest.TestCase):
    """parse_sarif ruleIndex 解析（line 162-166）。"""

    def test_valid_rule_index_resolves_id(self):
        """ruleIndex 在范围内时应解析为对应 rule id。"""
        import generate_report
        sarif = {
            "runs": [{
                "tool": {"driver": {"rules": [{"id": "first"}, {"id": "second"}]}},
                "results": [{
                    "ruleIndex": 1,
                    "level": "note",
                    "message": {"text": "y"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "g.py"},
                        "region": {"startLine": 5}}}]}]
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

    def test_out_of_range_rule_index_falls_back(self):
        """ruleIndex 越界时应回退到 unknown-rule，不抛异常。"""
        import generate_report
        sarif = {
            "runs": [{
                "tool": {"driver": {"rules": [{"id": "r0"}]}},
                "results": [{
                    "ruleIndex": 999,
                    "level": "error",
                    "message": {"text": "x"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "f.py"},
                        "region": {"startLine": 1}}}]}]
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


class TestParseCppcheckFull(unittest.TestCase):
    """parse_cppcheck 成功解析路径（line 236-254）。"""

    def test_valid_xml_with_multiple_errors_parsed(self):
        """有效 XML 含多个 error 应全部解析，severity 正确映射。"""
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
  </errors>
</results>"""
        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
            f.write(xml)
            path = f.name
        try:
            findings, err = generate_report.parse_cppcheck(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 2)
            by_msg = {f["message"]: f for f in findings}
            self.assertEqual(by_msg["Null pointer dereference"]["severity"], "high")
            self.assertEqual(by_msg["Null pointer dereference"]["file"], "src/a.c")
            self.assertEqual(by_msg["Null pointer dereference"]["line"], "10")
            self.assertEqual(by_msg["Unused variable"]["severity"], "low")
        finally:
            os.unlink(path)

    def test_error_without_location_uses_defaults(self):
        """error 无 location 元素时应使用默认 file/line。"""
        import generate_report
        xml = """<?xml version="1.0"?>
<results><errors>
  <error id="noLoc" severity="warning" msg="No location"/>
</errors></results>"""
        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
            f.write(xml)
            path = f.name
        try:
            findings, _ = generate_report.parse_cppcheck(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["file"], "unknown file")
            self.assertEqual(findings[0]["line"], "?")
        finally:
            os.unlink(path)


class TestParseCargoAuditFull(unittest.TestCase):
    """parse_cargo_audit 成功解析路径（line 264-279）。"""

    def test_valid_json_with_vulnerabilities_parsed(self):
        """有效 JSON 含多个漏洞应全部解析。"""
        import generate_report
        data = {
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": {"id": "RUSTSEC-001", "severity": "High", "title": "XSS"},
                        "package": {"name": "foo", "version": "1.0"},
                    },
                    {
                        "advisory": {"id": "RUSTSEC-002", "title": "no severity"},
                        "package": {"name": "bar", "version": "2.0"},
                    },
                ]
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_cargo_audit(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0]["tool"], "cargo-audit")
            self.assertEqual(findings[0]["rule"], "RUSTSEC-001")
            self.assertEqual(findings[0]["severity"], "high")
            self.assertEqual(findings[0]["file"], "Cargo.lock")
            self.assertIn("foo 1.0", findings[0]["message"])
            self.assertIn("XSS", findings[0]["message"])
            self.assertEqual(findings[1]["severity"], "medium")
        finally:
            os.unlink(path)

    def test_empty_vulnerabilities_returns_empty(self):
        """无漏洞时应返回空 findings。"""
        import generate_report
        data = {"vulnerabilities": {"list": []}}
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_cargo_audit(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)


class TestCvssToSeverity(unittest.TestCase):
    """_cvss_to_severity 全部分支（line 402-414）。"""

    def test_none_returns_unknown(self):
        import generate_report
        self.assertEqual(generate_report._cvss_to_severity(None), "unknown")

    def test_non_numeric_returns_unknown(self):
        import generate_report
        self.assertEqual(generate_report._cvss_to_severity("abc"), "unknown")
        self.assertEqual(generate_report._cvss_to_severity([1, 2]), "unknown")

    def test_critical_band(self):
        """score >= 9.0 → critical。"""
        import generate_report
        self.assertEqual(generate_report._cvss_to_severity(9.0), "critical")
        self.assertEqual(generate_report._cvss_to_severity(10.0), "critical")
        self.assertEqual(generate_report._cvss_to_severity("9.5"), "critical")

    def test_high_band(self):
        """7.0 <= score < 9.0 → high。"""
        import generate_report
        self.assertEqual(generate_report._cvss_to_severity(7.0), "high")
        self.assertEqual(generate_report._cvss_to_severity(8.9), "high")

    def test_medium_band(self):
        """4.0 <= score < 7.0 → medium。"""
        import generate_report
        self.assertEqual(generate_report._cvss_to_severity(4.0), "medium")
        self.assertEqual(generate_report._cvss_to_severity(6.9), "medium")

    def test_low_band(self):
        """score < 4.0 → low。"""
        import generate_report
        self.assertEqual(generate_report._cvss_to_severity(0.0), "low")
        self.assertEqual(generate_report._cvss_to_severity(3.9), "low")


class TestTrivyCvssScore(unittest.TestCase):
    """_trivy_cvss_score 全部分支（line 424-434）。"""

    def test_no_cvss_returns_none(self):
        import generate_report
        self.assertIsNone(generate_report._trivy_cvss_score({}))

    def test_cvss_not_dict_returns_none(self):
        import generate_report
        self.assertIsNone(generate_report._trivy_cvss_score({"CVSS": "not a dict"}))

    def test_nvd_v3_score_extracted(self):
        import generate_report
        vuln = {"CVSS": {"nvd": {"V3Score": 9.8}}}
        self.assertEqual(generate_report._trivy_cvss_score(vuln), 9.8)

    def test_redhat_v2_score_extracted(self):
        import generate_report
        vuln = {"CVSS": {"redhat": {"V2Score": 7.5}}}
        self.assertEqual(generate_report._trivy_cvss_score(vuln), 7.5)

    def test_vendor_preference_nvd_over_redhat(self):
        """nvd 优先于 redhat。"""
        import generate_report
        vuln = {"CVSS": {"nvd": {"V3Score": 9.0}, "redhat": {"V3Score": 5.0}}}
        self.assertEqual(generate_report._trivy_cvss_score(vuln), 9.0)

    def test_no_vendor_score_returns_none(self):
        import generate_report
        vuln = {"CVSS": {"nvd": {}}}
        self.assertIsNone(generate_report._trivy_cvss_score(vuln))


class TestParseTrivy(unittest.TestCase):
    """parse_trivy 全路径（line 448-478）。"""

    def test_valid_json_with_severity_field(self):
        """有 Severity 字段时应使用 norm_severity 映射。"""
        import generate_report
        data = {
            "Results": [{
                "Target": "package-lock.json",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-001",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.0",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                }]
            }]
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_trivy(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f0 = findings[0]
            self.assertEqual(f0["tool"], "trivy")
            self.assertEqual(f0["rule"], "CVE-2024-001")
            self.assertEqual(f0["severity"], "high")
            self.assertEqual(f0["file"], "package-lock.json")
            self.assertIn("lodash 4.17.0", f0["message"])
            self.assertIn("fixed in 4.17.21", f0["message"])
        finally:
            os.unlink(path)

    def test_no_severity_falls_back_to_cvss(self):
        """无 Severity 字段时应通过 CVSS 分数推断 severity。"""
        import generate_report
        data = {
            "Results": [{
                "Target": "Cargo.lock",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-002",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.0.0",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                }]
            }]
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_trivy(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "critical")
            self.assertNotIn("fixed in", findings[0]["message"])
        finally:
            os.unlink(path)

    def test_corrupt_json_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("{not valid")
            path = f.name
        try:
            findings, err = generate_report.parse_trivy(path)
            self.assertEqual(findings, [])
            self.assertIn("could not parse", err)
        finally:
            os.unlink(path)

    def test_empty_results_returns_empty(self):
        import generate_report
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"Results": []}, f)
            path = f.name
        try:
            findings, err = generate_report.parse_trivy(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)


class TestParseGitleaks(unittest.TestCase):
    """parse_gitleaks 全路径（line 491-520）。"""

    def test_valid_json_array_parsed(self):
        """有效 JSON array 应正确解析，Secret/Match 不应出现在 message 中。"""
        import generate_report
        data = [
            {
                "RuleID": "aws-access-key",
                "File": "/repo/config.py",
                "StartLine": 42,
                "Secret": "AKIAEXAMPLE1234567890",
                "Match": "AKIAEXAMPLE",
                "Entropy": 3.5,
            }
        ]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_gitleaks(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f0 = findings[0]
            self.assertEqual(f0["tool"], "gitleaks")
            self.assertEqual(f0["rule"], "aws-access-key")
            self.assertEqual(f0["severity"], "high")
            self.assertEqual(f0["file"], "/repo/config.py")
            self.assertEqual(f0["line"], 42)
            self.assertIn("aws-access-key", f0["message"])
            self.assertIn("entropy=3.5", f0["message"])
            self.assertNotIn("AKIAEXAMPLE", f0["message"],
                              "Secret 值不应出现在 message 中")
        finally:
            os.unlink(path)

    def test_non_list_input_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"not": "a list"}, f)
            path = f.name
        try:
            findings, err = generate_report.parse_gitleaks(path)
            self.assertEqual(findings, [])
            self.assertIn("unexpected gitleaks json shape", err)
        finally:
            os.unlink(path)

    def test_corrupt_json_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("{not valid")
            path = f.name
        try:
            findings, err = generate_report.parse_gitleaks(path)
            self.assertEqual(findings, [])
            self.assertIn("could not parse", err)
        finally:
            os.unlink(path)

    def test_description_fallback_for_rule_id(self):
        """无 RuleID 时应使用 Description 作为 rule_id。"""
        import generate_report
        data = [{"Description": "custom-rule", "File": "x.py", "StartLine": 1}]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_gitleaks(path)
            self.assertEqual(findings[0]["rule"], "custom-rule")
        finally:
            os.unlink(path)

    def test_non_dict_entry_skipped(self):
        """非 dict 的条目应被跳过。"""
        import generate_report
        data = [123, "str", {"RuleID": "real", "File": "x.py", "StartLine": 1}]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_gitleaks(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "real")
        finally:
            os.unlink(path)


class TestParseRetire(unittest.TestCase):
    """parse_retire 全路径（line 579-617）。"""

    def test_valid_json_with_cve_parsed(self):
        """有效 JSON 含 CVE identifiers 应正确解析。"""
        import generate_report
        data = [
            {
                "component": "jquery",
                "version": "1.8.0",
                "path": "/public/js/jquery.js",
                "results": [{
                    "vulnerabilities": [{
                        "id": "vuln-1",
                        "severity": "high",
                        "identifiers": {"CVE": ["CVE-2015-9251"]},
                    }]
                }],
            }
        ]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, err = generate_report.parse_retire(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f0 = findings[0]
            self.assertEqual(f0["tool"], "retire")
            self.assertEqual(f0["rule"], "CVE-2015-9251")
            self.assertEqual(f0["severity"], "high")
            self.assertEqual(f0["file"], "/public/js/jquery.js")
            self.assertIn("jquery 1.8.0", f0["message"])
            self.assertIn("CVE-2015-9251", f0["message"])
        finally:
            os.unlink(path)

    def test_no_cve_uses_retire_id(self):
        """无 CVE 时应使用 retire 内部 id 作为 rule_id。"""
        import generate_report
        data = [
            {
                "component": "lodash",
                "version": "1.0",
                "path": "/lodash.js",
                "results": [{
                    "vulnerabilities": [{
                        "id": "retire-123",
                        "severity": "medium",
                        "identifiers": {},
                    }]
                }],
            }
        ]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_retire(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "retire-retire-123")
            self.assertEqual(findings[0]["severity"], "medium")
        finally:
            os.unlink(path)

    def test_non_list_input_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"not": "a list"}, f)
            path = f.name
        try:
            findings, err = generate_report.parse_retire(path)
            self.assertEqual(findings, [])
            self.assertIn("unexpected retire json shape", err)
        finally:
            os.unlink(path)

    def test_corrupt_json_returns_error(self):
        import generate_report
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("{not valid")
            path = f.name
        try:
            findings, err = generate_report.parse_retire(path)
            self.assertEqual(findings, [])
            self.assertIn("could not parse", err)
        finally:
            os.unlink(path)

    def test_non_dict_component_skipped(self):
        """非 dict 的 component 应被跳过。"""
        import generate_report
        data = [123, {"component": "x", "version": "1", "path": "x.js", "results": []}]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings, _ = generate_report.parse_retire(path)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)


class TestCollectFindingsDedupAndCodeqlError(unittest.TestCase):
    """collect_findings 去重 + codeql 错误分支。"""

    def test_dedup_skips_duplicate(self):
        """相同 file:line:rule 的 finding 应去重，只保留第一个。"""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            semgrep_sarif = {
                "runs": [{
                    "tool": {"driver": {"rules": [{"id": "r1"}]}},
                    "results": [{
                        "ruleId": "r1",
                        "level": "error",
                        "message": {"text": "a"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "f.py"},
                            "region": {"startLine": 1}}}]
                    }]
                }]
            }
            with open(os.path.join(d, "semgrep.sarif"), "w") as f:
                json.dump(semgrep_sarif, f)
            bandit_json = {
                "results": [{
                    "test_id": "r1",
                    "issue_severity": "HIGH",
                    "filename": "f.py",
                    "line_number": 1,
                    "issue_text": "same issue from bandit"
                }]
            }
            with open(os.path.join(d, "bandit.json"), "w") as f:
                json.dump(bandit_json, f)
            findings, _ = generate_report.collect_findings(d)
            self.assertEqual(len(findings), 1, "相同 file:line:rule 应去重")

    def test_codeql_corrupt_sarif_collects_error(self):
        """corrupt codeql-*.sarif 应将错误收集到 parse_errors。"""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "codeql-cpp.sarif"), "w") as f:
                f.write("{not valid json")
            findings, errors = generate_report.collect_findings(d)
            self.assertEqual(findings, [])
            self.assertEqual(len(errors), 1)
            self.assertIn("could not parse", errors[0])
            self.assertIn("codeql-cpp.sarif", errors[0])


class TestRenderReportFailedToolsAndSeverityBreak(unittest.TestCase):
    """render_report failed_tools 段 + 多 severity 间隔。"""

    def _basic_manifest(self):
        return {"target": "/test", "languages": ["python"], "timestamp": "2024-01-01"}

    def test_failed_tools_section_rendered(self):
        """manifest 含非零 returncode 的 ran 条目时，报告应含 failed_tools 段。"""
        import generate_report
        manifest = self._basic_manifest()
        manifest["ran"] = [
            {"tool": "bandit", "returncode": 0},
            {"tool": "gosec", "returncode": 1, "log_tail": "panic: tool not found"},
            {"tool": "cppcheck", "returncode": 2, "log_tail": ""},
        ]
        report = generate_report.render_report("/test", [], [], manifest)
        self.assertIn("## Tools attempted but failed", report)
        self.assertIn("**gosec**", report)
        self.assertIn("exit 1", report)
        self.assertIn("panic: tool not found", report)
        self.assertIn("**cppcheck**", report)
        self.assertIn("(no output)", report)
        self.assertNotIn("**bandit**", report)

    def test_multiple_severities_get_section_breaks(self):
        """多个 severity 的 findings 应有分节标题。"""
        import generate_report
        findings = [
            {
                "tool": "t1", "rule": "r1", "severity": "high",
                "file": "a.py", "line": "1", "message": "high issue",
            },
            {
                "tool": "t2", "rule": "r2", "severity": "low",
                "file": "b.py", "line": "2", "message": "low issue",
            },
        ]
        report = generate_report.render_report("/test", findings, [], self._basic_manifest())
        self.assertIn("### High", report)
        self.assertIn("### Low", report)
        self.assertIn("high issue", report)
        self.assertIn("low issue", report)


class TestParseCheckov(unittest.TestCase):
    """parse_checkov: IaC scanner JSON output parser."""

    def _write(self, d, data):
        p = os.path.join(d, "checkov.json")
        with open(p, "w") as f:
            json.dump(data, f)
        return p

    def test_failed_checks_parsed(self):
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            data = {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_18",
                            "name": "Ensure S3 bucket has logging enabled",
                            "resource": "aws_s3_bucket.my_bucket",
                            "file_path": "/main.tf",
                            "file_line_range": [1, 10],
                            "severity": "high",
                        }
                    ],
                    "passed_checks": [{"check_id": "CKV_AWS_19"}],
                }
            }
            findings, err = generate_report.parse_checkov(self._write(d, data))
        self.assertIsNone(err)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["tool"], "checkov")
        self.assertEqual(f["rule"], "CKV_AWS_18")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["file"], "main.tf")
        self.assertEqual(f["line"], 1)
        self.assertIn("S3 bucket", f["message"])

    def test_passed_checks_ignored(self):
        """Only failed_checks should produce findings."""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            data = {"results": {"passed_checks": [{"check_id": "CKV_1"}]}}
            findings, err = generate_report.parse_checkov(self._write(d, data))
        self.assertIsNone(err)
        self.assertEqual(findings, [])

    def test_empty_results(self):
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            findings, err = generate_report.parse_checkov(self._write(d, {"results": {}}))
        self.assertIsNone(err)
        self.assertEqual(findings, [])

    def test_guideline_appended(self):
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            data = {"results": {"failed_checks": [{
                "check_id": "CKV1", "name": "test", "resource": "r",
                "file_path": "/f.tf", "file_line_range": [1, 2],
                "severity": "medium", "guideline": "https://example.com",
            }]}}
            findings, _ = generate_report.parse_checkov(self._write(d, data))
        self.assertIn("https://example.com", findings[0]["message"])


class TestParseTfsec(unittest.TestCase):
    """parse_tfsec: Terraform-specific security scanner JSON output parser."""

    def _write(self, d, data):
        p = os.path.join(d, "tfsec.json")
        with open(p, "w") as f:
            json.dump(data, f)
        return p

    def test_results_parsed(self):
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            data = {"results": [{
                "rule_id": "AWS018",
                "severity": "HIGH",
                "description": "S3 bucket without logging",
                "location": {"filename": "main.tf", "start_line": 5},
                "resolution": "Enable logging",
            }]}
            findings, err = generate_report.parse_tfsec(self._write(d, data))
        self.assertIsNone(err)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["tool"], "tfsec")
        self.assertEqual(f["rule"], "AWS018")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["file"], "main.tf")
        self.assertEqual(f["line"], 5)
        self.assertIn("fix: Enable logging", f["message"])

    def test_empty_results(self):
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            findings, err = generate_report.parse_tfsec(self._write(d, {"results": []}))
        self.assertIsNone(err)
        self.assertEqual(findings, [])

    def test_list_format(self):
        """tfsec may emit a bare list instead of {results: [...]}."""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            data = [{"rule_id": "GEN001", "severity": "MEDIUM",
                      "description": "test", "location": {"filename": "f.tf", "start_line": 1}}]
            findings, err = generate_report.parse_tfsec(self._write(d, data))
        self.assertIsNone(err)
        self.assertEqual(len(findings), 1)


class TestScriptEntryPoint(unittest.TestCase):
    """覆盖 if __name__ == "__main__": main() 行（line 819）。"""

    def test_script_runs_via_subprocess(self):
        """直接执行脚本应触发 main() 入口。"""
        import generate_report
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run(
                [sys.executable, generate_report.__file__, d],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(os.path.exists(os.path.join(d, "report.md")))
            self.assertIn("report written to", result.stdout)


if __name__ == "__main__":
    unittest.main()
