#!/usr/bin/env python3
"""Tiangang strix 吸收功能的单元测试。

覆盖从 strix 吸收进 tiangang 的四项功能：
- trivy SCA 依赖 CVE 扫描
- gitleaks + trufflehog 专用密钥扫描
- Semgrep 调用参数升级（--metrics=off/--jobs/--timeout/--quiet）
- retire.js 前端 CVE 库扫描

测试验证有意义的属性：解析正确性、字段提取、secret 不泄露、
severity 映射、空结果处理，而非仅"函数有返回值"。
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


# ===== trivy SCA parser =====


class TestTrivyParser(unittest.TestCase):
    """trivy fs --scanners vuln --format json 输出解析。"""

    def _write(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_parses_vulnerability_fields(self):
        import generate_report

        data = {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-23337",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.4",
                            "FixedVersion": "4.17.21",
                            "Severity": "HIGH",
                            "CVSS": {"nvd": {"V3Score": 7.5}},
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                        }
                    ],
                }
            ]
        }
        path = self._write(data)
        try:
            findings, err = generate_report.parse_trivy(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f["tool"], "trivy")
            self.assertEqual(f["rule"], "CVE-2021-23337")
            self.assertEqual(f["severity"], "high")
            self.assertIn("lodash", f["message"])
            self.assertIn("4.17.4", f["message"])
            self.assertIn("4.17.21", f["message"])
            self.assertEqual(f["file"], "package-lock.json")
        finally:
            os.unlink(path)

    def test_severity_from_cvss_when_field_missing(self):
        """Severity 字段缺失时，CVSS V3 分数驱动 severity 映射。"""
        import generate_report

        data = {
            "Results": [
                {
                    "Target": "Cargo.lock",
                    "Type": "cargo",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2020-9999",
                            "PkgName": "foo",
                            "InstalledVersion": "1.0",
                            "CVSS": {"nvd": {"V3Score": 9.8}},
                        }
                    ],
                }
            ]
        }
        path = self._write(data)
        try:
            findings, _ = generate_report.parse_trivy(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "critical")
        finally:
            os.unlink(path)

    def test_empty_results_returns_empty(self):
        import generate_report

        path = self._write({"Results": []})
        try:
            findings, err = generate_report.parse_trivy(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_results_without_vulnerabilities(self):
        """有 Results 但无 Vulnerabilities（lockfile 扫了但干净）。"""
        import generate_report

        data = {
            "Results": [
                {"Target": "go.sum", "Type": "gomod", "Vulnerabilities": []}
            ]
        }
        path = self._write(data)
        try:
            findings, err = generate_report.parse_trivy(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_corrupt_json_returns_error(self):
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write("{not valid json")
        f.close()
        try:
            findings, err = generate_report.parse_trivy(f.name)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(f.name)


# ===== gitleaks parser =====


class TestGitleaksParser(unittest.TestCase):
    """gitleaks detect --report-format json 输出解析。"""

    def _write(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_parses_finding_without_leaking_secret(self):
        """gitleaks 的 Secret/Match 字段不得出现在 finding message 中。"""
        import generate_report

        data = [
            {
                "Description": "AWS Access Token",
                "StartLine": 42,
                "EndLine": 42,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "config.py",
                "RuleID": "aws-access-token",
                "Entropy": 3.5,
                "Fingerprint": "config.py:aws-access-token:42",
            }
        ]
        path = self._write(data)
        try:
            findings, err = generate_report.parse_gitleaks(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f["tool"], "gitleaks")
            self.assertEqual(f["rule"], "aws-access-token")
            self.assertEqual(f["file"], "config.py")
            self.assertEqual(f["line"], 42)
            self.assertEqual(f["severity"], "high")
            # P0 安全属性：message 不得包含实际 secret 值
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f["message"])
        finally:
            os.unlink(path)

    def test_missing_ruleid_falls_back_to_description(self):
        import generate_report

        data = [
            {
                "Description": "Generic API Key",
                "StartLine": 10,
                "File": "app.py",
                "Secret": "xxx",
            }
        ]
        path = self._write(data)
        try:
            findings, _ = generate_report.parse_gitleaks(path)
            self.assertEqual(findings[0]["rule"], "Generic API Key")
        finally:
            os.unlink(path)

    def test_empty_array_returns_empty(self):
        import generate_report

        path = self._write([])
        try:
            findings, err = generate_report.parse_gitleaks(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)


# ===== trufflehog parser =====


class TestTrufflehogParser(unittest.TestCase):
    """trufflehog filesystem --json 输出解析（JSONL，每行一个 JSON）。"""

    def _write(self, records):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        for r in records:
            f.write(json.dumps(r) + "\n")
        f.close()
        return f.name

    def test_parses_finding_without_leaking_raw(self):
        """trufflehog 的 Raw/Redacted 字段不得出现在 message 中。"""
        import generate_report

        record = {
            "SourceMetadata": {"Data": {"Filesystem": {"path": "config.py"}}},
            "DetectorName": "AWS",
            "DetectorType": 18,
            "Verified": False,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "Redacted": "AKIA[REDACTED]",
        }
        path = self._write([record])
        try:
            findings, err = generate_report.parse_trufflehog(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f["tool"], "trufflehog")
            self.assertEqual(f["rule"], "AWS")
            self.assertEqual(f["file"], "config.py")
            self.assertEqual(f["severity"], "high")
            # P0 安全属性：message 不得包含 Raw 值
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f["message"])
            self.assertIn("unverified", f["message"].lower())
        finally:
            os.unlink(path)

    def test_verified_finding_critical_severity(self):
        """Verified=True 的 secret 提升到 critical。"""
        import generate_report

        record = {
            "SourceMetadata": {"Data": {"Filesystem": {"path": ".env"}}},
            "DetectorName": "Slack",
            "Verified": True,
            "Raw": "xoxb-...",
            "Redacted": "xoxb-[REDACTED]",
        }
        path = self._write([record])
        try:
            findings, _ = generate_report.parse_trufflehog(path)
            self.assertEqual(findings[0]["severity"], "critical")
        finally:
            os.unlink(path)

    def test_empty_file_returns_empty(self):
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.close()
        try:
            findings, err = generate_report.parse_trufflehog(f.name)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(f.name)

    def test_skips_non_json_lines(self):
        """非 JSON 行（如 trufflehog 的进度日志）应被跳过而非崩溃。"""
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write("loading modules...\n")
        f.write(json.dumps({
            "SourceMetadata": {"Data": {"Filesystem": {"path": "a.py"}}},
            "DetectorName": "AWS",
            "Verified": False,
        }) + "\n")
        f.close()
        try:
            findings, err = generate_report.parse_trufflehog(f.name)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
        finally:
            os.unlink(f.name)


# ===== retire.js parser =====


class TestRetireParser(unittest.TestCase):
    """retire --outputformat json 输出解析。"""

    def _write(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_parses_component_vulnerability(self):
        import generate_report

        data = [
            {
                "component": "jquery",
                "version": "1.8.3",
                "path": "/abs/public/jquery.js",
                "detections": ["file"],
                "results": [
                    {
                        "vulnerabilities": [
                            {
                                "id": 1,
                                "severity": "high",
                                "identifiers": {"CVE": ["CVE-2015-9251"]},
                                "info": ["https://example.com/advisory"],
                            }
                        ]
                    }
                ],
            }
        ]
        path = self._write(data)
        try:
            findings, err = generate_report.parse_retire(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f["tool"], "retire")
            self.assertEqual(f["rule"], "CVE-2015-9251")
            self.assertEqual(f["severity"], "high")
            self.assertIn("jquery", f["message"])
            self.assertIn("1.8.3", f["message"])
            self.assertEqual(f["file"], "/abs/public/jquery.js")
        finally:
            os.unlink(path)

    def test_multiple_vulnerabilities_one_per_cve(self):
        """一个组件多个 CVE 应拆成多个 finding。"""
        import generate_report

        data = [
            {
                "component": "lodash",
                "version": "4.17.4",
                "path": "/abs/lodash.js",
                "results": [
                    {
                        "vulnerabilities": [
                            {
                                "severity": "high",
                                "identifiers": {"CVE": ["CVE-2019-10744"]},
                            },
                            {
                                "severity": "medium",
                                "identifiers": {"CVE": ["CVE-2020-8203"]},
                            },
                        ]
                    }
                ],
            }
        ]
        path = self._write(data)
        try:
            findings, _ = generate_report.parse_retire(path)
            self.assertEqual(len(findings), 2)
            rules = {f["rule"] for f in findings}
            self.assertEqual(rules, {"CVE-2019-10744", "CVE-2020-8203"})
        finally:
            os.unlink(path)

    def test_empty_array_returns_empty(self):
        import generate_report

        path = self._write([])
        try:
            findings, err = generate_report.parse_retire(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)


# ===== Semgrep 参数升级 =====


class TestSemgrepMetricsOff(unittest.TestCase):
    """Semgrep 命令必须包含 --metrics=off（隐私+正确性）。"""

    def test_semgrep_cmd_has_metrics_off(self):
        import inspect
        import run_scan

        source = inspect.getsource(run_scan._run_semgrep)
        self.assertIn(
            "--metrics=off",
            source,
            "semgrep 必须显式 --metrics=off 关闭遥测（默认会发送）",
        )


class TestSemgrepJobsTimeout(unittest.TestCase):
    """Semgrep 命令应包含 --jobs 和 --timeout 保证可复现运行。"""

    def test_semgrep_cmd_has_jobs_and_timeout(self):
        import inspect
        import run_scan

        source = inspect.getsource(run_scan._run_semgrep)
        self.assertIn("--jobs", source, "semgrep 应显式 --jobs")
        self.assertIn("--timeout", source, "semgrep 应显式 --timeout")


class TestSemgrepQuiet(unittest.TestCase):
    """自动化场景下 semgrep 应 --quiet 减少噪声。"""

    def test_semgrep_cmd_has_quiet(self):
        import inspect
        import run_scan

        source = inspect.getsource(run_scan._run_semgrep)
        self.assertIn("--quiet", source)


# ===== PARSERS 注册 =====


class TestParsersIncludeNewTools(unittest.TestCase):
    """PARSERS 必须注册 trivy/gitleaks/trufflehog/retire。"""

    def test_parsers_include_all_new(self):
        import generate_report

        keys = set(generate_report.PARSERS.keys())
        for name in (
            "trivy.json",
            "gitleaks.json",
            "trufflehog.jsonl",
            "retire.json",
        ):
            self.assertIn(name, keys, f"PARSERS 必须注册 {name}")


# ===== run_scan 工具集成 =====


class TestRunScanWiresNewTools(unittest.TestCase):
    """run_scan.py 应该为 trivy/gitleaks/trufflehog/retire 构造扫描命令。"""

    def _source(self):
        with open(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "run_scan.py")
        ) as f:
            return f.read()

    def test_run_scan_wires_trivy(self):
        s = self._source()
        self.assertIn("trivy", s)
        self.assertIn("--scanners", s)
        self.assertIn("--offline-scan", s)

    def test_run_scan_wires_gitleaks(self):
        self.assertIn("gitleaks", self._source())

    def test_run_scan_wires_trufflehog(self):
        self.assertIn("trufflehog", self._source())

    def test_run_scan_wires_retire(self):
        self.assertIn("retire", self._source())

    def test_run_scan_trivy_db_staleness_signal(self):
        """trivy version 应被记录作为 DB 陈旧信号（不静默干净扫描）。"""
        s = self._source()
        self.assertIn("trivy version", s)


# ===== edge case / error-handling coverage for absorbed parsers =====


class TestCvssToSeverityBands(unittest.TestCase):
    """_cvss_to_severity 必须按 CVSS v3 标准带映射全部四个 band + None/非数字。"""

    def test_none_score_returns_unknown(self):
        import generate_report

        self.assertEqual(generate_report._cvss_to_severity(None), "unknown")

    def test_non_numeric_score_returns_unknown(self):
        import generate_report

        self.assertEqual(generate_report._cvss_to_severity("not-a-number"), "unknown")
        # 直接抛 TypeError 的对象
        self.assertEqual(
            generate_report._cvss_to_severity({"foo": "bar"}), "unknown"
        )

    def test_low_band_below_4(self):
        import generate_report

        self.assertEqual(generate_report._cvss_to_severity(3.9), "low")
        self.assertEqual(generate_report._cvss_to_severity(0.0), "low")

    def test_medium_band_4_to_7(self):
        import generate_report

        self.assertEqual(generate_report._cvss_to_severity(4.0), "medium")
        self.assertEqual(generate_report._cvss_to_severity(6.9), "medium")

    def test_high_band_7_to_9(self):
        import generate_report

        self.assertEqual(generate_report._cvss_to_severity(7.0), "high")
        self.assertEqual(generate_report._cvss_to_severity(8.9), "high")

    def test_critical_band_9_plus(self):
        import generate_report

        self.assertEqual(generate_report._cvss_to_severity(9.0), "critical")
        self.assertEqual(generate_report._cvss_to_severity(10.0), "critical")


class TestTrivyCvssScoreExtraction(unittest.TestCase):
    """_trivy_cvss_score 应从多个 vendor block 中取第一个 V3Score。"""

    def test_cvss_not_dict_returns_none(self):
        import generate_report

        # CVSS 字段不是 dict（malformed trivy 输出）应返回 None 而非崩溃
        vuln = {"CVSS": ["not", "a", "dict"]}
        self.assertIsNone(generate_report._trivy_cvss_score(vuln))

    def test_no_vendor_match_returns_none(self):
        import generate_report

        # 所有 vendor block 都没有 V3Score/V2Score
        vuln = {"CVSS": {"nvd": {}, "redhat": {}}}
        self.assertIsNone(generate_report._trivy_cvss_score(vuln))

    def test_falls_back_to_v2_score(self):
        import generate_report

        # 没有 V3Score 时回退到 V2Score
        vuln = {"CVSS": {"nvd": {"V2Score": 6.5}}}
        self.assertEqual(generate_report._trivy_cvss_score(vuln), 6.5)

    def test_missing_cvss_field_returns_none(self):
        import generate_report

        # 完全没有 CVSS 字段
        self.assertIsNone(generate_report._trivy_cvss_score({}))


class TestGitleaksMalformedInput(unittest.TestCase):
    """gitleaks parser 对 malformed input 必须显性返回错误，不崩溃。"""

    def test_corrupt_json_returns_error(self):
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write("{not valid json")
        f.close()
        try:
            findings, err = generate_report.parse_gitleaks(f.name)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(f.name)

    def test_non_list_shape_returns_error(self):
        """gitleaks 输出必须是 list；其他形状是 malformed 输出。"""
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump({"not": "an array"}, f)
        f.close()
        try:
            findings, err = generate_report.parse_gitleaks(f.name)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("expected list", err)
        finally:
            os.unlink(f.name)

    def test_non_dict_items_skipped(self):
        """list 中的非 dict 项应被跳过，不崩溃。"""
        import generate_report

        # 混入字符串和 None
        data = [
            "not a dict",
            None,
            {"RuleID": "real-rule", "File": "a.py", "StartLine": 1},
        ]
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        try:
            findings, err = generate_report.parse_gitleaks(f.name)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "real-rule")
        finally:
            os.unlink(f.name)


class TestTrufflehogMalformedInput(unittest.TestCase):
    """trufflehog parser 对 malformed JSONL 必须跳过非 JSON 行，不崩溃。"""

    def test_corrupt_json_line_skipped(self):
        """以 { 开头但 JSON 解析失败的行应被跳过。"""
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write('{"DetectorName": "AWS", "Verified": false}\n')  # 有效行
        f.write('{"broken": missing quotes}\n')  # JSON 解析失败
        f.close()
        try:
            findings, err = generate_report.parse_trufflehog(f.name)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "AWS")
        finally:
            os.unlink(f.name)

    def test_non_dict_json_skipped(self):
        """合法 JSON 但不是 dict（如 [1,2,3]）应被跳过。"""
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write('[1, 2, 3]\n')  # list, not dict
        f.write('{"DetectorName": "Slack", "Verified": true}\n')
        f.close()
        try:
            findings, _ = generate_report.parse_trufflehog(f.name)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "Slack")
        finally:
            os.unlink(f.name)

    def test_missing_source_metadata_uses_default(self):
        """没有 SourceMetadata 字段时 file 应回退到 'unknown file'。"""
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.write(json.dumps({"DetectorName": "GitHub", "Verified": False}) + "\n")
        f.close()
        try:
            findings, _ = generate_report.parse_trufflehog(f.name)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["file"], "unknown file")
        finally:
            os.unlink(f.name)


class TestRetireMalformedInput(unittest.TestCase):
    """retire parser 对 malformed input 必须显性返回错误，不崩溃。"""

    def test_corrupt_json_returns_error(self):
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write("{not valid json")
        f.close()
        try:
            findings, err = generate_report.parse_retire(f.name)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(f.name)

    def test_non_list_shape_returns_error(self):
        """retire 输出必须是 list。"""
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump({"unexpected": "shape"}, f)
        f.close()
        try:
            findings, err = generate_report.parse_retire(f.name)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("expected list", err)
        finally:
            os.unlink(f.name)

    def test_non_dict_component_skipped(self):
        """list 中的非 dict 项应被跳过。"""
        import generate_report

        data = [
            "not a dict",
            None,
            {
                "component": "jquery",
                "version": "1.8.3",
                "path": "/jquery.js",
                "results": [
                    {
                        "vulnerabilities": [
                            {"severity": "high", "identifiers": {"CVE": ["CVE-X"]}}
                        ]
                    }
                ],
            },
        ]
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        try:
            findings, err = generate_report.parse_retire(f.name)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "CVE-X")
        finally:
            os.unlink(f.name)

    def test_missing_cve_identifier_falls_back_to_id(self):
        """没有 CVE identifier 时回退到 retire-{id} 规则名。"""
        import generate_report

        data = [
            {
                "component": "lib",
                "version": "1.0",
                "path": "/lib.js",
                "results": [
                    {
                        "vulnerabilities": [
                            {"id": 42, "severity": "medium", "identifiers": {}}
                        ]
                    }
                ],
            }
        ]
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        try:
            findings, _ = generate_report.parse_retire(f.name)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "retire-42")
        finally:
            os.unlink(f.name)


class TestTrivyVersionParser(unittest.TestCase):
    """parse_trivy_version 把 DB 陈旧信号转成显式 finding（M-1 修复）。"""

    def _write(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_stale_db_emits_medium_finding(self):
        """DB UpdatedAt > 14 天前 → medium finding，含 age 和修复指令。"""
        import generate_report

        path = self._write({"VulnerabilityDB": {"UpdatedAt": "2020-01-01T00:00:00Z"}})
        try:
            findings, err = generate_report.parse_trivy_version(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "medium")
            self.assertEqual(findings[0]["rule"], "stale-vuln-db")
            self.assertIn("trivy db update", findings[0]["message"])
            self.assertIn("days old", findings[0]["message"])
        finally:
            os.unlink(path)

    def test_fresh_db_no_finding(self):
        """DB UpdatedAt 在 14 天内 → 无 finding。"""
        import generate_report
        from datetime import datetime, timezone, timedelta

        recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat().replace(
            "+00:00", "Z"
        )
        path = self._write({"VulnerabilityDB": {"UpdatedAt": recent}})
        try:
            findings, err = generate_report.parse_trivy_version(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_missing_db_info_no_finding(self):
        """无 VulnerabilityDB 字段 → 无 finding，无错误。"""
        import generate_report

        path = self._write({"Version": "0.50.0"})
        try:
            findings, err = generate_report.parse_trivy_version(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_corrupt_json_returns_error(self):
        """corrupt JSON → 返回错误。"""
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write("{not valid json")
        f.close()
        try:
            findings, err = generate_report.parse_trivy_version(f.name)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(f.name)

    def test_future_timestamp_no_finding(self):
        """未来时间戳（时钟偏移）→ 无 finding，不误报。"""
        import generate_report
        from datetime import datetime, timezone, timedelta

        future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat().replace(
            "+00:00", "Z"
        )
        path = self._write({"VulnerabilityDB": {"UpdatedAt": future}})
        try:
            findings, err = generate_report.parse_trivy_version(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
