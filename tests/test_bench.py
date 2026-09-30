#!/usr/bin/env python3
"""tiangang 扫描器准确率基准（tests/bench + scripts/run_bench.py）的测试。

覆盖两层：
- score()/路径/规则 id 处理的纯单元测试（不需要 semgrep，离线必跑）：
  TP/FN/FP 记账、阴性对照、未声明 finding 记 FP、manifest 越界防护。
- 端到端冒烟（需要 semgrep，缺失时 skip 而非报错）：跑真基准，断言
  TP=4/FN=0/FP=0 的记分卡通过。

测试验证有意义的属性（记账正确性、ground truth 一致性、失败可诊断），
而非仅"脚本退出 0"。
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import run_bench  # noqa: E402

SEMGREP_AVAILABLE = run_bench.shutil.which("semgrep") is not None


def _load_real_manifest():
    with open(os.path.join(REPO_ROOT, "tests", "bench", "manifest.json")) as f:
        return json.load(f)


def _real_fixture_path(bench_dir, exp):
    return run_bench._exp_fixture_path(bench_dir, exp)


class TestRuleIdNormalization(unittest.TestCase):
    """_rule_id：本地配置的 checkId 带 <path>. 前缀，须还原裸规则 id。"""

    def test_strips_local_config_prefix(self):
        self.assertEqual(
            run_bench._rule_id("rules.llm-security.llm-sec-output-to-sql"),
            "llm-sec-output-to-sql",
        )

    def test_bare_id_unchanged(self):
        self.assertEqual(run_bench._rule_id("web-base-cors-wildcard-credentials"),
                         "web-base-cors-wildcard-credentials")

    def test_none_is_safe(self):
        self.assertEqual(run_bench._rule_id(None), "")


class TestFixturePathGuard(unittest.TestCase):
    """manifest 里的 fixture 路径必须存在且不许逃出 bench 目录。"""

    def test_missing_fixture_raises(self):
        with tempfile.TemporaryDirectory() as d:
            bad = {"file": "fixtures/nope.py"}
            with self.assertRaises(FileNotFoundError):
                run_bench._fixture_paths(d, [bad])

    def test_escaping_fixture_raises(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "fixtures"))
            evil = {"file": os.path.join("..", "..", "evil.py")}
            with self.assertRaises(ValueError):
                run_bench._fixture_paths(d, [evil])


class TestScoreAccounting(unittest.TestCase):
    """score()：TP/FN/FP 记账对真实 manifest 做纯函数验证（无 semgrep）。"""

    def setUp(self):
        self.bench_dir = os.path.join(REPO_ROOT, "tests", "bench")
        self.manifest = _load_real_manifest()
        self.exp_by_id = {e["id"]: e for e in self.manifest["expectations"]}

    def _findings(self, *specs):
        return [
            {
                "rule": rule,
                "file": _real_fixture_path(self.bench_dir, self.exp_by_id[eid]),
                "line": line,
            }
            for eid, rule, line in specs
        ]

    def test_all_hits_is_clean_pass(self):
        findings = self._findings(
            ("sql-injection", "llm-sec-output-to-sql", 24),
            ("command-injection", "llm-sec-output-to-shell", 22),
            ("xss-render", "llm-sec-output-to-html-render", 20),
            ("ssti", "llm-sec-output-to-template-render", 22),
        )
        card = run_bench.score(self.bench_dir, self.manifest["expectations"], findings)
        self.assertTrue(card["passed"])
        self.assertEqual((card["tp"], card["fn"], card["fp"]), (4, 0, 0))

    def test_missing_positive_hit_is_fn_fails(self):
        card = run_bench.score(
            self.bench_dir, self.manifest["expectations"], []
        )
        self.assertFalse(card["passed"])
        self.assertEqual((card["tp"], card["fn"], card["fp"]), (0, 4, 0))

    def test_negative_control_hit_is_fp_fails(self):
        findings = self._findings(
            ("negative-control", "llm-sec-output-to-sql", 40),
        )
        card = run_bench.score(self.bench_dir, self.manifest["expectations"], findings)
        self.assertFalse(card["passed"])
        self.assertEqual(card["fp"], 1)

    def test_wrong_rule_on_positive_is_fn_plus_fp(self):
        # 阳性样例被别的规则命中：预期规则没中（FN），多余命中也是过报（FP）。
        findings = self._findings(
            ("sql-injection", "llm-sec-prompt-concat-signal", 24),
        )
        card = run_bench.score(self.bench_dir, self.manifest["expectations"], findings)
        self.assertFalse(card["passed"])
        self.assertEqual((card["fn"], card["fp"]), (4, 1))

    def test_unclaimed_finding_is_fp(self):
        # 落在已知 fixture 上但不匹配任何 expectation 的规则 = 未声明命中。
        findings = self._findings(
            ("sql-injection", "llm-sec-output-to-sql", 24),
            ("sql-injection", "some-other-rule", 10),
        )
        card = run_bench.score(self.bench_dir, self.manifest["expectations"], findings)
        self.assertFalse(card["passed"])
        self.assertEqual(card["fp"], 1)

    def test_scorecard_records_first_hit_line(self):
        findings = self._findings(
            ("sql-injection", "llm-sec-output-to-sql", 24),
        )
        card = run_bench.score(self.bench_dir, self.manifest["expectations"], findings)
        entry = next(e for e in card["expectations"] if e["id"] == "sql-injection")
        self.assertEqual(entry["outcome"], "TP")
        self.assertIn("line 24", entry["detail"][0])


class TestManifestGroundTruth(unittest.TestCase):
    """manifest 自身的完整性：ground truth 声明与文件一一对应。"""

    def test_every_expectation_file_exists_and_in_bench(self):
        bench_dir = os.path.join(REPO_ROOT, "tests", "bench")
        manifest = _load_real_manifest()
        paths = run_bench._fixture_paths(bench_dir, manifest["expectations"])
        self.assertEqual(len(paths), len(manifest["expectations"]))

    def test_positive_expectations_declare_rule_and_cwe(self):
        manifest = _load_real_manifest()
        for exp in manifest["expectations"]:
            if exp.get("negative"):
                self.assertIsNone(exp["expect_rule"])
            else:
                self.assertTrue(exp["expect_rule"], exp["id"])
                self.assertTrue(exp["cwe"], exp["id"])
        # 阴性对照至少一个——没有它基准只能量化召回，量化不了过报。
        self.assertTrue(
            any(e.get("negative") for e in manifest["expectations"])
        )

    def test_declared_rules_exist_on_disk(self):
        manifest = _load_real_manifest()
        for rel in manifest["rules"]:
            self.assertTrue(
                os.path.isfile(os.path.join(REPO_ROOT, rel)), rel
            )


@unittest.skipUnless(SEMGREP_AVAILABLE, "semgrep not installed — bench run skipped")
class TestBenchEndToEnd(unittest.TestCase):
    """端到端：真实 semgrep + 打包规则，记分卡必须 PASS（TP=4/FN=0/FP=0）。"""

    def test_bench_passes(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "run_bench.py")],
            capture_output=True,
            text=True,
            timeout=300,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"bench failed:\n{proc.stdout}\n{proc.stderr}",
        )
        self.assertIn("TP=4", proc.stdout)
        self.assertIn("FN=0", proc.stdout)
        self.assertIn("FP=0", proc.stdout)
        self.assertIn("PASS", proc.stdout)

    def test_bench_json_machine_readable(self):
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(REPO_ROOT, "scripts", "run_bench.py"),
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        card = json.loads(proc.stdout)
        self.assertTrue(card["passed"])
        self.assertEqual(card["tp"], 4)
        self.assertEqual(len(card["expectations"]), 5)


class TestBenchSkipWhenSemgrepMissing(unittest.TestCase):
    """semgrep 缺失时 run_bench 走 SKIP 路径：退出 0 且打印 SKIP（不静默）。"""

    def test_skip_exit_zero_with_marker(self):
        orig = run_bench.shutil.which
        with tempfile.TemporaryDirectory() as d:
            # 用一个不存在 semgrep 的 PATH 隔离真机安装。
            env = dict(os.environ)
            env["PATH"] = d
            proc = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "scripts", "run_bench.py")],
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("SKIP:", proc.stdout)


if __name__ == "__main__":
    unittest.main()
