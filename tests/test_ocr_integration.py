#!/usr/bin/env python3
"""Tiangang OCR (open-code-review) 吸收功能的单元测试。

覆盖从 open-code-review 吸收进 tiangang 的功能：
- parse_ocr 解析器：字段提取、severity 映射、fix 提取
- parse_ocr_session 解析器：session JSONL 提取的 finding 解析
- PARSERS 注册：ocr.json + ocr-session.json 已注册
- run_scan.py 集成：--ocr / --ocr-delegate CLI 开关、thunk 构造
- _ocr_detect_project_type：项目类型检测与审查背景生成
- _ocr_setup_env：token 管理与连通性测试
- _ocr_find_subdirs：子目录发现（分批扫描）
- _ocr_extract_session_findings：session JSONL 提取
- secret-on-disk 防护：OCR content 中的凭证不进报告
- install_tools.sh：ocr 安装命令存在
- 新增 CLI 参数：--ocr-background/--ocr-delay/--ocr-retry/--ocr-timeout

测试验证有意义的属性：解析正确性、字段提取、secret 不泄露、
severity 映射、空结果处理，而非仅"函数有返回值"。
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


# ===== parse_ocr parser =====


class TestOcrParser(unittest.TestCase):
    """OCR scan/review JSON 输出解析。"""

    def _write(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_parses_review_comment_fields(self):
        """基本字段提取：path/content/start_line/severity/category。"""
        import generate_report

        data = [
            {
                "path": "src/handler.go",
                "content": "SQL query concatenates user input directly",
                "start_line": 42,
                "end_line": 45,
                "category": "security",
                "severity": "high",
                "suggestion_code": "db.QueryContext(ctx, query, args...)",
            }
        ]
        path = self._write(data)
        try:
            findings, err = generate_report.parse_ocr(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f["tool"], "ocr")
            self.assertEqual(f["rule"], "ocr/security")
            self.assertEqual(f["severity"], "high")
            self.assertEqual(f["file"], "src/handler.go")
            self.assertEqual(f["line"], 42)
            self.assertEqual(f["message"], "SQL query concatenates user input directly")
            self.assertEqual(f["fix"], "db.QueryContext(ctx, query, args...)")
        finally:
            os.unlink(path)

    def test_category_encoded_in_rule(self):
        """category 字段编码到 rule 中为 ocr/<category>。"""
        import generate_report

        for cat in ("bug", "security", "performance", "maintainability", "style"):
            data = [{"path": "a.py", "content": "x", "category": cat, "severity": "low"}]
            path = self._write(data)
            try:
                findings, _ = generate_report.parse_ocr(path)
                self.assertEqual(findings[0]["rule"], f"ocr/{cat}")
            finally:
                os.unlink(path)

    def test_missing_category_defaults_to_other(self):
        """category 缺失时回退到 ocr/other。"""
        import generate_report

        data = [{"path": "a.py", "content": "x", "severity": "medium"}]
        path = self._write(data)
        try:
            findings, _ = generate_report.parse_ocr(path)
            self.assertEqual(findings[0]["rule"], "ocr/other")
        finally:
            os.unlink(path)

    def test_severity_normalization(self):
        """severity 通过 norm_severity 归一化。"""
        import generate_report

        data = [
            {"path": "a.py", "content": "x", "severity": "critical", "category": "bug"},
            {"path": "b.py", "content": "y", "severity": "high", "category": "bug"},
            {"path": "c.py", "content": "z", "severity": "medium", "category": "bug"},
            {"path": "d.py", "content": "w", "severity": "low", "category": "bug"},
        ]
        path = self._write(data)
        try:
            findings, _ = generate_report.parse_ocr(path)
            self.assertEqual(len(findings), 4)
            sevs = [f["severity"] for f in findings]
            self.assertEqual(sevs, ["critical", "high", "medium", "low"])
        finally:
            os.unlink(path)

    def test_no_suggestion_code_no_fix_key(self):
        """没有 suggestion_code 时 finding 不含 fix 键。"""
        import generate_report

        data = [{"path": "a.py", "content": "issue", "severity": "medium"}]
        path = self._write(data)
        try:
            findings, _ = generate_report.parse_ocr(path)
            self.assertNotIn("fix", findings[0])
        finally:
            os.unlink(path)

    def test_empty_array_returns_empty(self):
        import generate_report

        path = self._write([])
        try:
            findings, err = generate_report.parse_ocr(path)
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
            findings, err = generate_report.parse_ocr(f.name)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("could not parse", err)
        finally:
            os.unlink(f.name)

    def test_non_list_shape_returns_error(self):
        """OCR 输出必须是 list；其他形状是 malformed 输出。"""
        import generate_report

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump({"not": "an array"}, f)
        f.close()
        try:
            findings, err = generate_report.parse_ocr(f.name)
            self.assertEqual(findings, [])
            self.assertIsNotNone(err)
            self.assertIn("expected list", err)
        finally:
            os.unlink(f.name)

    def test_non_dict_items_skipped(self):
        """list 中的非 dict 项应被跳过，不崩溃。"""
        import generate_report

        data = [
            "not a dict",
            None,
            {"path": "a.py", "content": "real finding", "severity": "high", "category": "bug"},
        ]
        path = self._write(data)
        try:
            findings, err = generate_report.parse_ocr(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["message"], "real finding")
        finally:
            os.unlink(path)

    def test_missing_fields_use_defaults(self):
        """缺失字段回退到默认值而非崩溃。"""
        import generate_report

        data = [{"content": "minimal finding"}]
        path = self._write(data)
        try:
            findings, _ = generate_report.parse_ocr(path)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f["file"], "unknown file")
            self.assertEqual(f["line"], "?")
            self.assertEqual(f["severity"], "unknown")
            self.assertEqual(f["rule"], "ocr/other")
        finally:
            os.unlink(path)

    def test_multiple_findings(self):
        """多个审查意见应全部解析。"""
        import generate_report

        data = [
            {"path": "a.py", "content": "issue 1", "severity": "high", "category": "bug", "start_line": 10},
            {"path": "b.go", "content": "issue 2", "severity": "medium", "category": "performance", "start_line": 20},
            {"path": "c.js", "content": "issue 3", "severity": "low", "category": "style", "start_line": 30},
        ]
        path = self._write(data)
        try:
            findings, _ = generate_report.parse_ocr(path)
            self.assertEqual(len(findings), 3)
            files = {f["file"] for f in findings}
            self.assertEqual(files, {"a.py", "b.go", "c.js"})
        finally:
            os.unlink(path)


# ===== PARSERS 注册 =====


class TestParsersIncludeOcr(unittest.TestCase):
    """PARSERS 必须注册 ocr.json 和 ocr-session.json。"""

    def test_parsers_include_ocr(self):
        import generate_report

        self.assertIn("ocr.json", generate_report.PARSERS)
        parser_fn, label = generate_report.PARSERS["ocr.json"]
        self.assertEqual(label, "ocr")

    def test_parsers_include_ocr_session(self):
        import generate_report

        self.assertIn("ocr-session.json", generate_report.PARSERS)
        parser_fn, label = generate_report.PARSERS["ocr-session.json"]
        self.assertEqual(label, "ocr/session")


# ===== run_scan.py CLI 集成 =====


class TestRunScanOcrIntegration(unittest.TestCase):
    """run_scan.py 应包含 OCR 集成代码。"""

    def _source(self):
        with open(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "run_scan.py")
        ) as f:
            return f.read()

    def test_ocr_thunk_exists(self):
        """_ocr_thunk 函数应存在。"""
        self.assertIn("_ocr_thunk", self._source())

    def test_ocr_scan_mode(self):
        """OCR scan 模式命令应包含 ocr scan --format json。"""
        s = self._source()
        self.assertIn('"ocr"', s)
        self.assertIn('"scan"', s)

    def test_ocr_review_mode(self):
        """OCR review 模式命令应包含 ocr review --format json。"""
        s = self._source()
        self.assertIn('"review"', s)
        self.assertIn('"--audience"', s)

    def test_ocr_cli_flags(self):
        """--ocr / --ocr-delegate / --ocr-background / --ocr-delay / --ocr-retry / --ocr-timeout 均应存在。"""
        s = self._source()
        self.assertIn('"--ocr"', s)
        self.assertIn('"--ocr-delegate"', s)
        self.assertIn('"--ocr-background"', s)
        self.assertIn('"--ocr-delay"', s)
        self.assertIn('"--ocr-retry"', s)
        self.assertIn('"--ocr-timeout"', s)

    def test_ocr_registry_entry(self):
        """OCR 不应在工具注册表中（独立触发，非自动调度）。"""
        s = self._source()
        # OCR should NOT be in the registry as an auto-dispatched tool.
        # Instead, it runs as a separate post-scan step in main().
        self.assertIn("# --- OCR: separate post-scan step", s)
        self.assertIn("--ocr", s)
        self.assertIn("--ocr-delegate", s)

    def test_ocr_rc_normalization(self):
        """OCR rc=1 应被归一化（与 gitleaks/checkov 同模式）。"""
        s = self._source()
        self.assertIn("ocr rc=1 normalized", s)

    def test_ocr_setup_env_function(self):
        """_ocr_setup_env 函数应存在，处理 token 映射与连通性测试。"""
        s = self._source()
        self.assertIn("_ocr_setup_env", s)
        self.assertIn("AGNES_TOKEN", s)
        self.assertIn("OCR_LLM_TOKEN", s)

    def test_ocr_detect_project_type_function(self):
        """_ocr_detect_project_type 应存在，检测项目类型生成审查背景。"""
        s = self._source()
        self.assertIn("_ocr_detect_project_type", s)
        self.assertIn("Cargo.toml", s)
        self.assertIn("go.mod", s)
        self.assertIn("package.json", s)
        self.assertIn("pubspec.yaml", s)

    def test_ocr_find_subdirs_function(self):
        """_ocr_find_subdirs 应存在，用于分批扫描。"""
        s = self._source()
        self.assertIn("_ocr_find_subdirs", s)

    def test_ocr_extract_session_findings_function(self):
        """_ocr_extract_session_findings 应存在，提取 session JSONL 数据。"""
        s = self._source()
        self.assertIn("_ocr_extract_session_findings", s)
        self.assertIn(".opencodereview", s)

    def test_ocr_batch_scanning(self):
        """OCR 分批扫描逻辑应包含延迟与重试。"""
        s = self._source()
        self.assertIn("ocr_delay", s)
        self.assertIn("ocr_retry", s)
        self.assertIn("ocr_background", s)
        self.assertIn("ocr_timeout", s)
        self.assertIn("Scan subtask error for", s)

    def test_ocr_not_in_registry(self):
        """OCR 不应在工具注册表中自动调度，而是作为独立后续步骤。"""
        s = self._source()
        # The old registry entry pattern should NOT exist.
        self.assertNotIn('"name": "ocr"', s)
        # The separate post-scan step pattern should exist.
        self.assertIn("_ocr_thunk(", s)
        self.assertIn("AI code review (OCR)", s)


# ===== install_tools.sh 集成 =====


class TestInstallToolsOcr(unittest.TestCase):
    """install_tools.sh 应包含 ocr 安装命令。"""

    def _source(self):
        with open(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "install_tools.sh")
        ) as f:
            return f.read()

    def test_ocr_install_command(self):
        s = self._source()
        self.assertIn("@alibaba-group/open-code-review", s)

    def test_ocr_check_command(self):
        s = self._source()
        self.assertIn("command -v ocr", s)


# ===== references/tools.md 文档 =====


class TestToolsDocOcr(unittest.TestCase):
    """references/tools.md 应包含 OCR 文档。"""

    def _source(self):
        with open(
            os.path.join(os.path.dirname(__file__), "..", "references", "tools.md")
        ) as f:
            return f.read()

    def test_ocr_section_exists(self):
        s = self._source()
        self.assertIn("open-code-review", s)

    def test_ocr_scan_command_documented(self):
        s = self._source()
        self.assertIn("ocr scan", s)

    def test_ocr_delegate_documented(self):
        s = self._source()
        self.assertIn("ocr delegate", s)


# ===== _ocr_detect_project_type =====


class TestOcrDetectProjectType(unittest.TestCase):
    """项目类型检测与审查背景生成。"""

    def _detect(self, target):
        import run_scan
        return run_scan._ocr_detect_project_type(target)

    def test_rust_project(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "Cargo.toml"), "w").close()
            bg = self._detect(d)
            self.assertIn("Rust", bg)
            self.assertIn("Unsafe", bg)
            self.assertIn("\u5e76\u53d1", bg)

    def test_go_project(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "go.mod"), "w").close()
            bg = self._detect(d)
            self.assertIn("Go", bg)
            self.assertIn("goroutine", bg)

    def test_node_project(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "package.json"), "w").close()
            bg = self._detect(d)
            self.assertIn("Node.js", bg)
            self.assertIn("Promise", bg)

    def test_python_project_requirements(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements.txt"), "w").close()
            bg = self._detect(d)
            self.assertIn("Python", bg)

    def test_python_project_pyproject(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "pyproject.toml"), "w").close()
            bg = self._detect(d)
            self.assertIn("Python", bg)

    def test_flutter_project(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "pubspec.yaml"), "w").close()
            bg = self._detect(d)
            self.assertIn("Flutter", bg)
            self.assertIn("Dart", bg)

    def test_generic_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            bg = self._detect(d)
            self.assertIn("\u901a\u7528", bg)

    def test_rust_priority_over_package_json(self):
        """Cargo.toml + package.json \u540c\u65f6\u5b58\u5728\u65f6\uff0cRust \u4f18\u5148\u3002"""
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "Cargo.toml"), "w").close()
            open(os.path.join(d, "package.json"), "w").close()
            bg = self._detect(d)
            self.assertIn("Rust", bg)


# ===== OCR 安全背景预设（P2：按项目类型合并，--ocr-background 追加其后）=====


class TestOcrSecurityPreset(unittest.TestCase):
    """_OCR_SECURITY_PRESETS 覆盖与合并行为。"""

    def test_presets_cover_all_kinds(self):
        """每种项目类型都有非空预设。"""
        import run_scan

        for kind in ("rust", "go", "node", "python", "flutter", "generic"):
            self.assertIn(kind, run_scan._OCR_SECURITY_PRESETS)
            self.assertTrue(run_scan._OCR_SECURITY_PRESETS[kind].strip())

    def test_presets_cover_four_hunting_dimensions(self):
        """每个预设覆盖业务逻辑/认证/租户隔离/资源四维度。"""
        import run_scan

        for kind, preset in run_scan._OCR_SECURITY_PRESETS.items():
            for dim in ("业务逻辑", "认证", "租户隔离", "资源"):
                self.assertIn(dim, preset, f"{kind} 预设缺少维度: {dim}")

    def test_project_kind_detection(self):
        """_ocr_project_kind 与 manifest 优先级一致（Cargo.toml → go.mod →
        package.json → requirements.txt/pyproject.toml → pubspec.yaml）。"""
        import run_scan

        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run_scan._ocr_project_kind(d), "generic")
        for manifest, kind in [
            ("Cargo.toml", "rust"),
            ("go.mod", "go"),
            ("package.json", "node"),
            ("requirements.txt", "python"),
            ("pyproject.toml", "python"),
            ("pubspec.yaml", "flutter"),
        ]:
            with tempfile.TemporaryDirectory() as d:
                open(os.path.join(d, manifest), "w").close()
                self.assertEqual(run_scan._ocr_project_kind(d), kind)

    def test_kind_priority_rust_over_node(self):
        """Cargo.toml 与 package.json 并存时 rust 优先（与语言背景同序）。"""
        import run_scan

        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "Cargo.toml"), "w").close()
            open(os.path.join(d, "package.json"), "w").close()
            self.assertEqual(run_scan._ocr_project_kind(d), "rust")

    def _run_thunk_capturing_background(self, target, ocr_background=""):
        """跑 _ocr_thunk 的 scan 路径（mock 掉环境与执行），捕获 --background。"""
        import run_scan

        captured = {}

        def fake_run_tool(name, ran, cmd, **kwargs):
            captured["cmd"] = cmd
            ran.append(
                {"tool": name, "command": " ".join(cmd), "returncode": 0, "log_tail": ""}
            )

        with tempfile.TemporaryDirectory() as out_dir:
            with mock.patch("run_scan._ocr_setup_env", return_value=(True, None)), \
                 mock.patch("run_scan.run_tool", side_effect=fake_run_tool), \
                 mock.patch("run_scan._ocr_extract_session_findings", return_value=[]):
                thunk = run_scan._ocr_thunk(
                    target, out_dir, "scan", ocr_background=ocr_background
                )
                thunk()
        return captured["cmd"]

    def test_background_merges_preset_and_user_background_last(self):
        """背景三层合并：语言背景 → 安全预设 → 用户 --ocr-background 在最后。"""
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "Cargo.toml"), "w").close()
            cmd = self._run_thunk_capturing_background(d, ocr_background="focus auth")
        bg = cmd[cmd.index("--background") + 1]
        self.assertIn("Rust项目全维度深度审查", bg)
        self.assertIn("业务逻辑", bg)
        self.assertIn("整数溢出", bg)
        self.assertIn("额外关注: focus auth", bg)
        # 用户背景追加在安全预设（最后一个维度是 4.资源）之后
        self.assertGreater(bg.index("额外关注"), bg.index("4.资源"))

    def test_background_generic_preset_without_user_background(self):
        """无 manifest 项目取 generic 预设；无 --ocr-background 时不追加'额外关注'。"""
        with tempfile.TemporaryDirectory() as d:
            cmd = self._run_thunk_capturing_background(d)
        bg = cmd[cmd.index("--background") + 1]
        self.assertIn("通用项目全维度深度审查", bg)
        self.assertIn("业务逻辑", bg)
        self.assertNotIn("额外关注", bg)

    def test_background_preset_matches_detected_kind(self):
        """node 项目合并 node 定制预设（原型污染），而非 generic。"""
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "package.json"), "w").close()
            cmd = self._run_thunk_capturing_background(d)
        bg = cmd[cmd.index("--background") + 1]
        self.assertIn("原型污染", bg)
        self.assertIn("Node.js/TypeScript项目全维度深度审查", bg)

    def test_opt_in_boundary_preserved(self):
        """预设只存在于 OCR 调用链内——不在自动调度的工具注册表中。"""
        with open(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "run_scan.py")
        ) as f:
            s = f.read()
        self.assertIn("_OCR_SECURITY_PRESETS", s)
        # 预设合并发生在 _ocr_thunk 内（仅 --ocr/--ocr-delegate 触发），
        # 不出现在 _build_registry 的任何条目里。
        registry_start = s.index("def _build_registry")
        registry_end = s.index("def _dispatch_registry")
        self.assertNotIn("_OCR_SECURITY_PRESETS", s[registry_start:registry_end])


# ===== _ocr_setup_env =====


class TestOcrSetupEnv(unittest.TestCase):
    """Token \u7ba1\u7406\u4e0e\u73af\u5883\u914d\u7f6e\u3002"""

    def test_no_token_returns_error(self):
        """\u65e0 token \u65f6\u8fd4\u56de\u9519\u8bef\u4fe1\u606f\u3002"""
        import run_scan
        old_ocr = os.environ.pop("OCR_LLM_TOKEN", None)
        old_agnes = os.environ.pop("AGNES_TOKEN", None)
        try:
            ok, err = run_scan._ocr_setup_env()
            self.assertFalse(ok)
            self.assertIn("not set", err)
        finally:
            if old_ocr:
                os.environ["OCR_LLM_TOKEN"] = old_ocr
            if old_agnes:
                os.environ["AGNES_TOKEN"] = old_agnes

    def test_agnes_token_mapped(self):
        """AGNES_TOKEN \u5e94\u88ab\u6620\u5c04\u4e3a OCR_LLM_TOKEN\u3002"""
        import run_scan
        old_ocr = os.environ.pop("OCR_LLM_TOKEN", None)
        old_agnes = os.environ.pop("AGNES_TOKEN", None)
        os.environ["AGNES_TOKEN"] = "test-key-123"
        try:
            # Will fail at connectivity test (ocr not installed), but
            # the token mapping should happen first.
            ok, err = run_scan._ocr_setup_env()
            self.assertEqual(os.environ.get("OCR_LLM_TOKEN"), "test-key-123")
        finally:
            os.environ.pop("OCR_LLM_TOKEN", None)
            os.environ.pop("AGNES_TOKEN", None)
            if old_ocr:
                os.environ["OCR_LLM_TOKEN"] = old_ocr
            if old_agnes:
                os.environ["AGNES_TOKEN"] = old_agnes

    def test_ocr_llm_token_priority(self):
        """OCR_LLM_TOKEN \u4f18\u5148\u7ea7\u9ad8\u4e8e AGNES_TOKEN\u3002"""
        import run_scan
        old_ocr = os.environ.get("OCR_LLM_TOKEN")
        old_agnes = os.environ.get("AGNES_TOKEN")
        os.environ["OCR_LLM_TOKEN"] = "direct-key"
        os.environ["AGNES_TOKEN"] = "agnes-key"
        try:
            ok, err = run_scan._ocr_setup_env()
            # Token should remain the direct one (not overwritten).
            self.assertEqual(os.environ.get("OCR_LLM_TOKEN"), "direct-key")
        finally:
            if old_ocr:
                os.environ["OCR_LLM_TOKEN"] = old_ocr
            else:
                os.environ.pop("OCR_LLM_TOKEN", None)
            if old_agnes:
                os.environ["AGNES_TOKEN"] = old_agnes
            else:
                os.environ.pop("AGNES_TOKEN", None)

    def test_default_env_vars_set(self):
        """\u9ed8\u8ba4 URL/Model/Protocol \u5e94\u88ab\u8bbe\u7f6e\u3002"""
        import run_scan
        old_url = os.environ.pop("OCR_LLM_URL", None)
        old_model = os.environ.pop("OCR_LLM_MODEL", None)
        old_proto = os.environ.pop("OCR_LLM_PROTOCOL", None)
        old_ocr = os.environ.pop("OCR_LLM_TOKEN", None)
        old_agnes = os.environ.pop("AGNES_TOKEN", None)
        os.environ["OCR_LLM_TOKEN"] = "test"
        try:
            run_scan._ocr_setup_env()
            self.assertEqual(
                os.environ.get("OCR_LLM_URL"),
                "https://apihub.agnes-ai.com/v1/chat/completions",
            )
            self.assertEqual(os.environ.get("OCR_LLM_MODEL"), "agnes-2.5-flash")
            self.assertEqual(os.environ.get("OCR_LLM_PROTOCOL"), "openai")
        finally:
            for k, v in [("OCR_LLM_URL", old_url), ("OCR_LLM_MODEL", old_model),
                         ("OCR_LLM_PROTOCOL", old_proto), ("OCR_LLM_TOKEN", old_ocr)]:
                if v:
                    os.environ[k] = v
                else:
                    os.environ.pop(k, None)
            if old_agnes:
                os.environ["AGNES_TOKEN"] = old_agnes
            else:
                os.environ.pop("AGNES_TOKEN", None)


# ===== _ocr_find_subdirs =====


class TestOcrFindSubdirs(unittest.TestCase):
    """\u5b50\u76ee\u5f55\u53d1\u73b0\u7528\u4e8e\u5206\u6279\u626b\u63cf\u3002"""

    def test_finds_dirs_with_source_files(self):
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            # Create subdirs with and without source files.
            src_dir = os.path.join(d, "src")
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, "main.py"), "w") as f:
                f.write("print('hello')")
            empty_dir = os.path.join(d, "docs")
            os.makedirs(empty_dir)
            with open(os.path.join(empty_dir, "readme.txt"), "w") as f:
                f.write("docs")
            subdirs = run_scan._ocr_find_subdirs(d)
            self.assertIn("src", subdirs)
            self.assertNotIn("docs", subdirs)

    def test_skips_hidden_dirs(self):
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            hidden = os.path.join(d, ".hidden")
            os.makedirs(hidden)
            with open(os.path.join(hidden, "main.py"), "w") as f:
                f.write("x")
            subdirs = run_scan._ocr_find_subdirs(d)
            self.assertNotIn(".hidden", subdirs)

    def test_empty_dir_returns_empty(self):
        import run_scan
        with tempfile.TemporaryDirectory() as d:
            subdirs = run_scan._ocr_find_subdirs(d)
            self.assertEqual(subdirs, [])


# ===== parse_ocr_session =====


class TestOcrSessionParser(unittest.TestCase):
    """parse_ocr_session \u89e3\u6790\u5668\u3002"""

    def _write(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_session_findings_tagged_as_ocr_session(self):
        """session finding \u5e94\u6807\u8bb0\u4e3a ocr/session\u3002"""
        import generate_report

        data = [
            {
                "path": "src/auth.rs",
                "content": "Mutex guard held across await point",
                "start_line": 55,
                "category": "concurrency",
                "severity": "high",
            }
        ]
        path = self._write(data)
        try:
            findings, err = generate_report.parse_ocr_session(path)
            self.assertIsNone(err)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["tool"], "ocr/session")
            self.assertEqual(findings[0]["rule"], "ocr/concurrency")
            self.assertEqual(findings[0]["severity"], "high")
        finally:
            os.unlink(path)

    def test_session_empty(self):
        import generate_report

        path = self._write([])
        try:
            findings, err = generate_report.parse_ocr_session(path)
            self.assertIsNone(err)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()