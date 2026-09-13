#!/usr/bin/env python3
"""Tiangang detect_languages.py 覆盖率测试。

把覆盖率从 24% 提升到 95%+。覆盖 detect() 函数主体（manifest 命中、扩展名
阈值、SKIP_DIRS 过滤、隐藏目录跳过、strong/weak 排序、JS/TS 共享 javascript 桶）
与 main() 函数主体（非目录 exit 1、--json 空/非空输出、文本模式 marker、indent=2）。

main() 测试通过 mock sys.argv 直接调用 dl.main()（in-process，被 coverage 跟踪），
而非 subprocess（subprocess 不被 coverage 跟踪，会导致 main() 覆盖率为 0）。
保留一个 subprocess 烟雾测试验证 CLI 入口可用。

每个测试验证有意义的属性（值、排序、结构、副作用、退出码、JSON 字段内容），
而非仅"函数有返回值"。
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

# 把 tiangang root 加到 sys.path，使 scripts.detect_languages 可作为
# namespace package 导入 — 这样 --cov=scripts/detect_languages 能匹配到模块
TIANGANG_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, TIANGANG_ROOT)

from scripts import detect_languages as dl  # noqa: E402

SCRIPT_PATH = os.path.join(TIANGANG_ROOT, "scripts", "detect_languages.py")


def write_file(path: Path, content: str = "") -> None:
    """在临时目录下创建文件（含父目录）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class TestDetectManifestHit(unittest.TestCase):
    """manifest 文件命中即视为 strong signal，与扩展名文件数无关。"""

    def test_requirements_txt_makes_python_strong(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "requirements.txt")
            ordered, ext_counts, strong = dl.detect(tmp)
            self.assertIn("python", strong)
            self.assertIn("python", ordered)

    def test_multiple_manifests_multiple_strong(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "go.mod")
            write_file(Path(tmp) / "Cargo.toml")
            _, _, strong = dl.detect(tmp)
            self.assertIn("go", strong)
            self.assertIn("rust", strong)

    def test_manifest_overrides_zero_extension_count(self):
        """manifest 即使扩展名文件数为 0，仍应检测出该语言（strong signal）。"""
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "package.json")
            ordered, ext_counts, strong = dl.detect(tmp)
            self.assertIn("javascript", strong)
            self.assertIn("javascript", ordered)
            self.assertEqual(ext_counts.get("javascript", 0), 0)


class TestDetectExtensionThreshold(unittest.TestCase):
    """扩展名文件数低于 MIN_FILE_COUNT 视为噪声，达到阈值才计入 ordered。"""

    def test_below_threshold_not_in_ordered(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(dl.MIN_FILE_COUNT - 1):
                write_file(Path(tmp) / f"a{i}.py")
            ordered, ext_counts, strong = dl.detect(tmp)
            # ext_counts 仍然记录原始计数（用于排序）
            self.assertEqual(ext_counts.get("python", 0), dl.MIN_FILE_COUNT - 1)
            # 但低于阈值不入 ordered
            self.assertNotIn("python", ordered)
            self.assertEqual(strong, [])

    def test_at_threshold_counted_in_ordered(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(dl.MIN_FILE_COUNT):
                write_file(Path(tmp) / f"a{i}.py")
            ordered, ext_counts, strong = dl.detect(tmp)
            self.assertEqual(ext_counts.get("python", 0), dl.MIN_FILE_COUNT)
            self.assertIn("python", ordered)
            self.assertEqual(strong, [])


class TestDetectSkipDirs(unittest.TestCase):
    """SKIP_DIRS 内的目录不参与遍历，扩展名不计入。"""

    def test_all_skip_dirs_filtered(self):
        """每个 SKIP_DIRS 下的 .py 文件都不应被计数。"""
        with tempfile.TemporaryDirectory() as tmp:
            for d in dl.SKIP_DIRS:
                # 在每个被跳过的目录里放足够多（>= MIN_FILE_COUNT+2）的 .py 文件
                for i in range(dl.MIN_FILE_COUNT + 2):
                    write_file(Path(tmp) / d / f"a{i}.py")
            ordered, ext_counts, _ = dl.detect(tmp)
            self.assertNotIn("python", ordered)
            self.assertEqual(ext_counts.get("python", 0), 0)

    def test_node_modules_specifically_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                write_file(Path(tmp) / "node_modules" / f"a{i}.py")
            ordered, ext_counts, _ = dl.detect(tmp)
            self.assertNotIn("python", ext_counts)
            self.assertNotIn("python", ordered)


class TestDetectHiddenDir(unittest.TestCase):
    """以 . 开头但不在 SKIP_DIRS 中的目录也应被跳过。"""

    def test_hidden_dir_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                write_file(Path(tmp) / ".hidden" / f"a{i}.py")
            ordered, ext_counts, _ = dl.detect(tmp)
            self.assertNotIn("python", ext_counts)
            self.assertNotIn("python", ordered)

    def test_nested_hidden_dir_skipped(self):
        """嵌套的隐藏目录也要被跳过。"""
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                write_file(Path(tmp) / "src" / ".cache" / f"a{i}.py")
            # src 下还放一个合法文件以保证 src 本身被遍历
            write_file(Path(tmp) / "src" / "keep.txt")
            ordered, ext_counts, _ = dl.detect(tmp)
            self.assertNotIn("python", ext_counts)


class TestDetectSorting(unittest.TestCase):
    """ordered 排序：strong 优先，再按文件数降序。"""

    def test_strong_before_weak(self):
        """python 5 个 .py（weak）+ go.mod（strong）→ go 在前。"""
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                write_file(Path(tmp) / f"a{i}.py")
            write_file(Path(tmp) / "go.mod")
            ordered, _, strong = dl.detect(tmp)
            self.assertEqual(ordered[0], "go")
            self.assertIn("python", ordered)
            self.assertEqual(strong, ["go"])

    def test_strong_internal_sort_by_file_count(self):
        """两个 strong 语言内部按文件数降序排。"""
        with tempfile.TemporaryDirectory() as tmp:
            # python：3 .py + pyproject.toml → strong，3 files
            for i in range(3):
                write_file(Path(tmp) / f"a{i}.py")
            write_file(Path(tmp) / "pyproject.toml")
            # java：5 .java + pom.xml → strong，5 files
            for i in range(5):
                write_file(Path(tmp) / f"b{i}.java")
            write_file(Path(tmp) / "pom.xml")
            ordered, ext_counts, strong = dl.detect(tmp)
            self.assertEqual(set(strong), {"python", "java"})
            # 两个都在 strong，按文件数降序：java(5) > python(3)
            self.assertEqual(ordered[0], "java")
            self.assertEqual(ordered[1], "python")
            self.assertEqual(ext_counts["java"], 5)
            self.assertEqual(ext_counts["python"], 3)

    def test_weak_internal_sort_by_file_count(self):
        """两个 weak 语言（无 manifest）按文件数降序排。"""
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):  # python 5
                write_file(Path(tmp) / f"a{i}.py")
            for i in range(3):  # rust 3
                write_file(Path(tmp) / f"b{i}.rs")
            ordered, _, _ = dl.detect(tmp)
            self.assertEqual(ordered[0], "python")
            self.assertEqual(ordered[1], "rust")


class TestDetectJavascriptBucket(unittest.TestCase):
    """JS/TS 扩展名共享 javascript 桶（同 SAST 工具集）。"""

    def test_ts_variants_map_to_javascript(self):
        with tempfile.TemporaryDirectory() as tmp:
            for ext in (".ts", ".tsx", ".mts", ".cts"):
                write_file(Path(tmp) / f"a{ext}")
            ordered, ext_counts, _ = dl.detect(tmp)
            # 4 个文件，超过 MIN_FILE_COUNT=3
            self.assertIn("javascript", ordered)
            self.assertEqual(ext_counts.get("javascript", 0), 4)

    def test_js_variants_map_to_javascript(self):
        with tempfile.TemporaryDirectory() as tmp:
            for ext in (".js", ".jsx", ".mjs", ".cjs"):
                write_file(Path(tmp) / f"a{ext}")
            ordered, ext_counts, _ = dl.detect(tmp)
            self.assertIn("javascript", ordered)
            self.assertEqual(ext_counts.get("javascript", 0), 4)


class TestDetectReturnShape(unittest.TestCase):
    """detect 返回三元组 (ordered list, ext_counts dict, strong sorted list)。"""

    def test_return_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "go.mod")
            ordered, ext_counts, strong = dl.detect(tmp)
            self.assertIsInstance(ordered, list)
            self.assertIsInstance(ext_counts, dict)
            self.assertIsInstance(strong, list)
            # strong 必须是已排序的（detect 返回 sorted(strong)）
            self.assertEqual(strong, sorted(strong))

    def test_empty_dir_returns_empty_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            ordered, ext_counts, strong = dl.detect(tmp)
            self.assertEqual(ordered, [])
            self.assertEqual(ext_counts, {})
            self.assertEqual(strong, [])


# ---------------------------------------------------------------------------
# main() tests — 直接调用 dl.main()（mock sys.argv + 捕获 stdout/stderr）
# 这样 coverage 能跟踪到 main() 函数体的每一行。subprocess 调用不被 coverage
# 跟踪，会导致 main() 覆盖率为 0。
# ---------------------------------------------------------------------------


def run_main(argv):
    """调用 dl.main(argv)，返回 (return_value, stdout, stderr, exit_code)。

    exit_code 为 None 表示正常返回（无 SystemExit），否则为 SystemExit.code。
    """
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    exit_code = None
    return_value = None
    with mock.patch("sys.argv", argv), redirect_stdout(out_buf), redirect_stderr(err_buf):
        try:
            return_value = dl.main()
        except SystemExit as e:
            exit_code = e.code
    return return_value, out_buf.getvalue(), err_buf.getvalue(), exit_code


class TestMainNonDir(unittest.TestCase):
    """非目录输入 → stderr + exit 1。"""

    def test_nonexistent_path_exits_1(self):
        _, stdout, stderr, exit_code = run_main(
            ["detect_languages.py", "/nonexistent/path/does/not/exist"]
        )
        self.assertEqual(exit_code, 1)
        self.assertIn("is not a directory", stderr)
        # 失败时不应有 stdout 输出
        self.assertEqual(stdout, "")

    def test_file_path_exits_1(self):
        """文件不是目录也应 exit 1。"""
        with tempfile.NamedTemporaryFile() as f:
            _, stdout, stderr, exit_code = run_main(["detect_languages.py", f.name])
        self.assertEqual(exit_code, 1)
        self.assertIn("is not a directory", stderr)
        self.assertEqual(stdout, "")


class TestMainJsonMode(unittest.TestCase):
    """--json 模式输出有效 JSON，含 languages/file_counts/manifest_matches 三键。"""

    def test_json_empty_when_no_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, stdout, _, exit_code = run_main(["detect_languages.py", tmp, "--json"])
        self.assertIsNone(exit_code)  # 正常返回
        data = json.loads(stdout)
        self.assertEqual(data["languages"], [])
        self.assertEqual(data["file_counts"], {})
        self.assertEqual(data["manifest_matches"], [])

    def test_json_with_manifest_has_all_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "go.mod")
            write_file(Path(tmp) / "Cargo.toml")
            _, stdout, _, exit_code = run_main(["detect_languages.py", tmp, "--json"])
        self.assertIsNone(exit_code)
        data = json.loads(stdout)
        # 三键齐全
        self.assertEqual(
            set(data.keys()), {"languages", "file_counts", "manifest_matches"}
        )
        # 强信号语言都出现
        self.assertIn("go", data["languages"])
        self.assertIn("rust", data["languages"])
        self.assertEqual(set(data["manifest_matches"]), {"go", "rust"})

    def test_json_indent_is_2(self):
        """有语言时 --json 输出必须用 indent=2 缩进。"""
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "go.mod")
            _, stdout, _, _ = run_main(["detect_languages.py", tmp, "--json"])
        # indent=2 的 JSON 第一行是 {，第二行是 '  "languages": ['（恰好 2 空格）
        lines = stdout.splitlines()
        self.assertGreater(len(lines), 1)
        self.assertEqual(lines[0], "{")
        self.assertEqual(
            lines[1],
            '  "languages": [',
            f"expected indent=2, got line: {lines[1]!r}",
        )


class TestMainTextMode(unittest.TestCase):
    """文本模式输出（无 --json）。"""

    def test_text_fallback_when_no_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, stdout, _, exit_code = run_main(["detect_languages.py", tmp])
        self.assertIsNone(exit_code)
        self.assertIn("Falling back to semgrep", stdout)

    def test_text_marker_for_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "go.mod")
            _, stdout, _, exit_code = run_main(["detect_languages.py", tmp])
        self.assertIsNone(exit_code)
        self.assertIn("go (manifest file found)", stdout)

    def test_text_marker_for_file_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                write_file(Path(tmp) / f"a{i}.py")
            _, stdout, _, exit_code = run_main(["detect_languages.py", tmp])
        self.assertIsNone(exit_code)
        # 文本模式输出形如 "python (5 files)"
        self.assertIn("python (5 files)", stdout)


class TestMaxDepth(unittest.TestCase):
    """detect(max_depth=N): limits traversal depth."""

    def test_max_depth_zero_unlimited(self):
        """max_depth=0 means unlimited — nested files are found."""
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(3):
                write_file(Path(tmp) / "sub" / "deep" / f"a{i}.py")
            ordered, _, _ = dl.detect(tmp, max_depth=0)
        self.assertIn("python", ordered)

    def test_max_depth_one_finds_root_only(self):
        """max_depth=1 only scans root-level files."""
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "root.py")
            write_file(Path(tmp) / "sub" / "deep.py")
            ordered, ext_counts, _ = dl.detect(tmp, max_depth=1)
        # root.py alone is below MIN_FILE_COUNT (3), so python not in ordered
        self.assertEqual(ext_counts.get("python", 0), 1)

    def test_max_depth_limits_traversal(self):
        """max_depth=2 should scan one level of subdirectories."""
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(3):
                write_file(Path(tmp) / f"sub" / f"f{i}.py")
            write_file(Path(tmp) / "sub" / "deep" / "nested.py")
            ordered, ext_counts, _ = dl.detect(tmp, max_depth=2)
        # depth=2 means root(0) -> sub(1) -> deep(2) is excluded
        self.assertEqual(ext_counts.get("python", 0), 3)
        self.assertIn("python", ordered)


class TestPermissionError(unittest.TestCase):
    """detect(): PermissionError in directory traversal is handled gracefully."""

    def test_permission_error_does_not_crash(self):
        """When inner file ops hit PermissionError, detection continues without crashing."""
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                write_file(Path(tmp) / f"f{i}.py")
            # Mock os.walk to yield the real root, then raise PermissionError
            # on the next iteration (simulating an unreadable subdirectory).
            original_walk = list(os.walk(tmp))
            call_log = [0]
            def mock_walk(top, **kwargs):
                for entry in original_walk:
                    call_log[0] += 1
                    if call_log[0] > 1:
                        # Simulate PermissionError inside the for-loop body
                        raise PermissionError("mocked")
                    yield entry
            with mock.patch("os.walk", side_effect=mock_walk):
                ordered, ext_counts, _ = dl.detect(tmp)
            self.assertIn("python", ordered)


class TestIaCDetection(unittest.TestCase):
    """New IaC language detection via extensions and manifests."""

    def test_tf_extension_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(3):
                write_file(Path(tmp) / f"main{i}.tf")
            ordered, _, _ = dl.detect(tmp)
        self.assertIn("iac", ordered)

    def test_main_tf_manifest_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "main.tf")
            _, _, strong = dl.detect(tmp)
        self.assertIn("iac", strong)

    def test_dockerfile_manifest_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_file(Path(tmp) / "Dockerfile")
            _, _, strong = dl.detect(tmp)
        self.assertIn("iac", strong)


class TestMainCliSmoke(unittest.TestCase):
    """端到端烟雾测试：验证脚本可作为 CLI 运行（覆盖 if __name__ == '__main__'）。"""

    def test_script_runs_as_cli(self):
        """python3 detect_languages.py <empty-dir> 应正常退出。"""
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, SCRIPT_PATH, tmp],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Falling back to semgrep", result.stdout)


if __name__ == "__main__":
    unittest.main()
