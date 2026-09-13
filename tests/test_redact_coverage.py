#!/usr/bin/env python3
"""redact.py edge case 测试，补齐覆盖率到 95%+。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


class TestRedactSecretsNonString(unittest.TestCase):
    """redact_secrets 对非字符串 / 空字符串必须原样返回（line 89 分支）。"""

    def test_none_input_returned_unchanged(self):
        """None 输入应原样返回 None，不抛异常。"""
        from redact import redact_secrets

        self.assertIsNone(redact_secrets(None))

    def test_non_string_input_returned_unchanged(self):
        """int / list / dict 输入应原样返回，不抛异常。"""
        from redact import redact_secrets

        for val in (42, 3.14, ["a", "b"], {"k": "v"}, True):
            self.assertEqual(redact_secrets(val), val)

    def test_empty_string_returned_unchanged(self):
        """空字符串应原样返回，不进入 pattern 循环。"""
        from redact import redact_secrets

        self.assertEqual(redact_secrets(""), "")


if __name__ == "__main__":
    unittest.main()
