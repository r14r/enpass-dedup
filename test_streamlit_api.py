"""Regression checks for Streamlit API compatibility without importing Streamlit."""

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class StreamlitApiTests(unittest.TestCase):
    def test_no_deprecated_use_container_width_arguments(self):
        tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    self.assertNotEqual(keyword.arg, "use_container_width")

    def test_full_width_widgets_use_stretch(self):
        tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        seen = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"dataframe", "download_button", "button"}:
                continue
            width = [kw.value for kw in node.keywords if kw.arg == "width"]
            self.assertEqual(len(width), 1, f"Missing width for {node.func.attr} at line {node.lineno}")
            self.assertIsInstance(width[0], ast.Constant)
            self.assertEqual(width[0].value, "stretch")
            seen += 1
        self.assertGreater(seen, 0)


if __name__ == "__main__":
    unittest.main()
