"""Offline functional tests; ONLY synthetic data, no real credentials."""
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("enpass_dedupe.py")
spec = importlib.util.spec_from_file_location("enpass_dedupe", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def item(uid, title, user, pw, modified, note="", category="login", host="example.test", **extras):
    return {"uuid": uid, "title": title, "category": category, "note": note,
            "updated_at": modified,
            "fields": [{"type": "username", "value": user},
                       {"type": "password", "value": pw, "sensitive": 1},
                       {"type": "url", "value": f"https://{host}"}],
            **extras}


class EnpassDedupeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.input = self.path / "vault.json"
        self.items = [
            item("a", "Example", "alice", "abcdABC!", 1500000000),
            item("b", "Example", "alice", "abcdABC!", 1600000000),  # exact (ignoring UUID/timestamp)
            item("c", "Example", "alice", "abcdABC!", 1700000000, note="NEVER DROP ME"),
            item("d", "Example", "alice", "changed-pass", 1800000000, note="NEW PASSWORD"),
            item("e", "Different", "bob", "Pass1", 1700000000),
            item("f", "Different", "bob", "Pass1", 1700000001, archived=1),
            item("g", "Sample", "clara", "Pass2", 1700000000, trashed=1),
            item("h", "Sample", "clara", "Pass2", 1700000001, trashed=1),
        ]
        self.source = {"folders": [{"name": "Work", "uuid": "f001"}], "items": self.items, "format": "enpass"}
        self.input.write_text(json.dumps(self.source), encoding="utf-8")

    def cmd(self, *args, ok=True):
        proc = subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              text=True, capture_output=True)
        if ok:
            self.assertEqual(proc.returncode, 0, proc.stderr)
        else:
            self.assertNotEqual(proc.returncode, 0)
        return proc

    def test_group_types_and_flags(self):
        groups = mod.groups_for(self.items)
        self.assertEqual([g.kind for g in groups], ["exact", "conflict"])
        self.assertEqual(groups[0].indices, (0, 1))
        self.assertEqual(groups[1].indices, (0, 1, 2, 3))
        groups_all = mod.groups_for(self.items, include_trashed=True, include_archived=True)
        self.assertEqual([g.kind for g in groups_all].count("exact"), 2)

    def test_safe_pipeline(self):
        plan = self.path / "plan.json"
        output = self.path / "clean.json"
        self.cmd("plan", self.input, "--output", plan)
        data = json.loads(plan.read_text())
        self.assertEqual(data["decisions"], [{"kind": "exact", "keep": 1, "remove": [0]}])
        self.cmd("apply", self.input, "--plan", plan, "--output", output, "--yes")
        self.cmd("verify", self.input, "--plan", plan, "--output", output)
        clean = json.loads(output.read_text())
        self.assertEqual(clean["folders"], self.source["folders"])
        self.assertEqual(clean["format"], self.source["format"])
        self.assertEqual(clean["items"], self.items[1:])
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(plan.stat().st_mode & 0o777, 0o600)

    def test_password_change_is_not_auto_removed(self):
        plan = self.path / "plan.json"
        self.cmd("plan", self.input, "--output", plan)
        decisions = json.loads(plan.read_text())["decisions"]
        self.assertEqual({i for d in decisions for i in d["remove"]}, {0})
        self.assertEqual({self.items[i]["uuid"] for i in range(2, 4)}, {"c", "d"})

    def test_credentials_policy_requires_explicit_risk_acceptance(self):
        plan = self.path / "plan.json"
        self.cmd("plan", self.input, "--output", plan,
                 "--policy", "same-credentials", ok=False)
        self.assertFalse(plan.exists())

    def test_changed_source_rejected(self):
        plan = self.path / "plan.json"
        output = self.path / "clean.json"
        self.cmd("plan", self.input, "--output", plan)
        edited = copy.deepcopy(self.source)
        edited["items"][0]["note"] = "secret change"
        self.input.write_text(json.dumps(edited))
        proc = self.cmd("apply", self.input, "--plan", plan, "--output", output, "--yes", ok=False)
        self.assertIn("SHA-256", proc.stderr)
        self.assertFalse(output.exists())

    def test_no_overwrite_input_or_existing_output(self):
        plan = self.path / "plan.json"
        self.cmd("plan", self.input, "--output", plan)
        self.cmd("apply", self.input, "--plan", plan, "--output", self.input, "--yes", ok=False)
        self.cmd("apply", self.input, "--plan", plan, "--output", plan, "--yes", ok=False)

    def test_wrong_shape(self):
        self.input.write_text('{"passwords": []}')
        self.cmd("scan", self.input, ok=False)

    def test_credentials_but_different_metadata(self):
        few = [item("a", "Service", "alice", "ABC123", 10, note=""),
               item("b", "Service", "alice", "ABC123", 20, note="note")]
        groups = mod.groups_for(few)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].kind, "credentials")
        self.assertEqual(mod.unique_field(item("x", "A", "b", "pAss", 1), "password"), "pAss")
        self.assertNotEqual(mod.unique_field(item("x", "A", "b", "pAss", 1), "password"), "pass")

    def test_same_credentials_policy_keeps_richest(self):
        self.items[3]["fields"][1]["value"] = "abcdABC!"
        self.input.write_text(json.dumps(self.source))
        plan_path = self.path / "plan.json"
        self.cmd("plan", self.input, "--output", plan_path, "--policy", "same-credentials",
                 "--acknowledge-metadata-loss", "--keep", "richest")
        plan = json.loads(plan_path.read_text())
        removed = mod.validate_plan(plan, self.input.read_bytes(), self.items)
        self.assertEqual(len(removed), 3)
        self.assertEqual(set(range(4)) - removed, {3})

    def test_fuzzy_and_csv_formula_protection(self):
        data = [item("1", "=DemoPortal", "user", "test", 12),
                item("2", "=DemoPortaI", "user", "test", 13)]
        self.assertTrue(any(g.kind == "possible" for g in mod.groups_for(data, fuzzy_threshold=0.7)))
        self.assertEqual(mod.safe_csv_cell("=HYPERLINK(1,2)"), "'=HYPERLINK(1,2)")
        self.assertEqual(mod.safe_csv_cell("normal"), "normal")

    def test_password_case_difference_with_multiple_fields(self):
        x = item("x", "A", "b", "pass", 1)
        x["fields"].append({"type": "password", "value": "PASS"})
        self.assertEqual(mod.unique_field(x, "password"), "")
        self.assertEqual(mod.record_key(x), None)


if __name__ == "__main__":
    unittest.main()
