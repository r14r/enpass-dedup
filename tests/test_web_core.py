"""Pure-core unit tests use synthetic (non-secret) data only."""
import copy
import json
import unittest

from enpass_dedupe import UserError, groups_for
from web_core import csv_report, export_clean_json, group_id, parse_upload, selections_to_plan, summary


def entry(uid, title="Example", password="local-test-only", note="", updated_at=100):
    return {
        "uuid": uid, "title": title, "category": "login", "updated_at": updated_at,
        "note": note, "fields": [
            {"type": "username", "value": "user@example.test"},
            {"type": "password", "value": password},
            {"type": "url", "value": "https://example.test"},
        ],
    }


class WebCoreTests(unittest.TestCase):
    def setUp(self):
        self.items = [entry("a"), entry("b", updated_at=200),
                      entry("c", note="critical notes"), entry("d", password="changed")]
        self.doc = {"items": self.items, "folders": [{"name": "custom"}], "other": {"a": 1}}
        self.raw = json.dumps(self.doc).encode()
        self.groups = groups_for(self.items)

    def test_valid_upload(self):
        self.assertEqual(parse_upload(self.raw), self.doc)
        with self.assertRaises(UserError):
            parse_upload(b'{"items":[1]}')
        with self.assertRaises(UserError):
            parse_upload(b'not json')
        with self.assertRaises(UserError):
            parse_upload(b'x' * (25 * 1024 * 1024 + 1))

    def test_exact_default_manual_unselected(self):
        plan, skipped = selections_to_plan(self.raw, self.items, self.groups, {})
        self.assertEqual(skipped, 0)
        self.assertEqual(len(plan["decisions"]), 1)
        self.assertEqual(plan["decisions"][0]["kind"], "exact")
        self.assertEqual(set(plan["decisions"][0]["remove"]), {0})
        clean = json.loads(export_clean_json(self.doc, self.raw, plan))
        self.assertEqual(clean["items"], self.items[1:])
        self.assertEqual(clean["folders"], self.doc["folders"])
        self.assertEqual(summary(self.items, self.groups, plan)["removed"], 1)

    def test_manual_conflict_supersedes_exact(self):
        conflicts = [g for g in self.groups if g.kind == "conflict"]
        self.assertEqual(len(conflicts), 1)
        selection = {group_id(conflicts[0]): {"approved": True, "keep": 3}}
        plan, skipped = selections_to_plan(self.raw, self.items, self.groups, selection)
        self.assertEqual(skipped, 1)
        self.assertEqual(len(plan["decisions"]), 1)
        self.assertEqual(plan["decisions"][0]["remove"], [0, 1, 2])

    def test_manual_overlap_blocked(self):
        # Fuzzy title can overlap a password-conflict group.
        items = [entry("a", title="Demo Portal"), entry("b", title="Demo PortaI"),
                 entry("c", title="Demo Portal", password="changed")]
        raw = json.dumps({"items": items}).encode()
        groups = groups_for(items, fuzzy_threshold=0.8)
        manual = [g for g in groups if g.kind in ("possible", "conflict")]
        self.assertGreaterEqual(len(manual), 2)
        selections = {group_id(g): {"approved": True, "keep": g.indices[0]} for g in manual}
        with self.assertRaises(UserError):
            selections_to_plan(raw, items, groups, selections, fuzzy_threshold=0.8)

    def test_source_change_rejected(self):
        plan, _ = selections_to_plan(self.raw, self.items, self.groups, {})
        changed = copy.deepcopy(self.doc)
        changed["items"][1]["note"] = "modified"
        with self.assertRaises(UserError):
            export_clean_json(changed, json.dumps(changed).encode(), plan)

    def test_no_password_or_formula_in_csv(self):
        items = [entry("1", title="=HYPERLINK(A1)"), entry("2", title="=HYPERLINK(A1)", updated_at=200)]
        raw = json.dumps({"items": items}).encode()
        groups = groups_for(items)
        plan, _ = selections_to_plan(raw, items, groups, {})
        csv = csv_report(items, groups, plan).decode()
        self.assertIn("'=HYPERLINK(A1)", csv)
        self.assertNotIn("local-test-only", csv)
        self.assertNotIn("user@example.test", csv)

    def test_invalid_keep_and_no_default_manual_remove(self):
        group = next(g for g in self.groups if g.kind == "conflict")
        with self.assertRaises(UserError):
            selections_to_plan(self.raw, self.items, self.groups,
                               {group_id(group): {"approved": True, "keep": 99}})


if __name__ == "__main__":
    unittest.main()


class TestSourceRouting(unittest.TestCase):
    def test_supported_import_formats_case_insensitive(self):
        from web_core import input_kind
        self.assertEqual(input_kind("data.json"), "json")
        self.assertEqual(input_kind("data.JSON"), "json")
        self.assertEqual(input_kind("backup.enpassbackup"), "enpassbackup")
        self.assertEqual(input_kind("backup.ENPASSBACKUP"), "enpassbackup")

    def test_unknown_format_rejected(self):
        from web_core import input_kind
        from enpass_dedupe import UserError
        for name in ("", "file.csv", "file.enpassbackup.json.zip"):
            with self.assertRaises(UserError):
                input_kind(name)

    def test_encrypted_backups_are_not_json(self):
        from web_core import parse_upload, backup_restore_steps
        from enpass_dedupe import UserError
        with self.assertRaises(UserError):
            parse_upload(b"\x00encrypted backup\xfa")
        steps = backup_restore_steps()
        self.assertEqual(len(steps), 5)
        self.assertIn("Exportieren", " ".join(steps))
