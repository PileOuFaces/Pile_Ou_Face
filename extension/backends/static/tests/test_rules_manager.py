# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.rules.rules_manager."""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.rules.rules_manager import RulesManager


class TestRulesManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Path(self.tmpdir) / "storage"
        self._old_storage_env = os.environ.get("POF_STORAGE_DIR")
        os.environ["POF_STORAGE_DIR"] = str(self.storage)

    def tearDown(self):
        if self._old_storage_env is None:
            os.environ.pop("POF_STORAGE_DIR", None)
        else:
            os.environ["POF_STORAGE_DIR"] = self._old_storage_env
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _mgr(self, global_cfg=None):
        return RulesManager(self.tmpdir, global_cfg)

    def _global_config_path(self):
        return str(Path(self.tmpdir) / ".state" / "rules-config.json")

    def test_list_empty_when_no_rules_dir(self):
        self.assertEqual(self._mgr().list_rules(), [])

    def test_add_yara_rule_creates_file(self):
        rule_id = self._mgr().add_user_rule(
            "test.yar", "rule Foo { condition: false }", "yara"
        )
        self.assertEqual(rule_id, "user:yara:test.yar")
        f = self.storage / "rules" / "yara" / "test.yar"
        self.assertTrue(f.exists())
        self.assertFalse((Path(self.tmpdir) / ".pile-ou-face").exists())

    def test_add_capa_rule_creates_file(self):
        rule_id = self._mgr().add_user_rule("my.yml", "name: x", "capa")
        self.assertEqual(rule_id, "user:capa:my.yml")
        f = self.storage / "rules" / "capa" / "my.yml"
        self.assertTrue(f.exists())
        self.assertFalse((Path(self.tmpdir) / ".pile-ou-face").exists())

    def test_without_storage_env_uses_local_rules_dir(self):
        os.environ["POF_STORAGE_DIR"] = ""
        rule_id = self._mgr().add_user_rule(
            "local.yar", "rule Local { condition: false }", "yara"
        )

        self.assertEqual(rule_id, "user:yara:local.yar")
        self.assertTrue((Path(self.tmpdir) / "rules" / "yara" / "local.yar").exists())
        self.assertFalse((Path(self.tmpdir) / ".pile-ou-face").exists())

    def test_add_rule_rejects_path_traversal_name(self):
        with self.assertRaises(ValueError):
            self._mgr().add_user_rule(
                "../escape.yar", "rule X { condition: false }", "yara"
            )

    def test_update_rule_rejects_path_traversal_name(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        with self.assertRaises(ValueError):
            mgr.update_user_rule(
                "user:yara:test.yar",
                "../renamed.yar",
                "rule Foo { condition: true }",
            )

    def test_list_returns_added_rule_enabled_by_default(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        rules = mgr.list_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "user:yara:test.yar")
        self.assertTrue(rules[0]["enabled"])

    def test_toggle_disables_rule(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        mgr.toggle_rule("user:yara:test.yar", False)
        self.assertFalse(mgr.list_rules()[0]["enabled"])

    def test_toggle_re_enables_rule(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        mgr.toggle_rule("user:yara:test.yar", False)
        mgr.toggle_rule("user:yara:test.yar", True)
        self.assertTrue(mgr.list_rules()[0]["enabled"])

    def test_delete_user_rule(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        mgr.delete_user_rule("user:yara:test.yar")
        self.assertEqual(mgr.list_rules(), [])

    def test_delete_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            self._mgr().delete_user_rule("user:yara:ghost.yar")

    def test_get_active_yara_paths_only_enabled(self):
        mgr = self._mgr()
        mgr.add_user_rule("a.yar", "rule A { condition: false }", "yara")
        mgr.add_user_rule("b.yar", "rule B { condition: false }", "yara")
        mgr.toggle_rule("user:yara:b.yar", False)
        paths = mgr.get_active_yara_paths()
        self.assertEqual(len(paths), 1)
        self.assertTrue(str(paths[0]).endswith("a.yar"))

    def test_get_active_yara_paths_with_extra(self):
        mgr = self._mgr()
        mgr.add_user_rule("a.yar", "rule A { condition: false }", "yara")
        extra = Path(self.tmpdir) / "extra.yar"
        extra.write_text("rule Extra { condition: false }", encoding="utf-8")
        paths = mgr.get_active_yara_paths(extra_path=extra)
        self.assertEqual(len(paths), 2)

    def test_inject_capa_only_active(self):
        mgr = self._mgr()
        mgr.add_user_rule("active.yml", "name: active", "capa")
        mgr.add_user_rule("inactive.yml", "name: inactive", "capa")
        mgr.toggle_rule("user:capa:inactive.yml", False)
        capa_dir = Path(self.tmpdir) / "capa-rules"
        capa_dir.mkdir()
        mgr.inject_active_capa_rules(capa_dir)
        injected = list((capa_dir / "custom").iterdir())
        self.assertEqual(len(injected), 1)
        self.assertEqual(injected[0].name, "active.yml")

    def test_global_config_default_overridden_by_project(self):
        global_cfg = Path(self.tmpdir) / "global.json"
        global_cfg.write_text(
            json.dumps(
                {"version": 1, "rules": {"user:yara:test.yar": {"enabled": False}}}
            ),
            encoding="utf-8",
        )
        mgr = self._mgr(str(global_cfg))
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        # Global dit disabled
        self.assertFalse(mgr.list_rules()[0]["enabled"])
        # Override projet le réactive
        mgr.toggle_rule("user:yara:test.yar", True)
        self.assertTrue(mgr.list_rules()[0]["enabled"])

    def test_add_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            self._mgr().add_user_rule("bad.txt", "content", "invalid")

    def test_get_rule_returns_content_and_scope(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        rule = mgr.get_rule("user:yara:test.yar")
        self.assertEqual(rule["name"], "test.yar")
        self.assertEqual(rule["scope"], "project")
        self.assertIn("condition: false", rule["content"])

    def test_update_rule_rewrites_content(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        same_id = mgr.update_user_rule(
            "user:yara:test.yar",
            "test.yar",
            "rule Foo { condition: true }",
        )
        self.assertEqual(same_id, "user:yara:test.yar")
        rule = mgr.get_rule("user:yara:test.yar")
        self.assertIn("condition: true", rule["content"])

    def test_update_rule_can_rename_and_preserve_toggle(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        mgr.toggle_rule("user:yara:test.yar", False)
        new_id = mgr.update_user_rule(
            "user:yara:test.yar",
            "renamed.yar",
            "rule Foo { condition: false }",
        )
        self.assertEqual(new_id, "user:yara:renamed.yar")
        listed = {rule["id"]: rule for rule in mgr.list_rules()}
        self.assertIn("user:yara:renamed.yar", listed)
        self.assertFalse(listed["user:yara:renamed.yar"]["enabled"])

    def test_add_global_yara_rule_creates_file_in_global_storage(self):
        mgr = self._mgr(self._global_config_path())
        rule_id = mgr.add_user_rule(
            "global_rule.yar",
            "rule GlobalRule { condition: false }",
            "yara",
            "global",
        )
        self.assertEqual(rule_id, "global:yara:global_rule.yar")
        target = Path(self.tmpdir) / ".state" / "rules" / "yara" / "global_rule.yar"
        self.assertTrue(target.exists())

    def test_list_rules_includes_global_and_project_scopes(self):
        mgr = self._mgr(self._global_config_path())
        mgr.add_user_rule("project_rule.yar", "rule P { condition: false }", "yara")
        mgr.add_user_rule(
            "global_rule.yar", "rule G { condition: false }", "yara", "global"
        )
        listed = sorted(
            ((rule["id"], rule["scope"]) for rule in mgr.list_rules()),
            key=lambda item: item[0],
        )
        self.assertEqual(
            listed,
            [
                ("global:yara:global_rule.yar", "global"),
                ("user:yara:project_rule.yar", "project"),
            ],
        )

    def test_toggle_global_rule_uses_global_config(self):
        global_cfg = Path(self._global_config_path())
        mgr = self._mgr(str(global_cfg))
        mgr.add_user_rule(
            "global_rule.yar", "rule G { condition: false }", "yara", "global"
        )
        mgr.toggle_rule("global:yara:global_rule.yar", False)
        cfg = json.loads(global_cfg.read_text(encoding="utf-8"))
        self.assertFalse(cfg["rules"]["global:yara:global_rule.yar"]["enabled"])
        listed = {rule["id"]: rule for rule in mgr.list_rules()}
        self.assertFalse(listed["global:yara:global_rule.yar"]["enabled"])

    def test_get_active_yara_paths_includes_global_and_project(self):
        mgr = self._mgr(self._global_config_path())
        mgr.add_user_rule("project_rule.yar", "rule P { condition: false }", "yara")
        mgr.add_user_rule(
            "global_rule.yar", "rule G { condition: false }", "yara", "global"
        )
        mgr.toggle_rule("user:yara:project_rule.yar", False)
        paths = [path.name for path in mgr.get_active_yara_paths()]
        self.assertEqual(paths, ["global_rule.yar"])

    def test_delete_global_rule_removes_file_and_config_entry(self):
        global_cfg = Path(self._global_config_path())
        mgr = self._mgr(str(global_cfg))
        mgr.add_user_rule(
            "global_rule.yar", "rule G { condition: false }", "yara", "global"
        )
        mgr.toggle_rule("global:yara:global_rule.yar", False)
        mgr.delete_user_rule("global:yara:global_rule.yar")
        target = Path(self.tmpdir) / ".state" / "rules" / "yara" / "global_rule.yar"
        self.assertFalse(target.exists())
        cfg = json.loads(global_cfg.read_text(encoding="utf-8"))
        self.assertNotIn("global:yara:global_rule.yar", cfg.get("rules", {}))


if __name__ == "__main__":
    unittest.main()
