# SPDX-License-Identifier: AGPL-3.0-only
"""Tests du patch in-place de l'overlay d'annotations (.asm + mapping.db)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.annotations.overlay_patch import (
    VERDICT_PATCHED,
    VERDICT_REBUILD,
    VERDICT_UNCHANGED,
    apply_overlay_mutation,
)
from backends.static.disasm import mapping_db


def _write_artifacts(tmp, asm_lines, lines, functions=None):
    mapping_json = os.path.join(tmp, "sample.disasm.mapping.json")
    asm_path = os.path.join(tmp, "sample.disasm.asm")
    Path(asm_path).write_text("\n".join(asm_lines), encoding="utf-8")
    db_path = mapping_db.mapping_db_path_for(mapping_json)
    mapping_db.write_mapping_db(
        db_path,
        {"binary": "/bin/fake", "lines": lines, "functions": functions or []},
    )
    return mapping_json, asm_path, db_path


class TestOverlayPatch(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_patch_adds_comment_on_line_without_suffix(self):
        mapping_json, asm_path, db_path = _write_artifacts(
            self.tmp,
            ["  0x401000:  mov eax, 1", "  0x401004:  ret"],
            [
                {"addr": "0x401000", "line": 1},
                {"addr": "0x401004", "line": 2},
            ],
        )
        verdict = apply_overlay_mutation(mapping_json, "0x401004", comment="sortie")
        self.assertEqual(verdict, VERDICT_PATCHED)
        asm = Path(asm_path).read_text(encoding="utf-8").split("\n")
        self.assertEqual(asm[1], "  0x401004:  ret  ; sortie")
        self.assertEqual(asm[0], "  0x401000:  mov eax, 1")
        entries = mapping_db.query_lines_by_addr(db_path, "0x401004")
        self.assertEqual(entries[0]["comment"], "sortie")

    def test_patch_replaces_comment_preserving_src_and_hints(self):
        stack = [{"kind": "var", "name": "x", "location": "rbp-0x8"}]
        mapping_json, asm_path, _ = _write_artifacts(
            self.tmp,
            ["  0x401000:  mov eax, 1  ; main.c:12 | ancien | var x @ rbp-0x8"],
            [
                {
                    "addr": "0x401000",
                    "line": 1,
                    "comment": "ancien",
                    "stack_hints": stack,
                }
            ],
        )
        verdict = apply_overlay_mutation(mapping_json, "0x401000", comment="nouveau")
        self.assertEqual(verdict, VERDICT_PATCHED)
        self.assertEqual(
            Path(asm_path).read_text(encoding="utf-8"),
            "  0x401000:  mov eax, 1  ; main.c:12 | nouveau | var x @ rbp-0x8",
        )

    def test_delete_removes_comment_but_keeps_hints(self):
        stack = [{"kind": "arg", "name": "argc", "location": "edi"}]
        mapping_json, asm_path, _ = _write_artifacts(
            self.tmp,
            ["  0x401000:  mov eax, edi  ; a-virer | arg argc @ edi"],
            [
                {
                    "addr": "0x401000",
                    "line": 1,
                    "comment": "a-virer",
                    "stack_hints": stack,
                }
            ],
        )
        verdict = apply_overlay_mutation(mapping_json, "0x401000", deleted=True)
        self.assertEqual(verdict, VERDICT_PATCHED)
        self.assertEqual(
            Path(asm_path).read_text(encoding="utf-8"),
            "  0x401000:  mov eax, edi  ; arg argc @ edi",
        )

    def test_rename_requires_rebuild(self):
        mapping_json, _, _ = _write_artifacts(
            self.tmp,
            ["  0x401000:  ret"],
            [{"addr": "0x401000", "line": 1}],
        )
        self.assertEqual(
            apply_overlay_mutation(mapping_json, "0x401000", name="entry_point"),
            VERDICT_REBUILD,
        )

    def test_delete_of_baked_rename_requires_rebuild(self):
        mapping_json, _, _ = _write_artifacts(
            self.tmp,
            ["; -- function rename @ 0x401000 --", "mon_entree:", "  0x401000:  ret"],
            [{"addr": "0x401000", "line": 3, "label": "mon_entree"}],
            functions=[{"addr": "0x401000", "name": "entry0"}],
        )
        self.assertEqual(
            apply_overlay_mutation(mapping_json, "0x401000", deleted=True),
            VERDICT_REBUILD,
        )

    def test_rename_equal_to_original_function_name_is_patchable(self):
        mapping_json, asm_path, _ = _write_artifacts(
            self.tmp,
            ["; -- function rename @ 0x401000 --", "entry0:", "  0x401000:  ret"],
            [{"addr": "0x401000", "line": 3, "label": "entry0"}],
            functions=[{"addr": "0x401000", "name": "entry0"}],
        )
        verdict = apply_overlay_mutation(
            mapping_json, "0x401000", name="entry0", comment="point d entree"
        )
        self.assertEqual(verdict, VERDICT_PATCHED)
        asm = Path(asm_path).read_text(encoding="utf-8").split("\n")
        self.assertEqual(asm[2], "  0x401000:  ret  ; point d entree")

    def test_none_fields_mean_unchanged(self):
        mapping_json, _, _ = _write_artifacts(
            self.tmp,
            ["; -- function rename @ 0x401000 --", "mon_entree:", "  0x401000:  ret"],
            [{"addr": "0x401000", "line": 3, "label": "mon_entree"}],
            functions=[{"addr": "0x401000", "name": "entry0"}],
        )
        # Commentaire seul fourni : le rename baké n'est pas affecté.
        verdict = apply_overlay_mutation(mapping_json, "0x401000", comment="note")
        self.assertEqual(verdict, VERDICT_PATCHED)

    def test_mapping_line_mismatch_falls_back_to_rebuild(self):
        mapping_json, _, _ = _write_artifacts(
            self.tmp,
            ["  0x401000:  mov eax, 1", "  0x401004:  ret"],
            [{"addr": "0x401004", "line": 1}],
        )
        self.assertEqual(
            apply_overlay_mutation(mapping_json, "0x401004", comment="x"),
            VERDICT_REBUILD,
        )

    def test_identical_comment_and_unknown_addr_are_unchanged(self):
        mapping_json, _, _ = _write_artifacts(
            self.tmp,
            ["  0x401000:  ret  ; pareil"],
            [{"addr": "0x401000", "line": 1, "comment": "pareil"}],
        )
        self.assertEqual(
            apply_overlay_mutation(mapping_json, "0x401000", comment="pareil"),
            VERDICT_UNCHANGED,
        )
        self.assertEqual(
            apply_overlay_mutation(mapping_json, "0xdead", comment="x"),
            VERDICT_UNCHANGED,
        )

    def test_missing_artifacts_are_unchanged(self):
        mapping_json = os.path.join(self.tmp, "missing.disasm.mapping.json")
        self.assertEqual(
            apply_overlay_mutation(mapping_json, "0x401000", comment="x"),
            VERDICT_UNCHANGED,
        )


if __name__ == "__main__":
    unittest.main()
