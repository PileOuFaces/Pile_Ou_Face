# SPDX-License-Identifier: AGPL-3.0-only
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loadtest.fixtures import FixtureSpec, build_fixture

HAS_CC = shutil.which("cc") is not None


@unittest.skipUnless(HAS_CC, "cc introuvable")
class TestBuildFixture(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="loadtest-fixture-")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_builds_binary_of_approximately_requested_size(self):
        spec = FixtureSpec(name="tiny", num_functions=3, padding_bytes=200_000)
        path = build_fixture(spec, cache_dir=Path(self._tmpdir))
        self.assertTrue(path.exists())
        # Le fichier final doit au moins contenir le padding demandé
        # (plus le code généré et l'overhead du format binaire).
        self.assertGreaterEqual(path.stat().st_size, 200_000)

    def test_caches_and_does_not_rebuild_second_call(self):
        spec = FixtureSpec(name="tiny2", num_functions=2, padding_bytes=50_000)
        cache_dir = Path(self._tmpdir)
        path1 = build_fixture(spec, cache_dir=cache_dir)
        mtime1 = path1.stat().st_mtime
        path2 = build_fixture(spec, cache_dir=cache_dir)
        self.assertEqual(path1, path2)
        self.assertEqual(mtime1, path2.stat().st_mtime)

    def test_different_specs_produce_different_files(self):
        cache_dir = Path(self._tmpdir)
        path_a = build_fixture(FixtureSpec(name="a", num_functions=2, padding_bytes=10_000), cache_dir=cache_dir)
        path_b = build_fixture(FixtureSpec(name="b", num_functions=5, padding_bytes=10_000), cache_dir=cache_dir)
        self.assertNotEqual(path_a, path_b)


if __name__ == "__main__":
    unittest.main()
