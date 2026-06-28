# SPDX-License-Identifier: AGPL-3.0-only
"""Tests de la fonction de scoring décompilateur et des détails qualité.

Valide :
- la fonction pure `_score_decompile_code` (comportement des métriques et poids)
- la cohérence des scores sur le corpus de fixtures synthétiques
- que `_build_function_quality_details` produit le bon format
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.decompile.decompile import (
    _build_function_quality_details,
    _score_decompile_code,
)

CORPUS_DIR = Path(__file__).parent / "fixtures" / "decompile_corpus"


# ── Tests unitaires de _score_decompile_code ────────────────────────────────


class TestScoreDecompileCode(unittest.TestCase):
    def test_empty_code_score_is_zero(self):
        result = _score_decompile_code("")
        self.assertEqual(result["score"], 0)

    def test_empty_code_has_all_metric_keys(self):
        result = _score_decompile_code("")
        expected_keys = {
            "lines",
            "calls",
            "control",
            "type_hints",
            "casts",
            "placeholders",
            "gotos",
            "low_level",
            "warnings",
            "matched_calls",
            "missed_calls",
        }
        self.assertFalse(
            expected_keys - result["metrics"].keys(), msg="Missing metric keys"
        )

    def test_no_quality_param(self):
        """_score_decompile_code ne doit pas accepter de paramètre 'quality'."""
        import inspect

        sig = inspect.signature(_score_decompile_code)
        self.assertNotIn("quality", sig.parameters)

    def test_clean_code_scores_positively(self):
        code = (
            "int32_t main(int32_t argc, char **argv) {\n"
            "    if (argc > 1) {\n"
            '        printf("%d\\n", fibonacci((int32_t)strtol(argv[1], NULL, 10)));\n'
            "        return 0;\n"
            "    }\n"
            '    puts("usage: fib <n>");\n'
            "    return 1;\n"
            "}\n"
        )
        self.assertGreater(_score_decompile_code(code)["score"], 20)

    def test_calls_reward_score(self):
        code = "int func() {\n  foo();\n  bar();\n  return 0;\n}\n"
        result = _score_decompile_code(code, [])
        self.assertGreater(result["score"], 0)
        self.assertGreater(result["metrics"]["calls"], 0)

    def test_gotos_are_penalized(self):
        no_goto = "int f(int x) { if (x > 0) { return x; } return 0; }\n"
        with_goto = (
            "int f(int x) { goto lbl;\nlbl: if (x > 0) { return x; } return 0; }\n"
        )
        self.assertGreater(
            _score_decompile_code(no_goto)["score"],
            _score_decompile_code(with_goto)["score"],
        )

    def test_warnings_are_heavily_penalized(self):
        base = "int f(int x) { return x; }\n"
        with_warns = (
            "int f(int x) {\n"
            "  // WARNING: undefined behavior\n"
            "  // WARNING: bad cast\n"
            "  return x;\n}\n"
        )
        r_base = _score_decompile_code(base)
        r_warns = _score_decompile_code(with_warns)
        self.assertGreater(r_base["score"], r_warns["score"])
        self.assertEqual(r_warns["metrics"]["warnings"], 2)

    def test_placeholders_are_penalized(self):
        clean = "int foo(int x) { int y = x * 2; return y; }\n"
        noisy = "int foo(int param_1) { int local_8 = param_1 * 2; return local_8; }\n"
        r_clean = _score_decompile_code(clean)
        r_noisy = _score_decompile_code(noisy)
        self.assertGreater(r_clean["score"], r_noisy["score"])
        # param_1 × 2 (signature + body) + local_8 × 2 (decl + return) = 4
        self.assertEqual(r_noisy["metrics"]["placeholders"], 4)

    def test_type_hints_reward_precision(self):
        untyped = "auto foo(auto a, auto b) { return a + b; }\n"
        typed = "int32_t foo(int32_t a, int32_t b) { return a + b; }\n"
        self.assertGreater(
            _score_decompile_code(typed)["score"],
            _score_decompile_code(untyped)["score"],
        )

    def test_expected_calls_boost_score(self):
        code = "int f(void) { malloc(8); free(NULL); return 0; }\n"
        r_no_hint = _score_decompile_code(code, expected_calls=None)
        r_matched = _score_decompile_code(code, expected_calls=["malloc", "free"])
        r_missed = _score_decompile_code(
            code, expected_calls=["malloc", "free", "realloc"]
        )
        self.assertGreater(r_matched["score"], r_no_hint["score"])
        self.assertGreater(r_matched["score"], r_missed["score"])
        self.assertEqual(r_matched["metrics"]["matched_calls"], 2)
        self.assertEqual(r_missed["metrics"]["missed_calls"], 1)

    def test_low_level_symbols_penalized(self):
        clean = "int call_malloc(int n) { return malloc(n) != NULL; }\n"
        noisy = "int FUN_401050(int n) { return DWORD[DAT_601030] != 0; }\n"
        self.assertGreater(
            _score_decompile_code(clean)["score"],
            _score_decompile_code(noisy)["score"],
        )
        self.assertGreater(_score_decompile_code(noisy)["metrics"]["low_level"], 0)

    def test_noisy_code_scores_below_clean(self):
        clean = "int32_t foo(int32_t x) {\n    if (x > 0) { return x * 2; }\n    return -1;\n}\n"
        noisy = (
            "int foo(int param_1) {\n"
            "    goto lbl1;\n"
            "    goto lbl2;\n"
            "    // WARNING: undefined behavior\n"
            "    // WARNING: possible overflow\n"
            "    *(int*)0 = (int)param_1;\n"
            "    local_10 = local_18;\n"
            "lbl1:\nlbl2:\n"
            "    return param_1;\n"
            "}\n"
        )
        self.assertGreater(
            _score_decompile_code(clean)["score"],
            _score_decompile_code(noisy)["score"],
        )


# ── Tests sur le corpus de fixtures ─────────────────────────────────────────


class TestDecompileCorpus(unittest.TestCase):
    """Valide que le scorer produit des scores dans les plages attendues du corpus."""

    def _load_corpus(self):
        if not CORPUS_DIR.exists():
            self.skipTest(f"Corpus directory not found: {CORPUS_DIR}")
        files = sorted(CORPUS_DIR.glob("*.json"))
        if not files:
            self.skipTest("No corpus fixtures found")
        return files

    def test_corpus_fixtures_all_in_range(self):
        files = self._load_corpus()
        failures = []
        for path in files:
            with open(path, encoding="utf-8") as f:
                sample = json.load(f)
            score = _score_decompile_code(sample["code"])["score"]
            lo, hi = sample["score_min"], sample["score_max"]
            if not (lo <= score <= hi):
                failures.append(
                    f"{path.name}: score={score} not in [{lo},{hi}] (quality={sample['quality']})"
                )
        if failures:
            self.fail("Corpus score failures:\n" + "\n".join(failures))

    def test_corpus_high_beats_medium(self):
        files = self._load_corpus()
        high_scores = []
        medium_scores = []
        for path in files:
            with open(path, encoding="utf-8") as f:
                s = json.load(f)
            score = _score_decompile_code(s["code"])["score"]
            if s["quality"] == "high":
                high_scores.append(score)
            elif s["quality"] == "medium":
                medium_scores.append(score)
        if not high_scores or not medium_scores:
            self.skipTest("Need at least one high and one medium fixture")
        self.assertGreater(
            min(high_scores),
            max(medium_scores),
            msg=f"Worst high ({min(high_scores)}) should beat best medium ({max(medium_scores)})",
        )

    def test_corpus_medium_beats_low_and_bad(self):
        files = self._load_corpus()
        medium_scores = []
        low_bad_scores = []
        for path in files:
            with open(path, encoding="utf-8") as f:
                s = json.load(f)
            score = _score_decompile_code(s["code"])["score"]
            if s["quality"] == "medium":
                medium_scores.append(score)
            elif s["quality"] in ("low", "bad"):
                low_bad_scores.append(score)
        if not medium_scores or not low_bad_scores:
            self.skipTest("Need medium and low/bad fixtures")
        self.assertGreater(
            min(medium_scores),
            max(low_bad_scores),
            msg=f"Worst medium ({min(medium_scores)}) should beat best low/bad ({max(low_bad_scores)})",
        )

    def test_corpus_bad_scores_are_negative_or_zero(self):
        files = self._load_corpus()
        for path in files:
            with open(path, encoding="utf-8") as f:
                s = json.load(f)
            if s["quality"] != "bad":
                continue
            score = _score_decompile_code(s["code"])["score"]
            self.assertLessEqual(
                score, 0, msg=f"{path.name}: bad fixture scored {score} > 0"
            )


# ── Tests _build_function_quality_details ───────────────────────────────────


class TestBuildFunctionQualityDetails(unittest.TestCase):
    def _make_attempt(self, decompiler, code=None, error=None):
        if error:
            return {"decompiler": decompiler, "error": error}
        return {"decompiler": decompiler, "code": code or "int f() { return 0; }"}

    def test_strategy_is_always_auto_first(self):
        a = self._make_attempt("tool_a")
        qd = _build_function_quality_details([a], a)
        self.assertEqual(qd["strategy"], "auto_first")

    def test_selected_backend_matches_selected_attempt(self):
        a = self._make_attempt("tool_a")
        b = self._make_attempt("tool_b")
        qd = _build_function_quality_details([a, b], b)
        self.assertEqual(qd["selected_backend"], "tool_b")
        selected_entry = next(e for e in qd["backends"] if e["decompiler"] == "tool_b")
        self.assertTrue(selected_entry["selected"])

    def test_failed_attempt_has_ok_false(self):
        a = self._make_attempt("tool_a", error="timeout")
        qd = _build_function_quality_details([a], None)
        self.assertFalse(qd["backends"][0]["ok"])
        self.assertEqual(qd["backends"][0]["error"], "timeout")

    def test_successful_attempt_has_score_and_metrics(self):
        a = self._make_attempt(
            "tool_a", code="int32_t foo(int32_t x) { return x * 2; }\n"
        )
        qd = _build_function_quality_details([a], a)
        entry = qd["backends"][0]
        self.assertTrue(entry["ok"])
        self.assertIn("score", entry)
        self.assertIn("metrics", entry)
        self.assertIsInstance(entry["score"], int)

    def test_expected_calls_improve_selected_score(self):
        code = "int f(void) { malloc(8); free(NULL); return 0; }\n"
        a1 = self._make_attempt("tool_a", code=code)
        qd_no = _build_function_quality_details([a1], a1, expected_calls=None)
        a2 = self._make_attempt("tool_a", code=code)
        qd_hit = _build_function_quality_details(
            [a2], a2, expected_calls=["malloc", "free"]
        )
        self.assertGreater(qd_hit["selected_score"], qd_no["selected_score"])

    def test_no_attempts_returns_empty_backends(self):
        qd = _build_function_quality_details([], None)
        self.assertEqual(qd["backends"], [])
        self.assertEqual(qd["selected_backend"], "")

    def test_multiple_tools_only_one_selected(self):
        a = self._make_attempt("tool_a")
        b = self._make_attempt("tool_b")
        qd = _build_function_quality_details([a, b], a)
        selected_count = sum(1 for e in qd["backends"] if e.get("selected"))
        self.assertEqual(selected_count, 1)


if __name__ == "__main__":
    unittest.main()
