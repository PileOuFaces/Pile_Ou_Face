# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for stdin/scanf helpers extracted from the Unicorn tracer."""

from __future__ import annotations

import unittest

from backends.dynamic.engine.unicorn.argv_stdin import (
    _consume_stream_literal,
    _consume_stream_token,
    _consume_stdin_bytes,
    _consume_stdin_line,
    _iterate_scanf_tokens,
)


class TestArgvStdinHelpers(unittest.TestCase):
    def test_consumes_stdin_bytes_and_lines_without_losing_position(self):
        state = {"stdin_data": b"AAAA\nBBBB", "stdin_pos": 0}

        self.assertEqual(_consume_stdin_bytes(state, 2), b"AA")
        self.assertEqual(state["stdin_pos"], 2)
        self.assertEqual(_consume_stdin_line(state, 10), b"AA\n")
        self.assertEqual(state["stdin_pos"], 5)

    def test_token_consumption_supports_width_and_scansets(self):
        state = {"file_data": b"include -42\n", "file_pos": 0}

        self.assertEqual(
            _consume_stream_token(state, "file_data", "file_pos", scanset="a-zA-Z_"),
            b"include",
        )
        self.assertTrue(_consume_stream_literal(state, "file_data", "file_pos", " "))
        self.assertEqual(
            _consume_stream_token(state, "file_data", "file_pos", scanset="-0-9"),
            b"-42",
        )

    def test_iterates_scanf_tokens_deterministically(self):
        self.assertEqual(
            _iterate_scanf_tokens("%4s %2[0-9] %%"),
            [
                {"kind": "conversion", "value": "s", "width": 4, "assign": True},
                {"kind": "whitespace"},
                {"kind": "conversion", "value": "[", "width": 2, "assign": True, "scanset": "0-9"},
                {"kind": "whitespace"},
                {"kind": "literal", "value": "%"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
