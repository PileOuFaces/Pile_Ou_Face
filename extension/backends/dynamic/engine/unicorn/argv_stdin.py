# SPDX-License-Identifier: AGPL-3.0-only
"""stdin stream and scanf token helpers for the Unicorn tracer."""

from __future__ import annotations


def _consume_stream_bytes(state: dict, data_key: str, pos_key: str, n: int) -> bytes:
    if n <= 0:
        return b""
    data = state.get(data_key, b"")
    pos = int(state.get(pos_key, 0))
    if pos >= len(data):
        return b""
    chunk = data[pos : pos + n]
    state[pos_key] = pos + len(chunk)
    return chunk


def _consume_stream_line(
    state: dict, data_key: str, pos_key: str, max_len: int
) -> bytes:
    if max_len <= 0:
        return b""
    data = state.get(data_key, b"")
    pos = int(state.get(pos_key, 0))
    if pos >= len(data):
        return b""
    end = min(len(data), pos + max_len)
    chunk = data[pos:end]
    nl = chunk.find(b"\n")
    if nl >= 0:
        chunk = chunk[: nl + 1]
    state[pos_key] = pos + len(chunk)
    return chunk


def _consume_stdin_bytes(state: dict, n: int) -> bytes:
    return _consume_stream_bytes(state, "stdin_data", "stdin_pos", n)


def _consume_stdin_line(state: dict, max_len: int) -> bytes:
    return _consume_stream_line(state, "stdin_data", "stdin_pos", max_len)


def _skip_stream_whitespace(state: dict, data_key: str, pos_key: str) -> int:
    data = state.get(data_key, b"")
    pos = int(state.get(pos_key, 0))
    start = pos
    while pos < len(data) and chr(data[pos]).isspace():
        pos += 1
    state[pos_key] = pos
    return pos - start


def _skip_stdin_whitespace(state: dict) -> int:
    return _skip_stream_whitespace(state, "stdin_data", "stdin_pos")


def _consume_stream_literal(
    state: dict, data_key: str, pos_key: str, literal: str
) -> bool:
    data = state.get(data_key, b"")
    pos = int(state.get(pos_key, 0))
    encoded = literal.encode("utf-8", errors="ignore")
    if not encoded:
        return False
    end = pos + len(encoded)
    if end > len(data) or data[pos:end] != encoded:
        return False
    state[pos_key] = end
    return True


def _consume_stdin_literal(state: dict, literal: str) -> bool:
    return _consume_stream_literal(state, "stdin_data", "stdin_pos", literal)


def _consume_stream_token(
    state: dict,
    data_key: str,
    pos_key: str,
    width: int | None = None,
    scanset: str | None = None,
) -> bytes:
    _skip_stream_whitespace(state, data_key, pos_key)
    data = state.get(data_key, b"")
    pos = int(state.get(pos_key, 0))
    if pos >= len(data):
        return b""
    end = len(data) if width is None else min(len(data), pos + width)
    cursor = pos
    while cursor < end:
        byte = data[cursor]
        if scanset is not None:
            if not _byte_matches_scanset(byte, scanset):
                break
        elif chr(byte).isspace():
            break
        cursor += 1
    state[pos_key] = cursor
    return data[pos:cursor]


def _consume_stdin_token(state: dict, width: int | None = None) -> bytes:
    return _consume_stream_token(state, "stdin_data", "stdin_pos", width)


def _byte_matches_scanset(byte: int, scanset: str) -> bool:
    if scanset == "":
        return False
    invert = scanset.startswith("^")
    spec = scanset[1:] if invert else scanset
    idx = 0
    matched = False
    while idx < len(spec):
        ch = spec[idx]
        if idx + 2 < len(spec) and spec[idx + 1] == "-":
            start = ord(ch)
            end = ord(spec[idx + 2])
            if min(start, end) <= byte <= max(start, end):
                matched = True
            idx += 3
            continue
        if byte == ord(ch):
            matched = True
        idx += 1
    return not matched if invert else matched


def _iterate_scanf_tokens(fmt: str) -> list[dict]:
    tokens: list[dict] = []
    idx = 0
    while idx < len(fmt):
        ch = fmt[idx]
        if ch.isspace():
            while idx < len(fmt) and fmt[idx].isspace():
                idx += 1
            tokens.append({"kind": "whitespace"})
            continue
        if ch != "%":
            tokens.append({"kind": "literal", "value": ch})
            idx += 1
            continue

        idx += 1
        if idx >= len(fmt):
            break
        if fmt[idx] == "%":
            tokens.append({"kind": "literal", "value": "%"})
            idx += 1
            continue

        assign = True
        if fmt[idx] == "*":
            assign = False
            idx += 1

        width_start = idx
        while idx < len(fmt) and fmt[idx].isdigit():
            idx += 1
        width = int(fmt[width_start:idx]) if idx > width_start else None

        if idx + 1 < len(fmt) and fmt[idx : idx + 2] in {"hh", "ll"}:
            idx += 2
        elif idx < len(fmt) and fmt[idx] in {"h", "l", "j", "z", "t", "L"}:
            idx += 1

        if idx >= len(fmt):
            break
        if fmt[idx] == "[":
            set_start = idx + 1
            if set_start < len(fmt) and fmt[set_start] == "^":
                set_start += 1
            cursor = set_start
            if cursor < len(fmt) and fmt[cursor] == "]":
                cursor += 1
            while cursor < len(fmt) and fmt[cursor] != "]":
                cursor += 1
            if cursor >= len(fmt):
                break
            tokens.append(
                {
                    "kind": "conversion",
                    "value": "[",
                    "width": width,
                    "assign": assign,
                    "scanset": fmt[idx + 1 : cursor],
                }
            )
            idx = cursor + 1
            continue
        tokens.append(
            {
                "kind": "conversion",
                "value": fmt[idx],
                "width": width,
                "assign": assign,
            }
        )
        idx += 1
    return tokens
