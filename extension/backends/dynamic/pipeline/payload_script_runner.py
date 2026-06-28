#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Extract payload bytes from pwntools-like scripts without running the target."""

from __future__ import annotations

import argparse
import builtins
import contextlib
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from types import ModuleType, SimpleNamespace
from typing import Any

try:
    from backends.static.binary.symbols import extract_symbols
except Exception:  # pragma: no cover - optional dependency at runtime
    try:
        from backends.static.symbols import extract_symbols
    except Exception:
        extract_symbols = None


ALPHABET = b"abcdefghijklmnopqrstuvwxyz"
SYMBOL_NAME_RE = re.compile(rb"[A-Za-z_.$][A-Za-z0-9_.$@]{2,96}")


class ScriptTimeoutError(RuntimeError):
    """Raised when script execution exceeds the allowed time budget."""


def _bytes_to_hex(data: bytes) -> str:
    return data.hex()


def _ascii_preview(data: bytes, limit: int = 80) -> str:
    blob = data[:limit]
    text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in blob)
    return f"{text}..." if len(data) > limit else text


def _delimiter_preview(data: bytes, limit: int = 40) -> str:
    text = _ascii_preview(data, limit)
    return text or data[:limit].hex()


def _coerce_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, str):
        try:
            return value.encode("latin1")
        except UnicodeEncodeError:
            return value.encode("utf-8")
    if isinstance(value, int):
        return str(value).encode("ascii", errors="ignore")
    if isinstance(value, (list, tuple)):
        return b"".join(_coerce_bytes(item) for item in value)
    raise TypeError(f"Unsupported payload type: {type(value).__name__}")


def _normalize_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            raise ValueError("empty integer")
        sign = -1 if text.startswith("-") else 1
        body = text.replace("+", "", 1).replace("-", "", 1)
        if body.startswith("0x"):
            return sign * int(body, 16)
        return sign * int(body, 10)
    raise TypeError(f"Unsupported integer type: {type(value).__name__}")


def _pack(value: Any, width: int, endian: str = "little") -> bytes:
    bits = width * 8
    number = _normalize_int(value) & ((1 << bits) - 1)
    return int(number).to_bytes(width, endian, signed=False)


def _normalize_word_size(value: Any, fallback: int = 8) -> int:
    if value in (None, ""):
        return 4 if int(fallback) <= 4 else 8
    raw = int(_normalize_int(value))
    if raw in (8, 16, 32, 64):
        return max(1, raw // 8) if raw > 8 else raw
    if raw <= 0:
        return 4 if int(fallback) <= 4 else 8
    return raw


def _de_bruijn(alphabet: bytes, n: int) -> bytes:
    k = len(alphabet)
    a = [0] * (k * n)
    sequence: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    sequence.append(alphabet[a[j]])
            return
        a[t] = a[t - p]
        db(t + 1, p)
        for j in range(a[t - p] + 1, k):
            a[t] = j
            db(t + 1, t)

    db(1, 1)
    return bytes(sequence)


_CYCLIC_CACHE: dict[int, bytes] = {}


def cyclic(length: int, n: int = 4) -> bytes:
    size = max(0, int(length))
    if n not in _CYCLIC_CACHE:
        _CYCLIC_CACHE[n] = _de_bruijn(ALPHABET, n)
    pattern = _CYCLIC_CACHE[n]
    if size > len(pattern):
        raise ValueError(f"pattern length too long ({len(pattern)} max for n={n})")
    return pattern[:size]


def cyclic_find(value: Any, n: int = 4) -> int:
    if isinstance(value, int):
        needle = _pack(value, n, "little")
    else:
        needle = _coerce_bytes(value)
    if not needle:
        return -1
    pattern = cyclic(20000, n=n)
    return pattern.find(needle[:n])


def _fill_bytes(length: int, filler: bytes) -> bytearray:
    unit = filler or b"\x00"
    repeated = (unit * ((length // len(unit)) + 1))[:length]
    return bytearray(repeated)


def _flatten_value(value: Any, word_size: int, endian: str) -> bytes:
    if isinstance(value, dict):
        return flat(value, word_size=word_size, endian=endian)
    if isinstance(value, (list, tuple)):
        return flat(*value, word_size=word_size, endian=endian)
    if isinstance(value, (bytes, bytearray, memoryview, str)):
        return _coerce_bytes(value)
    if isinstance(value, int):
        return _pack(value, word_size, endian)
    raise TypeError(f"Unsupported flat() item: {type(value).__name__}")


def flat(
    *items: Any,
    word_size: int = 8,
    endian: str = "little",
    filler: bytes = b"\x00",
    length: int | None = None,
) -> bytes:
    word_size = _normalize_word_size(word_size, fallback=word_size)
    if len(items) == 1 and isinstance(items[0], dict):
        mapping = items[0]
        max_end = 0
        chunks: list[tuple[int, bytes]] = []
        for raw_offset, raw_value in mapping.items():
            offset = int(raw_offset)
            data = _flatten_value(raw_value, word_size, endian)
            chunks.append((offset, data))
            max_end = max(max_end, offset + len(data))
        target_len = max(length or 0, max_end)
        out = _fill_bytes(target_len, filler)
        for offset, data in chunks:
            out[offset : offset + len(data)] = data
        return bytes(out[:length] if length is not None else out)

    values: Iterable[Any]
    if len(items) == 1 and isinstance(items[0], (list, tuple)):
        values = items[0]
    else:
        values = items
    out = bytearray()
    for item in values:
        out.extend(_flatten_value(item, word_size, endian))
    if length is not None and len(out) < length:
        out.extend(_fill_bytes(length - len(out), filler))
    return bytes(out[:length] if length is not None else out)


class FakeArgs(SimpleNamespace):
    """Return False for any missing pwntools args flag."""

    def __getattr__(self, _name: str) -> bool:  # pragma: no cover - trivial
        return False


class FakeLogger:
    """No-op pwntools logger shim."""

    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    info = success = warning = error = critical = debug


class FakeELF:
    """Very small ELF shim good enough for common pwntools scripts."""

    def __init__(self, path: Any, *_args: Any, **_kwargs: Any) -> None:
        self.path = os.path.abspath(os.fspath(path))
        self.address = 0
        self.symbols = _load_elf_symbols(self.path)
        self.sym = self.symbols
        self.plt: dict[str, int] = {}
        self.got: dict[str, int] = {}
        self.functions = {name: addr for name, addr in self.symbols.items() if addr}

    def __fspath__(self) -> str:
        return self.path

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.path

    def search(self, _needle: Any) -> iter:
        return iter(())

    def bss(self, offset: int = 0) -> int:
        return 0x404000 + int(offset)

    def checksec(self) -> dict[str, Any]:
        return {}


class FakeROP:
    """Tiny ROP placeholder that can still emit a byte chain."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self._items: list[Any] = []

    def raw(self, value: Any) -> FakeROP:
        self._items.append(value)
        return self

    def chain(self) -> bytes:
        return flat(self._items)


@dataclass
class RunnerState:
    source_file_name: str
    warnings: list[str] = field(default_factory=list)
    captures: list[dict[str, Any]] = field(default_factory=list)
    globals: dict[str, dict[str, Any]] = field(default_factory=dict)
    processes: list[dict[str, Any]] = field(default_factory=list)
    next_capture_id: int = 1

    def warn(self, message: str) -> None:
        text = str(message).strip()
        if text and text not in self.warnings:
            self.warnings.append(text)


def _load_elf_symbols(binary_path: str) -> dict[str, int]:
    if not binary_path or not os.path.exists(binary_path):
        return {}
    symbols: dict[str, int] = {}
    if extract_symbols:
        try:
            raw_symbols = extract_symbols(binary_path, defined_only=True)
        except Exception:
            raw_symbols = []
        for entry in raw_symbols if isinstance(raw_symbols, list) else []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            addr = entry.get("addr")
            if not name or addr in (None, "", "0x0", 0):
                continue
            try:
                symbols[name] = _normalize_int(addr)
            except Exception:
                continue

    if shutil.which("nm"):
        try:
            result = subprocess.run(
                ["nm", "-C", "-n", binary_path],
                check=False,
                capture_output=True,
                text=True,
                timeout=2.0,
            )
        except Exception:
            result = None
        if result and result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                addr, sym_type = parts[0], parts[1]
                name = " ".join(parts[2:]).strip()
                if not name or sym_type.upper() == "U" or addr == "0":
                    continue
                try:
                    symbols.setdefault(name, int(addr, 16))
                except ValueError:
                    continue

    try:
        data = open(binary_path, "rb").read()
    except OSError:
        data = b""
    for match in SYMBOL_NAME_RE.finditer(data):
        name = match.group().decode("ascii", errors="ignore")
        if not name or name in symbols:
            continue
        symbols[name] = match.start()
    return symbols


def _normalize_process_arg(value: Any) -> str:
    if isinstance(value, FakeELF):
        return value.path
    if hasattr(value, "path") and isinstance(value.path, str):
        return str(value.path)
    if isinstance(value, bytes):
        return value.decode("latin1", errors="ignore")
    return str(value)


class FakeTube:
    """Capture pwntools send* traffic instead of interacting with a real target."""

    def __init__(
        self,
        state: RunnerState,
        kind: str,
        process_index: int | None = None,
        process_args: list[str] | None = None,
        remote_target: str = "",
    ) -> None:
        self._state = state
        self._kind = kind
        self._process_index = process_index
        self._process_args = process_args or []
        self._remote_target = remote_target

    def _capture(
        self,
        method: str,
        payload: Any,
        *,
        delimiter: Any = None,
        newline: bool = False,
    ) -> int:
        blob = _coerce_bytes(payload)
        if newline:
            blob += b"\n"
        delimiter_bytes = _coerce_bytes(delimiter) if delimiter is not None else b""
        entry = {
            "id": f"cap-{self._state.next_capture_id}",
            "type": method,
            "kind": method,
            "targetHint": "stdin",
            "data": _bytes_to_hex(blob),
            "encoding": "hex",
            "size": len(blob),
            "hex": _bytes_to_hex(blob),
            "asciiPreview": _ascii_preview(blob),
            "hexPreview": _bytes_to_hex(blob[:48]),
            "processIndex": self._process_index,
            "processArgs": list(self._process_args),
        }
        if delimiter_bytes:
            entry["delimiterHex"] = _bytes_to_hex(delimiter_bytes)
            entry["delimiterPreview"] = _delimiter_preview(delimiter_bytes)
        if self._remote_target:
            entry["remoteTarget"] = self._remote_target
        self._state.next_capture_id += 1
        self._state.captures.append(entry)
        return len(blob)

    def send(self, payload: Any) -> int:
        return self._capture("send", payload)

    def sendline(self, payload: Any = b"") -> int:
        return self._capture("sendline", payload, newline=True)

    def sendafter(self, delimiter: Any, payload: Any) -> int:
        return self._capture("sendafter", payload, delimiter=delimiter)

    def sendlineafter(self, delimiter: Any, payload: Any) -> int:
        return self._capture(
            "sendlineafter", payload, delimiter=delimiter, newline=True
        )

    def write(self, payload: Any) -> int:
        return self._capture("write", payload)

    sendraw = send

    def recv(self, *_args: Any, **_kwargs: Any) -> bytes:
        return b""

    recvline = recvuntil = recvrepeat = recvall = recv

    def clean(self, *_args: Any, **_kwargs: Any) -> bytes:
        return b""

    def interactive(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def close(self) -> None:
        return None

    shutdown = wait = wait_for_close = close

    def can_recv(self, *_args: Any, **_kwargs: Any) -> bool:
        return False

    def __enter__(self) -> FakeTube:  # pragma: no cover - trivial
        return self

    def __exit__(self, *_exc: Any) -> None:  # pragma: no cover - trivial
        self.close()


def _payload_record(kind: str, data: bytes) -> dict[str, Any]:
    return {
        "type": kind,
        "kind": kind,
        "data": _bytes_to_hex(data),
        "encoding": "hex",
        "size": len(data),
        "hex": _bytes_to_hex(data),
        "hexPreview": _bytes_to_hex(data[:48]),
        "asciiPreview": _ascii_preview(data),
    }


def _make_fake_pwn(state: RunnerState) -> ModuleType:
    module = ModuleType("pwn")
    context = SimpleNamespace(
        arch="amd64", bits=64, endian="little", binary=None, log_level="info"
    )

    def _default_word_size() -> int:
        bits = int(getattr(context, "bits", 64) or 64)
        return 4 if bits <= 32 else 8

    def _process(argv: Any = None, *_args: Any, **_kwargs: Any) -> FakeTube:
        if isinstance(argv, (list, tuple)):
            normalized_args = [_normalize_process_arg(item) for item in argv]
        elif argv is None:
            normalized_args = []
        else:
            normalized_args = [_normalize_process_arg(argv)]
        record = {
            "kind": "process",
            "argv": normalized_args,
        }
        state.processes.append(record)
        return FakeTube(
            state,
            kind="process",
            process_index=len(state.processes) - 1,
            process_args=normalized_args,
        )

    def _remote(host: Any, port: Any, *_args: Any, **_kwargs: Any) -> FakeTube:
        target = f"{host}:{port}"
        state.warn(f"remote() bloque: reseau desactive pendant l'analyse ({target}).")
        return FakeTube(state, kind="remote", remote_target=target)

    def _gdb_debug(argv: Any = None, *_args: Any, **_kwargs: Any) -> FakeTube:
        state.warn("gdb.debug() remplace par un faux process pendant l'analyse.")
        return _process(argv)

    def _pack_fn(width: int):
        return lambda value, *args, **kwargs: _pack(
            value,
            width,
            str(kwargs.get("endian") or getattr(context, "endian", "little")).lower()
            == "big"
            and "big"
            or "little",
        )

    def _flat(*items: Any, **kwargs: Any) -> bytes:
        return flat(
            *items,
            word_size=_normalize_word_size(
                kwargs.get("word_size")
                or kwargs.get("word_size_bits", 0)
                or _default_word_size(),
                fallback=_default_word_size(),
            ),
            endian=str(
                kwargs.get("endian") or getattr(context, "endian", "little")
            ).lower()
            == "big"
            and "big"
            or "little",
            filler=_coerce_bytes(kwargs.get("filler", b"\x00")),
            length=kwargs.get("length"),
        )

    def _fit(*items: Any, **kwargs: Any) -> bytes:
        return _flat(*items, **kwargs)

    def _u32(data: Any) -> int:
        return int.from_bytes(_coerce_bytes(data)[:4].ljust(4, b"\x00"), "little")

    def _u64(data: Any) -> int:
        return int.from_bytes(_coerce_bytes(data)[:8].ljust(8, b"\x00"), "little")

    def _pause(*_args: Any, **_kwargs: Any) -> None:
        return None

    module.context = context
    module.args = FakeArgs()
    module.log = FakeLogger()
    module.process = _process
    module.remote = _remote
    module.ELF = FakeELF
    module.ROP = FakeROP
    module.gdb = SimpleNamespace(debug=_gdb_debug, attach=lambda *_a, **_k: None)
    module.p8 = _pack_fn(1)
    module.p16 = _pack_fn(2)
    module.p32 = _pack_fn(4)
    module.p64 = _pack_fn(8)
    module.pack = lambda value, word_size=None, **kwargs: _pack(
        value,
        _normalize_word_size(
            word_size or _default_word_size(), fallback=_default_word_size()
        ),
        "big"
        if str(kwargs.get("endian") or getattr(context, "endian", "little")).lower()
        == "big"
        else "little",
    )
    module.flat = _flat
    module.fit = _fit
    module.cyclic = cyclic
    module.cyclic_find = cyclic_find
    module.u32 = _u32
    module.u64 = _u64
    module.pause = _pause
    module.sleep = lambda *_a, **_k: None
    module.asm = lambda *_a, **_k: b""
    module.packing = SimpleNamespace(
        p8=module.p8, p16=module.p16, p32=module.p32, p64=module.p64
    )
    module.__all__ = [
        "ELF",
        "ROP",
        "args",
        "asm",
        "context",
        "cyclic",
        "cyclic_find",
        "fit",
        "flat",
        "gdb",
        "log",
        "p8",
        "p16",
        "p32",
        "p64",
        "pause",
        "process",
        "remote",
        "sleep",
        "u32",
        "u64",
    ]
    return module


@contextlib.contextmanager
def _script_timeout(seconds: float) -> Any:
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _handler(_signum: int, _frame: Any) -> None:
        raise ScriptTimeoutError(f"timeout after {seconds:.1f}s")

    previous = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@contextlib.contextmanager
def _patched_runtime(fake_pwn: ModuleType, source_file_name: str) -> Any:
    patched: list[tuple[Any, str, Any]] = []
    saved_modules = {name: sys.modules.get(name) for name in ("pwn",)}
    saved_stdin = sys.stdin
    saved_argv = sys.argv[:]
    saved_cwd = os.getcwd()

    def patch_attr(target: Any, name: str, value: Any) -> None:
        previous = getattr(target, name)
        setattr(target, name, value)
        patched.append((target, name, previous))

    def blocked_process(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("subprocess bloque pendant l'analyse pwntools")

    def blocked_socket(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("reseau bloque pendant l'analyse pwntools")

    sys.modules["pwn"] = fake_pwn
    sys.stdin = io.StringIO("")
    sys.argv = [source_file_name]

    patch_attr(subprocess, "Popen", blocked_process)
    patch_attr(subprocess, "run", blocked_process)
    patch_attr(subprocess, "call", blocked_process)
    patch_attr(subprocess, "check_call", blocked_process)
    patch_attr(subprocess, "check_output", blocked_process)
    patch_attr(socket, "socket", blocked_socket)
    patch_attr(socket, "create_connection", blocked_socket)
    patch_attr(
        os,
        "system",
        lambda *_a, **_k: (_ for _ in ()).throw(
            RuntimeError("os.system bloque pendant l'analyse pwntools")
        ),
    )
    patch_attr(
        os,
        "popen",
        lambda *_a, **_k: (_ for _ in ()).throw(
            RuntimeError("os.popen bloque pendant l'analyse pwntools")
        ),
    )
    patch_attr(time, "sleep", lambda *_a, **_k: None)
    patch_attr(builtins, "input", lambda *_a, **_k: "")

    try:
        yield
    finally:
        for target, name, previous in reversed(patched):
            setattr(target, name, previous)
        sys.stdin = saved_stdin
        sys.argv = saved_argv
        os.chdir(saved_cwd)
        for name, previous in saved_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def analyze_script_text(
    script_text: str,
    *,
    source_file_name: str = "payload.py",
    timeout_seconds: float = 2.0,
    script_args: list[str] | None = None,
    script_root: str = "",
) -> dict[str, Any]:
    state = RunnerState(source_file_name=source_file_name)
    fake_pwn = _make_fake_pwn(state)
    namespace: dict[str, Any] = {
        "__name__": "__main__",
        "__file__": source_file_name,
    }
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    error = ""
    ok = True

    try:
        code = compile(script_text, source_file_name, "exec")
    except Exception as exc:
        return {
            "ok": False,
            "sourceFileName": source_file_name,
            "captures": [],
            "captured": [],
            "globals": {},
            "processes": [],
            "warnings": ["Script pwntools invalide."],
            "error": f"{type(exc).__name__}: {exc}",
            "stdout": "",
            "stderr": "",
        }

    normalized_script_root = os.path.abspath(script_root) if script_root else ""
    normalized_script_args = [os.fspath(arg) for arg in (script_args or [])]

    @contextlib.contextmanager
    def _runtime_context() -> Any:
        with _patched_runtime(fake_pwn, source_file_name):
            sys.argv = [source_file_name, *normalized_script_args]
            if normalized_script_root and os.path.isdir(normalized_script_root):
                os.chdir(normalized_script_root)
            yield

    with _runtime_context():
        try:
            with (
                contextlib.redirect_stdout(stdout_buffer),
                contextlib.redirect_stderr(stderr_buffer),
                _script_timeout(timeout_seconds),
            ):
                exec(code, namespace, namespace)
        except Exception as exc:
            ok = False
            error = f"{type(exc).__name__}: {exc}"

    payload_global = namespace.get("payload")
    try:
        if payload_global is not None:
            payload_bytes = _coerce_bytes(payload_global)
            state.globals["payload"] = _payload_record("global_payload", payload_bytes)
    except Exception as exc:
        state.warn(f"Variable globale payload ignoree: {exc}")

    if not state.captures and "payload" not in state.globals:
        state.warn("Aucun payload capture dans le script pwntools.")

    return {
        "ok": ok,
        "sourceFileName": source_file_name,
        "captures": state.captures,
        "captured": state.captures,
        "globals": state.globals,
        "processes": state.processes,
        "warnings": state.warnings,
        "error": error,
        "stdout": stdout_buffer.getvalue(),
        "stderr": stderr_buffer.getvalue(),
    }


def _read_script(args: argparse.Namespace) -> tuple[str, str]:
    if args.script_file:
        with open(args.script_file, encoding="utf-8") as handle:
            return handle.read(), args.source_name or os.path.basename(args.script_file)
    data = sys.stdin.read()
    return data, args.source_name or "payload.py"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyse un script pwntools et extrait les payloads envoyes."
    )
    parser.add_argument("--script-file", default="", help="Chemin du script a analyser")
    parser.add_argument(
        "--source-name", default="", help="Nom source a exposer dans le resultat"
    )
    parser.add_argument(
        "--script-root",
        default="",
        help="Repertoire de resolution pour les chemins relatifs du script",
    )
    parser.add_argument(
        "--script-arg",
        action="append",
        default=[],
        help="Argument supplementaire expose dans sys.argv",
    )
    parser.add_argument(
        "--timeout-seconds", type=float, default=2.0, help="Timeout d'execution interne"
    )
    args = parser.parse_args(argv)

    script_text, source_name = _read_script(args)
    result = analyze_script_text(
        script_text,
        source_file_name=source_name,
        timeout_seconds=max(0.1, float(args.timeout_seconds or 2.0)),
        script_args=[str(value) for value in (args.script_arg or [])],
        script_root=str(args.script_root or ""),
    )
    sys.stdout.write(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
