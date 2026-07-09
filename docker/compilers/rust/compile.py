#!/usr/bin/env python3
"""Adapter Rust pour Pile ou Face."""

import argparse
import json
import subprocess
import sys

# rustup target triple → (triple, cross-linker)
TARGET_TRIPLE: dict[str, tuple[str, str]] = {
    "elf-x64": ("x86_64-unknown-linux-gnu", ""),
    "elf-arm64": ("aarch64-unknown-linux-gnu", "aarch64-linux-gnu-gcc"),
    "elf-arm": ("armv7-unknown-linux-gnueabihf", "arm-linux-gnueabihf-gcc"),
    "pe-x64": ("x86_64-pc-windows-gnu", "x86_64-w64-mingw32-gcc"),
    "macho-arm64": ("aarch64-apple-darwin", ""),
    "macho-x64": ("x86_64-apple-darwin", ""),
    # PowerPC
    "elf-ppc": ("powerpc-unknown-linux-gnu", "powerpc-linux-gnu-gcc"),
    "elf-ppc64": ("powerpc64-unknown-linux-gnu", "powerpc64-linux-gnu-gcc"),
    "elf-ppc64le": ("powerpc64le-unknown-linux-gnu", "powerpc64le-linux-gnu-gcc"),
    # SPARC64
    "elf-sparc64": ("sparc64-unknown-linux-gnu", "sparc64-linux-gnu-gcc"),
    # RISC-V 64
    "elf-riscv64": ("riscv64gc-unknown-linux-gnu", "riscv64-linux-gnu-gcc"),
    # SystemZ
    "elf-s390x": ("s390x-unknown-linux-gnu", "s390x-linux-gnu-gcc"),
}


def run(
    src: str, _lang: str, target: str, output: str, flags: list[str] | None = None
) -> dict:
    entry = TARGET_TRIPLE.get(target)
    if not entry:
        return {"error": f"Target non supporté: {target}"}
    triple, linker = entry
    cmd = ["rustc", "--edition", "2021", "--target", triple, "-o", output, src]
    if linker:
        cmd += ["-C", f"linker={linker}"]
    if flags:
        for f in flags:
            cmd += ["-C", f"link-arg={f}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "output_path": output if r.returncode == 0 else None,
            "compiler_used": "rust",
            "target": target,
            "exit_code": r.returncode,
            "stderr": r.stderr,
        }
    except Exception as exc:
        return {
            "output_path": None,
            "compiler_used": "rust",
            "target": target,
            "exit_code": -1,
            "stderr": str(exc),
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--lang", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--flags", default="[]")
    args = parser.parse_args()
    try:
        flags = json.loads(args.flags) if args.flags and args.flags != "[]" else None
    except Exception:
        flags = None
    result = run(args.src, args.lang, args.target, args.output, flags=flags)
    print(json.dumps(result))
    sys.exit(0 if result.get("exit_code", 1) == 0 else 1)
