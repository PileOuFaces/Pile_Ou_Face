#!/usr/bin/env python3
"""Adapter GCC multi-arch pour Pile ou Face.

Usage: python compile.py --src <path> --lang <c|cpp> --target <target-id> --output <path>
Sortie JSON: {"output_path": "...", "compiler_used": "gcc-multiarch", ...}

Tout le code gcc-spécifique vit ici — jamais dans le moteur générique.
"""
import argparse
import json
import subprocess
import sys

TARGET_COMPILER: dict[str, str] = {
    # x86 / x86-64
    "elf-x64":      "x86_64-linux-gnu-gcc",
    "elf-x86":      "i686-linux-gnu-gcc",
    # ARM / AArch64
    "elf-arm64":    "aarch64-linux-gnu-gcc",
    "elf-arm":      "arm-linux-gnueabihf-gcc",
    # Windows (MinGW)
    "pe-x64":       "x86_64-w64-mingw32-gcc",
    "pe-x86":       "i686-w64-mingw32-gcc",
    # MIPS
    "elf-mips":     "mips-linux-gnu-gcc",
    "elf-mipsel":   "mipsel-linux-gnu-gcc",
    "elf-mips64el": "mips64el-linux-gnuabi64-gcc",
    # PowerPC
    "elf-ppc":      "powerpc-linux-gnu-gcc",
    "elf-ppc64":    "powerpc64-linux-gnu-gcc",
    "elf-ppc64le":  "powerpc64le-linux-gnu-gcc",
    # SPARC64
    "elf-sparc64":  "sparc64-linux-gnu-gcc",
    # RISC-V 64
    "elf-riscv64":  "riscv64-linux-gnu-gcc",
    # IBM SystemZ
    "elf-s390x":    "s390x-linux-gnu-gcc",
    # Motorola M68K
    "elf-m68k":     "m68k-linux-gnu-gcc",
    # SuperH SH4
    "elf-sh4":      "sh4-linux-gnu-gcc",
}
# g++ variant (replace -gcc with -g++ where available; falls back gracefully)
CPP_COMPILER: dict[str, str] = {
    k: v.replace("-gcc", "-g++") for k, v in TARGET_COMPILER.items()
}
# Archs without a packaged g++ — use gcc for C++ (works for most cases)
_CPP_USE_GCC: set[str] = {"elf-mips", "elf-m68k", "elf-sh4"}
for _t in _CPP_USE_GCC:
    if _t in CPP_COMPILER:
        CPP_COMPILER[_t] = TARGET_COMPILER[_t]


def run(src: str, lang: str, target: str, output: str, flags: list[str] | None = None) -> dict:
    compiler_map = CPP_COMPILER if lang == "cpp" else TARGET_COMPILER
    compiler = compiler_map.get(target)
    if not compiler:
        return {"error": f"Target non supporté: {target}"}
    extra = flags if flags else ["-O0", "-g", "-fno-stack-protector"]
    cmd = [compiler, *extra, "-o", output, src]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "output_path": output if r.returncode == 0 else None,
            "compiler_used": "gcc-multiarch",
            "target": target,
            "exit_code": r.returncode,
            "stderr": r.stderr,
        }
    except Exception as exc:
        return {
            "output_path": None,
            "compiler_used": "gcc-multiarch",
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
    parser.add_argument("--flags", default="[]",
                        help="Flags extra encodés en JSON")
    args = parser.parse_args()
    try:
        import json as _json
        flags = _json.loads(args.flags) if args.flags and args.flags != "[]" else None
    except Exception:
        flags = None
    result = run(args.src, args.lang, args.target, args.output, flags=flags)
    print(json.dumps(result))
    sys.exit(0 if result.get("exit_code", 1) == 0 else 1)
