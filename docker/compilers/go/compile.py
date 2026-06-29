#!/usr/bin/env python3
"""Adapter Go pour Pile ou Face."""
import argparse
import json
import os
import subprocess
import sys

# (GOOS, GOARCH) — Go natively supports cross-compilation via env vars
TARGET_ENV: dict[str, tuple[str, str]] = {
    # Standard
    "elf-x64":      ("linux",   "amd64"),
    "elf-x86":      ("linux",   "386"),
    "elf-arm64":    ("linux",   "arm64"),
    "elf-arm":      ("linux",   "arm"),
    "pe-x64":       ("windows", "amd64"),
    "pe-x86":       ("windows", "386"),
    "macho-arm64":  ("darwin",  "arm64"),
    "macho-x64":    ("darwin",  "amd64"),
    # MIPS
    "elf-mips":     ("linux",   "mips"),
    "elf-mipsel":   ("linux",   "mipsle"),
    "elf-mips64":   ("linux",   "mips64"),
    "elf-mips64el": ("linux",   "mips64le"),
    # PowerPC
    "elf-ppc64":    ("linux",   "ppc64"),
    "elf-ppc64le":  ("linux",   "ppc64le"),
    # RISC-V 64
    "elf-riscv64":  ("linux",   "riscv64"),
    # IBM SystemZ
    "elf-s390x":    ("linux",   "s390x"),
}


def run(src: str, _lang: str, target: str, output: str, flags: list[str] | None = None) -> dict:
    env_pair = TARGET_ENV.get(target)
    if not env_pair:
        return {"error": f"Target non supporté: {target}"}
    goos, goarch = env_pair
    env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"}
    cmd = ["go", "build", "-o", output, src]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
        return {
            "output_path": output if r.returncode == 0 else None,
            "compiler_used": "go",
            "target": target,
            "exit_code": r.returncode,
            "stderr": r.stderr,
        }
    except Exception as exc:
        return {
            "output_path": None,
            "compiler_used": "go",
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
