# SPDX-License-Identifier: AGPL-3.0-only
"""Détection de convention d'appel pour les fonctions d'un binaire.

Usage:
    python backends/static/calling_convention.py --binary <path> [--addrs 0x401050,0x401020]

Output JSON:
    {
      "arch": "x86_64",
      "conventions": {
        "0x401050": {"convention": "System V AMD64", "confidence": 0.9},
        "0x401020": {"convention": null, "confidence": 0.0}
      },
      "error": null
    }
"""

from __future__ import annotations

__mcp_enabled__ = True

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from backends.static.binary.arch import ArchInfo, detect_binary_arch

try:
    import lief
except ImportError:
    lief = None

try:
    import capstone
except ImportError:
    capstone = None


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

# x86-64 parameter registers
# rdi/rsi are exclusive to System V AMD64 — never used by Microsoft x64
_SYSV_EXCLUSIVE_REGS = {"rdi", "rsi"}
# rcx/r8/r9 are Microsoft x64 parameter registers (rdx is shared, excluded)
_MS_X64_REGS = {"rcx", "r8", "r9"}


def _analyze_x86(insns: list, bits: int = 64) -> tuple[str | None, float]:
    """Analyse les instructions d'une fonction et retourne (convention, confidence)."""
    if bits == 64:
        sysv_exclusive_hits = 0
        ms_hits = 0
        for insn in insns[:30]:
            # capstone with detail=True exposes regs_read
            try:
                regs_read = [insn.reg_name(r).lower() for r in insn.regs_read]
            except Exception:
                regs_read = []
            for reg in regs_read:
                if reg in _SYSV_EXCLUSIVE_REGS:
                    sysv_exclusive_hits += 1
                if reg in _MS_X64_REGS:
                    ms_hits += 1

        if sysv_exclusive_hits > 0:
            confidence = min(1.0, 0.5 + 0.1 * sysv_exclusive_hits)
            return "System V AMD64", confidence
        elif ms_hits > 0:
            confidence = min(1.0, 0.4 + 0.15 * ms_hits)
            return "Microsoft x64", confidence
        else:
            return "System V AMD64", 0.3

    else:
        # x86-32 heuristics
        # Check for ret N (stdcall)
        for insn in insns[:30]:
            mnemonic = insn.mnemonic.lower()
            if mnemonic in ("ret", "retn") and insn.op_str.strip():
                return "__stdcall", 0.8

        # Check register usage for thiscall / fastcall / cdecl
        ecx_first = False
        edx_seen = False
        for insn in insns[:30]:
            try:
                regs_read = [insn.reg_name(r).lower() for r in insn.regs_read]
            except Exception:
                regs_read = []
            if not ecx_first and "ecx" in regs_read:
                ecx_first = True
            if "edx" in regs_read:
                edx_seen = True

        if ecx_first and edx_seen:
            return "__fastcall", 0.7
        elif ecx_first and not edx_seen:
            return "__thiscall", 0.7
        else:
            return "__cdecl", 0.5


def _analyze_arm64(insns: list) -> tuple[str, float]:
    return "AAPCS64", 0.6


def _analyze_arm32(insns: list) -> tuple[str, float]:
    del insns
    return "AAPCS32", 0.55


_ABI_CONVENTION_NAMES = {
    "sysv64": "System V AMD64",
    "win64": "Microsoft x64",
    "cdecl32": "__cdecl",
    "aapcs64": "AAPCS64",
    "aapcs32": "AAPCS32",
    "mips_o32": "MIPS o32",
    "mips_n64": "MIPS n64",
    "ppc32_sysv": "PowerPC SysV",
    "ppc64_elfv2": "PowerPC ELFv2",
    "sparc": "SPARC ABI",
    "riscv": "RISC-V psABI",
    "sysz": "System V s390x",
}

_FAMILY_CONVENTION_NAMES = {
    "bpf": "BPF helper-call ABI",
    "wasm": "WebAssembly stack-machine ABI",
    "m68k": "M68K ABI",
    "sh": "SuperH ABI",
    "tricore": "TriCore EABI",
}


def _known_abi_convention(arch_info: ArchInfo) -> tuple[str | None, float]:
    """Return the static ABI convention known for an architecture.

    This is intentionally less confident than x86/ARM instruction heuristics:
    it tells the caller what ABI applies to the architecture, but it does not
    prove a per-function convention from observed register/stack usage.
    """
    if arch_info.abi in _ABI_CONVENTION_NAMES:
        return _ABI_CONVENTION_NAMES[arch_info.abi], 0.45
    if arch_info.family in _FAMILY_CONVENTION_NAMES:
        return _FAMILY_CONVENTION_NAMES[arch_info.family], 0.35
    if arch_info.abi and arch_info.abi not in {"generic", "unknown"}:
        return arch_info.abi, 0.3
    if arch_info.display_name:
        return f"{arch_info.display_name} ABI", 0.25
    return None, 0.0


def _classify_arch_convention(
    arch_info: ArchInfo,
    insns: list | None = None,
) -> tuple[str | None, float, str]:
    """Return convention/confidence/source for one function.

    x86 needs instruction-level hints to distinguish common conventions.
    Most other supported ISAs have a single ABI per platform family, so the
    known ABI is still useful even when bytes are unavailable.
    """
    if arch_info.key == "x86_64" and insns:
        convention, confidence = _analyze_x86(insns, bits=64)
        return convention, confidence, "heuristic"
    if arch_info.key == "x86_32" and insns:
        convention, confidence = _analyze_x86(insns, bits=32)
        return convention, confidence, "heuristic"
    if arch_info.key == "arm64":
        convention, confidence = _analyze_arm64(insns or [])
        return convention, confidence, "abi"
    if arch_info.key == "arm32":
        convention, confidence = _analyze_arm32(insns or [])
        return convention, confidence, "abi"
    if arch_info.key in {"x86_64", "x86_32"}:
        return None, 0.0, "heuristic"
    convention, confidence = _known_abi_convention(arch_info)
    return convention, confidence, "abi"


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def _get_function_bytes(binary, addr: int, size: int = 128) -> bytes | None:
    """Lit les bytes d'une fonction via lief."""
    try:
        content = binary.get_content_from_virtual_address(addr, size)
        if content is None:
            return None
        return bytes(content)
    except Exception:
        return None


def _analyze_function(binary, cs, arch_info: ArchInfo, addr: int) -> dict:
    """Analyse une fonction à l'adresse donnée et retourne {convention, confidence}."""

    def result(convention: str | None, confidence: float, source: str) -> dict:
        return {
            "convention": convention,
            "confidence": round(confidence, 4),
            "arg_registers": list(arch_info.arg_registers),
            "source": source,
        }

    code = _get_function_bytes(binary, addr)
    if not code or len(code) == 0:
        return result(*_classify_arch_convention(arch_info, None))

    try:
        cs.detail = True
        insns = list(cs.disasm(code, addr))
    except Exception:
        return result(*_classify_arch_convention(arch_info, None))

    if not insns:
        return result(*_classify_arch_convention(arch_info, None))

    return result(*_classify_arch_convention(arch_info, insns))


def _collect_function_addrs(binary) -> list[int]:
    """Collecte les adresses de toutes les fonctions du binaire."""
    addrs: list[int] = []
    seen: set[int] = set()

    # Primary: binary.functions
    try:
        for fn in binary.functions:
            addr = fn.address
            if addr and addr not in seen:
                seen.add(addr)
                addrs.append(addr)
    except Exception:
        pass

    # Fallback: symbols with address > 0x1000
    if not addrs:
        try:
            for sym in binary.symbols:
                try:
                    addr = int(sym.value)
                except (TypeError, ValueError):
                    continue
                if addr > 0x1000 and addr not in seen:
                    seen.add(addr)
                    addrs.append(addr)
        except Exception:
            pass

    return addrs


def analyze_calling_conventions(binary_path: str, addrs: list[int] | None = None) -> dict:
    """Analyse les conventions d'appel d'un binaire.

    Args:
        binary_path: Chemin vers le binaire.
        addrs: Liste d'adresses à analyser. Si None, analyse toutes les fonctions.

    Returns:
        {
            "arch": str,
            "conventions": {hex_addr: {"convention": str|None, "confidence": float}},
            "error": str|None,
        }
    """
    if not lief:
        return {"error": "lief non installé", "arch": None, "conventions": {}}
    if not capstone:
        return {"error": "capstone non installé", "arch": None, "conventions": {}}

    binary = lief.parse(binary_path)
    if binary is None:
        return {
            "error": f"Impossible de parser le binaire : {binary_path}",
            "arch": None,
            "conventions": {},
        }

    arch_info = detect_binary_arch(binary)
    if arch_info is None or arch_info.capstone_tuple is None:
        return {
            "error": "Architecture non supportée",
            "arch": None,
            "conventions": {},
        }
    cs = capstone.Cs(*arch_info.capstone_tuple)
    cs.detail = True

    if addrs is None:
        addrs = _collect_function_addrs(binary)

    conventions: dict[str, dict] = {}
    for addr in addrs:
        hex_addr = hex(addr)
        conventions[hex_addr] = _analyze_function(binary, cs, arch_info, addr)

    return {
        "arch": arch_info.key,
        "conventions": conventions,
        "error": None,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Détecte les conventions d'appel des fonctions d'un binaire"
    )
    parser.add_argument("--binary", required=True, help="Chemin du binaire")
    parser.add_argument(
        "--addrs",
        help="Adresses hex séparées par des virgules (ex: 0x401050,0x401020)",
        default=None,
    )
    args = parser.parse_args()

    addrs: list[int] | None = None
    if args.addrs:
        try:
            addrs = [int(a.strip(), 16) for a in args.addrs.split(",") if a.strip()]
        except ValueError as exc:
            result = {"error": f"Adresses invalides : {exc}", "arch": None, "conventions": {}}
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 1

    result = analyze_calling_conventions(args.binary, addrs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
