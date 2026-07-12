# SPDX-License-Identifier: AGPL-3.0-only
"""Descripteurs d'architecture et adapteurs ISA pour l'analyse statique.

Centralise:
- format -> ISA -> capstone
- ABI / taille de pointeur
- comportement de base des instructions (call/jump/return)
- motifs de prologue

L'objectif est d'eviter la duplication de logique x86/x64/ARM64 dans
plusieurs backends et de rendre l'ajout d'une nouvelle ISA plus localise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

try:
    import capstone
except ImportError:  # pragma: no cover - dependance optionnelle
    capstone = None

try:
    import lief
except ImportError:  # pragma: no cover - dependance optionnelle
    lief = None


X86_PROLOGUE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bendbr64\b", "endbr64"),
    (r"\bpush\s+rbp\b", "push rbp"),
    (r"\bpush\s+ebp\b", "push ebp"),
    (r"\bsub\s+rsp\s*,\s*0x[0-9a-fA-F]+\b", "sub rsp"),
    (r"\bsub\s+esp\s*,\s*0x[0-9a-fA-F]+\b", "sub esp"),
)

ARM64_PROLOGUE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bstp\s+[xw]\d+,\s*[xw]\d+,\s*\[sp", "stp"),
    (r"\bsub\s+sp\s*,\s*sp\s*,\s*#?0x[0-9a-fA-F]+\b", "sub sp"),
    (r"\bstr\s+[xw]\d+,\s*\[sp\s*,\s*#-?\d+\]!", "str preindex"),
)

ARM32_PROLOGUE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bpush\s+\{[^}]*lr[^}]*\}", "push lr"),
    (r"\bstmdb\s+sp!", "stmdb sp"),
    (r"\bsub\s+sp\s*,\s*sp\s*,\s*#?0x[0-9a-fA-F]+\b", "sub sp"),
)

_SIGNED_IMMEDIATE_RE = r"[-+]?(?:0x[0-9a-fA-F]+|\d+)"

X86_CONDITIONAL_BRANCHES = frozenset(
    {
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "jcxz",
        "jecxz",
        "jrcxz",
        "je",
        "jz",
        "jne",
        "jnz",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "loop",
        "loope",
        "loopne",
        "loopnz",
        "loopz",
    }
)

ARM64_CONDITIONAL_BRANCHES = frozenset({"cbz", "cbnz", "tbz", "tbnz"})
ARM64_CONDITIONAL_PREFIXES = ("b.",)
ARM32_CONDITIONAL_BRANCHES = frozenset(
    {
        "beq",
        "bne",
        "bcs",
        "bcc",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
    }
)

X86_DATA_REF_MNEMONICS = frozenset(
    {
        "mov",
        "movzx",
        "movsx",
        "movsxd",
        "lea",
        "cmp",
        "test",
        "add",
        "sub",
        "and",
        "or",
        "xor",
        "xchg",
        "dec",
        "inc",
    }
)

ARM64_DATA_REF_MNEMONICS = frozenset(
    {
        "adr",
        "adrp",
        "add",
        "sub",
        "mov",
        "ldr",
        "ldrb",
        "ldrh",
        "ldrsw",
        "ldur",
        "ldp",
        "str",
        "stur",
        "stp",
        "cmp",
        "tst",
    }
)

ARM32_DATA_REF_MNEMONICS = frozenset(
    {
        "adr",
        "add",
        "sub",
        "mov",
        "ldr",
        "ldrb",
        "ldrh",
        "ldrsh",
        "ldrsb",
        "str",
        "stm",
        "ldm",
        "cmp",
        "tst",
    }
)

GENERIC_DATA_REF_MNEMONICS = frozenset(
    {
        "add",
        "addi",
        "adr",
        "adrp",
        "cmp",
        "la",
        "lea",
        "ld",
        "ld.b",
        "ld.h",
        "ld.w",
        "ld.d",
        "ldbu",
        "ldhu",
        "ldw",
        "ldwu",
        "ldr",
        "ldrb",
        "ldrh",
        "ldrsw",
        "load",
        "lw",
        "lwu",
        "lb",
        "lbu",
        "lh",
        "lhu",
        "mov",
        "move",
        "or",
        "st",
        "st.b",
        "st.h",
        "st.w",
        "st.d",
        "std",
        "stw",
        "str",
        "strb",
        "strh",
        "store",
        "sw",
        "sd",
        "sb",
        "sh",
    }
)

ABI_ARG_REGISTERS: dict[str, tuple[str, ...]] = {
    "sysv64": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "win64": ("rcx", "rdx", "r8", "r9"),
    "cdecl32": (),
    "aapcs64": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
    "aapcs32": ("r0", "r1", "r2", "r3"),
    "mips_o32": ("a0", "a1", "a2", "a3"),
    "mips_n64": ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
    "ppc32_sysv": ("r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"),
    "ppc64_elfv2": ("r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"),
    "sparc": ("o0", "o1", "o2", "o3", "o4", "o5"),
    "riscv": ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
    "sysz": ("r2", "r3", "r4", "r5", "r6"),
}

FEATURES: tuple[str, ...] = (
    "disasm",
    "discover_functions",
    "cfg",
    "xrefs",
    "call_graph",
    "stack_frame",
    "calling_convention",
)


@dataclass(frozen=True)
class FeatureSupport:
    """Niveau de support public d'une feature pour une ISA."""

    level: str
    note: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"level": self.level, "note": self.note}


@dataclass(frozen=True)
class ArchAdapter:
    """Comportements ISA reutilisables par les differents backends."""

    key: str
    family: str
    display_name: str
    call_mnemonics: frozenset[str]
    unconditional_jump_mnemonics: frozenset[str]
    conditional_branch_mnemonics: frozenset[str]
    return_mnemonics: frozenset[str]
    prologue_patterns: tuple[tuple[str, str], ...]
    data_ref_mnemonics: frozenset[str]
    conditional_branch_prefixes: tuple[str, ...] = ()
    pc_registers: tuple[str, ...] = ()
    sp_registers: tuple[str, ...] = ()
    fp_registers: tuple[str, ...] = ()
    lr_registers: tuple[str, ...] = ()
    support: dict[str, FeatureSupport] | None = field(
        default=None, compare=False, hash=False
    )

    def matches_prologue(
        self,
        text: str,
        custom_preludes: list[tuple[str, str]] | None = None,
    ) -> str | None:
        source = (text or "").strip()
        for pattern, name in custom_preludes or []:
            if re.search(pattern, source, re.IGNORECASE):
                return name
        for pattern, name in self.prologue_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                return name
        return None

    def is_call_mnemonic(self, mnemonic: str) -> bool:
        return mnemonic in self.call_mnemonics

    def is_return_mnemonic(self, mnemonic: str) -> bool:
        return mnemonic in self.return_mnemonics

    def is_return_instruction(self, mnemonic: str, operands: str = "") -> bool:
        mnem = str(mnemonic or "").strip().lower()
        ops = re.sub(r"\s+", "", str(operands or "").strip().lower())
        if self.is_return_mnemonic(mnem):
            return True
        if self.family == "arm" and mnem == "bx" and ops == "lr":
            return True
        if self.family == "arm" and mnem == "pop" and "pc" in ops:
            return True
        if self.family == "arm" and mnem in {"ldm", "ldmia", "ldmfd"} and "pc" in ops:
            return True
        if self.family == "sysz" and mnem == "br" and ops in {"r14", "%r14", "14"}:
            return True
        return bool(self.family == "mips" and mnem == "jr" and ops in {"ra", "$ra"})

    def is_unconditional_jump_mnemonic(self, mnemonic: str) -> bool:
        return mnemonic in self.unconditional_jump_mnemonics

    def is_conditional_branch_mnemonic(self, mnemonic: str) -> bool:
        if mnemonic in self.conditional_branch_mnemonics:
            return True
        return any(
            mnemonic.startswith(prefix) for prefix in self.conditional_branch_prefixes
        )

    def classify_code_ref_mnemonic(self, mnemonic: str) -> str | None:
        if self.is_return_mnemonic(mnemonic):
            return "ret"
        if self.is_call_mnemonic(mnemonic):
            return "call"
        if self.is_unconditional_jump_mnemonic(mnemonic):
            return "jmp"
        if self.is_conditional_branch_mnemonic(mnemonic):
            return "jcc"
        return None

    def supports_data_ref_mnemonic(self, mnemonic: str) -> bool:
        return mnemonic in self.data_ref_mnemonics

    def support_for(self, feature: str) -> FeatureSupport:
        if self.support and feature in self.support:
            return self.support[feature]
        if feature == "disasm":
            return FeatureSupport("full", "Capstone profile available")
        if self.key == "generic":
            return FeatureSupport("disasm-only", "No ISA semantics table")
        return FeatureSupport("partial", "Generic Capstone-backed semantics")


@dataclass(frozen=True)
class ArchInfo:
    """Resolution concrete d'une architecture pour un binaire ou un blob."""

    key: str
    bits: int
    ptr_size: int
    abi: str
    raw_name: str
    capstone_arch: int | None
    capstone_mode: int | None
    adapter: ArchAdapter
    format_kind: str | None = None
    machine: str | None = None
    endian: str = "little"

    @property
    def family(self) -> str:
        return self.adapter.family

    @property
    def display_name(self) -> str:
        return self.adapter.display_name

    @property
    def arg_registers(self) -> tuple[str, ...]:
        return ABI_ARG_REGISTERS.get(self.abi, ())

    @property
    def capstone_tuple(self) -> tuple[int, int] | None:
        if self.capstone_arch is None or self.capstone_mode is None:
            return None
        return (self.capstone_arch, self.capstone_mode)


X86_ADAPTER = ArchAdapter(
    key="x86",
    family="x86",
    display_name="x86/x64",
    call_mnemonics=frozenset({"call"}),
    unconditional_jump_mnemonics=frozenset({"jmp"}),
    conditional_branch_mnemonics=X86_CONDITIONAL_BRANCHES,
    return_mnemonics=frozenset({"ret", "retq", "retn", "retl", "retf"}),
    prologue_patterns=X86_PROLOGUE_PATTERNS,
    data_ref_mnemonics=X86_DATA_REF_MNEMONICS,
    pc_registers=("rip", "eip", "ip"),
    sp_registers=("rsp", "esp"),
    fp_registers=("rbp", "ebp"),
    support={
        "disasm": FeatureSupport("full", "Capstone x86/x64"),
        "discover_functions": FeatureSupport(
            "full", "Prologues, calls, thunks and tail-calls"
        ),
        "cfg": FeatureSupport(
            "full", "Calls, jumps, conditional branches, returns and x86 jump tables"
        ),
        "xrefs": FeatureSupport("full", "Code refs and common RIP-relative/data refs"),
        "call_graph": FeatureSupport("full", "Direct calls and ELF/Mach-O stubs"),
        "stack_frame": FeatureSupport(
            "full", "Frame-pointer and frame-pointer-less x86/x64"
        ),
        "calling_convention": FeatureSupport(
            "full", "cdecl/stdcall/fastcall/thiscall and SysV/Win64 heuristics"
        ),
    },
)

ARM64_ADAPTER = ArchAdapter(
    key="arm64",
    family="arm64",
    display_name="ARM64",
    call_mnemonics=frozenset({"bl", "blr"}),
    unconditional_jump_mnemonics=frozenset({"b", "br"}),
    conditional_branch_mnemonics=ARM64_CONDITIONAL_BRANCHES,
    return_mnemonics=frozenset({"ret", "retab", "retaa"}),
    prologue_patterns=ARM64_PROLOGUE_PATTERNS,
    data_ref_mnemonics=ARM64_DATA_REF_MNEMONICS,
    conditional_branch_prefixes=ARM64_CONDITIONAL_PREFIXES,
    pc_registers=("pc",),
    sp_registers=("sp",),
    fp_registers=("x29", "fp"),
    lr_registers=("x30", "lr"),
    support={
        "disasm": FeatureSupport("full", "Capstone ARM64"),
        "discover_functions": FeatureSupport(
            "full", "AArch64 prologues, BL targets and LR returns"
        ),
        "cfg": FeatureSupport(
            "full", "BL/B/BR/CBZ/TBZ/RET and common jump-table setup"
        ),
        "xrefs": FeatureSupport("full", "Code refs and ADR/ADRP/LDR/STR data refs"),
        "call_graph": FeatureSupport("full", "Direct BL calls and Mach-O stubs"),
        "stack_frame": FeatureSupport("full", "x29/sp tracking and register args"),
        "calling_convention": FeatureSupport("partial", "AAPCS64 identification"),
    },
)

ARM32_ADAPTER = ArchAdapter(
    key="arm32",
    family="arm",
    display_name="ARM",
    call_mnemonics=frozenset({"bl", "blx"}),
    unconditional_jump_mnemonics=frozenset({"b", "bx"}),
    conditional_branch_mnemonics=ARM32_CONDITIONAL_BRANCHES,
    return_mnemonics=frozenset(),
    prologue_patterns=ARM32_PROLOGUE_PATTERNS,
    data_ref_mnemonics=ARM32_DATA_REF_MNEMONICS,
    pc_registers=("pc",),
    sp_registers=("sp", "r13"),
    fp_registers=("fp", "r11", "r7"),
    lr_registers=("lr", "r14"),
    support={
        "disasm": FeatureSupport("full", "Capstone ARM/Thumb"),
        "discover_functions": FeatureSupport(
            "partial", "BL targets, push-lr prologues and LR returns"
        ),
        "cfg": FeatureSupport(
            "partial", "Direct branches/calls and LR return patterns"
        ),
        "xrefs": FeatureSupport("partial", "Code refs and common LDR/STR data refs"),
        "call_graph": FeatureSupport("partial", "Direct BL/BLX calls"),
        "stack_frame": FeatureSupport("partial", "SP/FP anchors and register args"),
        "calling_convention": FeatureSupport("partial", "AAPCS32 identification"),
    },
)

MIPS_ADAPTER = ArchAdapter(
    key="mips",
    family="mips",
    display_name="MIPS",
    call_mnemonics=frozenset({"bal", "bgezal", "bltzal", "jal", "jalr"}),
    unconditional_jump_mnemonics=frozenset({"b", "j", "jr"}),
    conditional_branch_mnemonics=frozenset(
        {
            "beq",
            "beql",
            "beqz",
            "bge",
            "bgeu",
            "bgez",
            "bgtz",
            "blez",
            "blt",
            "bltu",
            "bltz",
            "bne",
            "bnel",
            "bnez",
            "bc1f",
            "bc1t",
        }
    ),
    return_mnemonics=frozenset({"eret"}),
    prologue_patterns=(
        (
            rf"\b(?:addiu|daddiu)\s+\$?sp\s*,\s*\$?sp\s*,\s*{_SIGNED_IMMEDIATE_RE}\b",
            "addiu sp",
        ),
    ),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
    pc_registers=("pc",),
    sp_registers=("sp", "$sp", "r29"),
    fp_registers=("fp", "$fp", "s8", "$s8", "r30"),
    lr_registers=("ra", "$ra", "r31"),
)

PPC_ADAPTER = ArchAdapter(
    key="ppc",
    family="ppc",
    display_name="PowerPC",
    call_mnemonics=frozenset({"bl", "bla", "bctrl", "bcl"}),
    unconditional_jump_mnemonics=frozenset({"b", "ba", "bcctr", "bctr"}),
    conditional_branch_mnemonics=frozenset(
        {
            "bc",
            "bca",
            "beq",
            "bge",
            "bgt",
            "ble",
            "blt",
            "bne",
            "bdnz",
            "bdz",
            "bf",
            "bt",
        }
    ),
    return_mnemonics=frozenset({"blr", "rfid", "rfi"}),
    prologue_patterns=(
        (r"\bst[dw]u?\s+r?1\s*,\s*-(?:0x[0-9a-fA-F]+|\d+)\(r?1\)", "stwu r1"),
        (r"\bmflr\s+r?0\b", "mflr"),
    ),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
    pc_registers=("pc",),
    sp_registers=("r1",),
    fp_registers=("r31", "r30"),
    lr_registers=("lr",),
)

SPARC_ADAPTER = ArchAdapter(
    key="sparc",
    family="sparc",
    display_name="SPARC",
    call_mnemonics=frozenset({"call"}),
    unconditional_jump_mnemonics=frozenset({"ba", "b,a", "jmp"}),
    conditional_branch_mnemonics=frozenset(
        {
            "be",
            "bne",
            "bg",
            "ble",
            "bge",
            "bl",
            "bgu",
            "bleu",
            "bpos",
            "bneg",
            "bvc",
            "bvs",
        }
    ),
    return_mnemonics=frozenset({"ret", "retl", "rett"}),
    prologue_patterns=((r"\bsave\s+%?sp\s*,", "save sp"),),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
    pc_registers=("pc",),
    sp_registers=("sp", "o6"),
    fp_registers=("fp", "i6"),
    lr_registers=("o7", "i7"),
)

RISCV_ADAPTER = ArchAdapter(
    key="riscv",
    family="riscv",
    display_name="RISC-V",
    call_mnemonics=frozenset({"call", "jal", "jalr"}),
    unconditional_jump_mnemonics=frozenset({"j", "jr", "tail"}),
    conditional_branch_mnemonics=frozenset(
        {
            "beq",
            "beqz",
            "bge",
            "bgez",
            "bgeu",
            "bgt",
            "bgtu",
            "bgtz",
            "ble",
            "bleu",
            "blez",
            "blt",
            "bltu",
            "bltz",
            "bne",
            "bnez",
        }
    ),
    return_mnemonics=frozenset({"ret", "mret", "sret", "uret"}),
    prologue_patterns=(
        (rf"\baddi(?:w)?\s+sp\s*,\s*sp\s*,\s*{_SIGNED_IMMEDIATE_RE}\b", "addi sp"),
    ),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
    pc_registers=("pc",),
    sp_registers=("sp",),
    fp_registers=("s0", "fp"),
    lr_registers=("ra",),
)

SYSZ_ADAPTER = ArchAdapter(
    key="sysz",
    family="sysz",
    display_name="SystemZ",
    call_mnemonics=frozenset({"bas", "basr", "bras", "brasl", "brasl.g"}),
    unconditional_jump_mnemonics=frozenset({"b", "br", "j"}),
    conditional_branch_mnemonics=frozenset(
        {
            "je",
            "jne",
            "jnz",
            "jz",
            "jg",
            "jge",
            "jl",
            "jle",
            "jh",
            "jhe",
            "jlh",
            "jo",
            "jno",
            "brc",
            "bc",
        }
    ),
    return_mnemonics=frozenset(),
    prologue_patterns=(
        (r"\bstmg\s+%?r?14\s*,\s*%?r?15\s*,", "stmg r14"),
        (r"\bstm\s+%?r?14\s*,\s*%?r?15\s*,", "stm r14"),
        (r"\baghi\s+%?r?15\s*,\s*-\d+\b", "aghi r15"),
    ),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
    pc_registers=("psw",),
    sp_registers=("r15", "%r15", "15"),
    fp_registers=("r11", "%r11", "11"),
    lr_registers=("r14", "%r14", "14"),
)

BPF_ADAPTER = ArchAdapter(
    key="bpf",
    family="bpf",
    display_name="BPF",
    call_mnemonics=frozenset({"call"}),
    unconditional_jump_mnemonics=frozenset({"ja", "goto"}),
    conditional_branch_mnemonics=frozenset(
        {
            "jeq",
            "jgt",
            "jge",
            "jlt",
            "jle",
            "jset",
            "jne",
            "jsgt",
            "jsge",
            "jslt",
            "jsle",
        }
    ),
    return_mnemonics=frozenset({"exit"}),
    prologue_patterns=(),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
)

WASM_ADAPTER = ArchAdapter(
    key="wasm",
    family="wasm",
    display_name="WebAssembly",
    call_mnemonics=frozenset({"call", "call_indirect"}),
    unconditional_jump_mnemonics=frozenset({"br"}),
    conditional_branch_mnemonics=frozenset({"br_if", "if"}),
    return_mnemonics=frozenset({"return", "end"}),
    prologue_patterns=(),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
)

M68K_ADAPTER = ArchAdapter(
    key="m68k",
    family="m68k",
    display_name="M68K",
    call_mnemonics=frozenset({"bsr", "jsr"}),
    unconditional_jump_mnemonics=frozenset({"bra", "jmp"}),
    conditional_branch_mnemonics=frozenset(
        {
            "bcc",
            "bcs",
            "beq",
            "bge",
            "bgt",
            "bhi",
            "ble",
            "bls",
            "blt",
            "bmi",
            "bne",
            "bpl",
            "bvc",
            "bvs",
        }
    ),
    return_mnemonics=frozenset({"rts", "rte", "rtr"}),
    prologue_patterns=((r"\blink(?:\.[wl])?\s+a[56]\s*,", "link"),),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
    sp_registers=("sp", "a7"),
    fp_registers=("a6", "a5"),
)

SH_ADAPTER = ArchAdapter(
    key="sh",
    family="sh",
    display_name="SuperH",
    call_mnemonics=frozenset({"bsr", "bsrf", "jsr"}),
    unconditional_jump_mnemonics=frozenset({"bra", "braf", "jmp"}),
    conditional_branch_mnemonics=frozenset({"bt", "bf", "bt/s", "bf/s"}),
    return_mnemonics=frozenset({"rts"}),
    prologue_patterns=(),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
    sp_registers=("r15", "sp"),
    lr_registers=("pr",),
)

TRICORE_ADAPTER = ArchAdapter(
    key="tricore",
    family="tricore",
    display_name="TriCore",
    call_mnemonics=frozenset({"call", "calla", "fcall"}),
    unconditional_jump_mnemonics=frozenset({"j", "ja", "ji"}),
    conditional_branch_mnemonics=frozenset(
        {"jeq", "jne", "jge", "jlt", "jgt", "jle", "jnz", "jz"}
    ),
    return_mnemonics=frozenset({"ret", "rfe", "fret"}),
    prologue_patterns=(),
    data_ref_mnemonics=GENERIC_DATA_REF_MNEMONICS,
    sp_registers=("a10", "sp"),
    lr_registers=("a11",),
)

GENERIC_ADAPTER = ArchAdapter(
    key="generic",
    family="generic",
    display_name="Generic ISA",
    call_mnemonics=frozenset(),
    unconditional_jump_mnemonics=frozenset(),
    conditional_branch_mnemonics=frozenset(),
    return_mnemonics=frozenset(),
    prologue_patterns=(),
    data_ref_mnemonics=frozenset(),
    support={
        feature: FeatureSupport(
            "disasm-only" if feature == "disasm" else "unsupported",
            "No ISA semantics table",
        )
        for feature in FEATURES
    },
)

_PARTIAL_SEMANTIC_ADAPTERS = {
    "mips": MIPS_ADAPTER,
    "mips32": MIPS_ADAPTER,
    "mips64": MIPS_ADAPTER,
    "ppc": PPC_ADAPTER,
    "ppc32": PPC_ADAPTER,
    "ppc64": PPC_ADAPTER,
    "sparc": SPARC_ADAPTER,
    "sparcv9": SPARC_ADAPTER,
    "sysz": SYSZ_ADAPTER,
    "s390x": SYSZ_ADAPTER,
    "riscv": RISCV_ADAPTER,
    "riscv32": RISCV_ADAPTER,
    "riscv64": RISCV_ADAPTER,
    "bpf": BPF_ADAPTER,
    "wasm": WASM_ADAPTER,
    "m68k": M68K_ADAPTER,
    "sh": SH_ADAPTER,
    "sh4": SH_ADAPTER,
    "tricore": TRICORE_ADAPTER,
}

for _adapter in _PARTIAL_SEMANTIC_ADAPTERS.values():
    object.__setattr__(
        _adapter,
        "support",
        {
            "disasm": FeatureSupport("full", f"Capstone {_adapter.display_name}"),
            "discover_functions": FeatureSupport(
                "partial", "Direct call/branch mnemonics and lightweight prologues"
            ),
            "cfg": FeatureSupport(
                "partial",
                "Direct branches/calls/returns; advanced switch recovery may be absent",
            ),
            "xrefs": FeatureSupport(
                "partial", "Direct code refs and common absolute data refs"
            ),
            "call_graph": FeatureSupport("partial", "Direct calls only"),
            "stack_frame": FeatureSupport(
                "partial", "ABI register args and common SP/FP stack access forms"
            ),
            "calling_convention": FeatureSupport(
                "partial",
                "Known ABI and argument registers; no deep per-function inference",
            ),
        },
    )

SUPPORTED_ADAPTERS: tuple[ArchAdapter, ...] = (
    X86_ADAPTER,
    ARM64_ADAPTER,
    ARM32_ADAPTER,
    MIPS_ADAPTER,
    PPC_ADAPTER,
    SPARC_ADAPTER,
    RISCV_ADAPTER,
    SYSZ_ADAPTER,
    BPF_ADAPTER,
    WASM_ADAPTER,
    M68K_ADAPTER,
    SH_ADAPTER,
    TRICORE_ADAPTER,
    GENERIC_ADAPTER,
)


def iter_supported_adapters() -> tuple[ArchAdapter, ...]:
    return SUPPORTED_ADAPTERS


def get_feature_support(
    adapter_or_key: ArchAdapter | str, feature: str
) -> FeatureSupport:
    adapter = (
        adapter_or_key
        if isinstance(adapter_or_key, ArchAdapter)
        else _adapter_for_key(adapter_or_key)
    )
    return adapter.support_for(feature)


def get_adapter_for_arch_key(key: str, display_name: str | None = None) -> ArchAdapter:
    """Retourne l'adaptateur ISA pour une clé d'architecture ou un profil raw."""
    return _adapter_for_key(key, display_name)


def get_feature_support_matrix() -> dict[str, dict[str, dict[str, str]]]:
    """Retourne la matrice feature x ISA exposable par le backend/UI."""
    matrix: dict[str, dict[str, dict[str, str]]] = {}
    for adapter in SUPPORTED_ADAPTERS:
        if adapter.key == "generic":
            continue
        matrix[adapter.key] = {
            feature: adapter.support_for(feature).as_dict() for feature in FEATURES
        }
    return matrix


def _capstone_tuple(arch: int, mode: int) -> tuple[int | None, int | None]:
    if not capstone:
        return None, None
    if arch is None or mode is None:
        return None, None
    return arch, mode


def _cs_arch(name: str) -> int | None:
    if not capstone:
        return None
    return getattr(capstone, f"CS_ARCH_{name}", None)


def _cs_mode(name: str | None = None) -> int | None:
    if not capstone:
        return None
    if not name:
        return getattr(capstone, "CS_MODE_LITTLE_ENDIAN", 0)
    return getattr(capstone, f"CS_MODE_{name}", None)


def _normalize_endian(endian: str | None) -> str:
    normalized = (endian or "").strip().lower()
    aliases = {
        "le": "little",
        "little": "little",
        "little-endian": "little",
        "be": "big",
        "big": "big",
        "big-endian": "big",
    }
    return aliases.get(normalized, "little")


def _apply_endian_mode(
    mode: int | None, endian: str, *, allow_big_endian: bool = True
) -> int | None:
    if mode is None or not capstone:
        return mode
    normalized = _normalize_endian(endian)
    if normalized == "big" and allow_big_endian:
        endian_flag = getattr(capstone, "CS_MODE_BIG_ENDIAN", 0)
        return mode | endian_flag
    endian_flag = getattr(capstone, "CS_MODE_LITTLE_ENDIAN", 0)
    return mode | endian_flag


def _generic_adapter(key: str, display_name: str) -> ArchAdapter:
    return ArchAdapter(
        key=key,
        family=key,
        display_name=display_name,
        call_mnemonics=frozenset(),
        unconditional_jump_mnemonics=frozenset(),
        conditional_branch_mnemonics=frozenset(),
        return_mnemonics=frozenset(),
        prologue_patterns=(),
        data_ref_mnemonics=frozenset(),
        support={
            "disasm": FeatureSupport(
                "disasm-only", "Capstone decoder available; no ISA semantics table"
            ),
            **{
                feature: FeatureSupport(
                    "unsupported", "No CFG/Call Graph semantics for this ISA yet"
                )
                for feature in FEATURES
                if feature != "disasm"
            },
        },
    )


def _adapter_for_key(key: str, display_name: str | None = None) -> ArchAdapter:
    if key.startswith("x86"):
        return X86_ADAPTER
    if key == "arm64":
        return ARM64_ADAPTER
    if key == "arm32":
        return ARM32_ADAPTER
    if key in _PARTIAL_SEMANTIC_ADAPTERS:
        return _PARTIAL_SEMANTIC_ADAPTERS[key]
    return _generic_adapter(key, display_name or key.upper())


def _arch_info(
    *,
    key: str,
    bits: int,
    ptr_size: int,
    abi: str,
    raw_name: str,
    capstone_arch_name: str,
    capstone_mode: int | None,
    display_name: str,
    format_kind: str | None,
    machine: str | None,
    endian: str = "little",
    adapter: ArchAdapter | None = None,
) -> ArchInfo:
    cs_arch, cs_mode = _capstone_tuple(_cs_arch(capstone_arch_name), capstone_mode)
    return ArchInfo(
        key=key,
        bits=bits,
        ptr_size=ptr_size,
        abi=abi,
        raw_name=raw_name,
        capstone_arch=cs_arch,
        capstone_mode=cs_mode,
        adapter=adapter or _adapter_for_key(key, display_name),
        format_kind=format_kind,
        machine=machine,
        endian=endian,
    )


def get_raw_arch_info(raw_arch: str, endian: str | None = None) -> ArchInfo | None:
    """Resolution d'un profil de blob brut vers ArchInfo."""
    normalized = (raw_arch or "").strip().lower()
    normalized_endian = _normalize_endian(endian)
    aliases = {
        "x86": "i386",
        "i386": "i386",
        "x86_64": "i386:x86-64",
        "x86-64": "i386:x86-64",
        "amd64": "i386:x86-64",
        "i386:x86_64": "i386:x86-64",
        "i386:x86-64": "i386:x86-64",
        "arm": "arm",
        "arm32": "arm",
        "thumb": "thumb",
        "armthumb": "thumb",
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "mips": "mips32",
        "mips32": "mips32",
        "mips64": "mips64",
        "ppc": "ppc32",
        "powerpc": "ppc32",
        "ppc32": "ppc32",
        "powerpc32": "ppc32",
        "ppc64": "ppc64",
        "powerpc64": "ppc64",
        "sparc": "sparc",
        "sparc64": "sparcv9",
        "sparcv9": "sparcv9",
        "s390x": "sysz",
        "systemz": "sysz",
        "sysz": "sysz",
        "xcore": "xcore",
        "m68k": "m68k",
        "m680x": "m680x",
        "tms320c64x": "tms320c64x",
        "tms": "tms320c64x",
        "evm": "evm",
        "mos65xx": "mos65xx",
        "6502": "mos65xx",
        "wasm": "wasm",
        "bpf": "bpf",
        "ebpf": "bpf",
        "riscv": "riscv64",
        "riscv32": "riscv32",
        "riscv64": "riscv64",
        "sh": "sh",
        "sh4": "sh4",
        "tricore": "tricore",
    }
    kind = aliases.get(normalized, normalized)
    if kind == "i386":
        base_mode = _cs_mode("32")
        cs_mode = _apply_endian_mode(base_mode, "little", allow_big_endian=False)
        return _arch_info(
            key="x86_32",
            bits=32,
            ptr_size=4,
            abi="cdecl32",
            raw_name="i386",
            capstone_arch_name="X86",
            capstone_mode=cs_mode,
            adapter=X86_ADAPTER,
            format_kind="raw",
            machine="i386",
            endian="little",
            display_name="x86",
        )
    if kind == "i386:x86-64":
        base_mode = _cs_mode("64")
        cs_mode = _apply_endian_mode(base_mode, "little", allow_big_endian=False)
        return _arch_info(
            key="x86_64",
            bits=64,
            ptr_size=8,
            abi="sysv64",
            raw_name="i386:x86-64",
            capstone_arch_name="X86",
            capstone_mode=cs_mode,
            adapter=X86_ADAPTER,
            format_kind="raw",
            machine="x86_64",
            endian="little",
            display_name="x86-64",
        )
    if kind == "thumb":
        base_mode = (_cs_mode("THUMB") or 0) | (_cs_mode("MCLASS") or 0)
        cs_mode = _apply_endian_mode(base_mode, normalized_endian)
        return _arch_info(
            key="arm32",
            bits=32,
            ptr_size=4,
            abi="aapcs32",
            raw_name="thumb",
            capstone_arch_name="ARM",
            capstone_mode=cs_mode,
            adapter=ARM32_ADAPTER,
            format_kind="raw",
            machine="thumb",
            endian=normalized_endian,
            display_name="Thumb",
        )
    if kind == "arm":
        base_mode = _cs_mode("ARM")
        cs_mode = _apply_endian_mode(base_mode, normalized_endian)
        return _arch_info(
            key="arm32",
            bits=32,
            ptr_size=4,
            abi="aapcs32",
            raw_name="arm",
            capstone_arch_name="ARM",
            capstone_mode=cs_mode,
            adapter=ARM32_ADAPTER,
            format_kind="raw",
            machine="arm",
            endian=normalized_endian,
            display_name="ARM",
        )
    if kind == "aarch64":
        base_mode = _cs_mode("ARM")
        cs_mode = _apply_endian_mode(base_mode, normalized_endian)
        return _arch_info(
            key="arm64",
            bits=64,
            ptr_size=8,
            abi="aapcs64",
            raw_name="aarch64",
            capstone_arch_name="ARM64",
            capstone_mode=cs_mode,
            adapter=ARM64_ADAPTER,
            format_kind="raw",
            machine="aarch64",
            endian=normalized_endian,
            display_name="AArch64",
        )
    raw_specs: dict[str, tuple[str, int | None, int, int, str, str, bool, str]] = {
        "mips32": (
            "MIPS",
            _cs_mode("MIPS32"),
            32,
            4,
            "MIPS",
            "MIPS32",
            True,
            "mips_o32",
        ),
        "mips64": (
            "MIPS",
            _cs_mode("MIPS64"),
            64,
            8,
            "MIPS64",
            "MIPS64",
            True,
            "mips_n64",
        ),
        "ppc32": (
            "PPC",
            _cs_mode("32"),
            32,
            4,
            "PowerPC",
            "PowerPC",
            True,
            "ppc32_sysv",
        ),
        "ppc64": (
            "PPC",
            _cs_mode("64"),
            64,
            8,
            "PowerPC64",
            "PowerPC64",
            True,
            "ppc64_elfv2",
        ),
        "sparc": ("SPARC", _cs_mode(), 32, 4, "SPARC", "SPARC", True, "sparc"),
        "sparcv9": (
            "SPARC",
            _cs_mode("V9"),
            64,
            8,
            "SPARCV9",
            "SPARCV9",
            True,
            "sparc",
        ),
        "sysz": ("SYSZ", _cs_mode(), 64, 8, "SystemZ", "SystemZ", False, "sysz"),
        "xcore": ("XCORE", _cs_mode(), 32, 4, "XCore", "XCore", False, "generic"),
        "m68k": ("M68K", _cs_mode("M68K_000"), 32, 4, "M68K", "M68K", True, "generic"),
        "m680x": (
            "M680X",
            _cs_mode("M680X_6800"),
            16,
            2,
            "M680X",
            "M680X",
            False,
            "generic",
        ),
        "tms320c64x": (
            "TMS320C64X",
            _cs_mode(),
            32,
            4,
            "TMS320C64x",
            "TMS320C64x",
            False,
            "generic",
        ),
        "evm": ("EVM", _cs_mode(), 256, 32, "EVM", "EVM", False, "generic"),
        "mos65xx": (
            "MOS65XX",
            _cs_mode("MOS65XX_6502"),
            16,
            2,
            "MOS65XX",
            "MOS65XX",
            False,
            "generic",
        ),
        "wasm": (
            "WASM",
            _cs_mode(),
            32,
            4,
            "WebAssembly",
            "WebAssembly",
            False,
            "generic",
        ),
        "bpf": ("BPF", _cs_mode("BPF_EXTENDED"), 64, 8, "BPF", "BPF", False, "generic"),
        "riscv32": (
            "RISCV",
            _cs_mode("RISCV32"),
            32,
            4,
            "RISC-V32",
            "RISC-V32",
            False,
            "riscv",
        ),
        "riscv64": (
            "RISCV",
            _cs_mode("RISCV64"),
            64,
            8,
            "RISC-V64",
            "RISC-V64",
            False,
            "riscv",
        ),
        "sh": ("SH", _cs_mode("SH2"), 32, 4, "SuperH", "SuperH", False, "generic"),
        "sh4": ("SH", _cs_mode("SH4"), 32, 4, "SuperH4", "SuperH4", False, "generic"),
        "tricore": (
            "TRICORE",
            _cs_mode("TRICORE_162"),
            32,
            4,
            "TriCore",
            "TriCore",
            False,
            "generic",
        ),
    }
    spec = raw_specs.get(kind)
    if spec:
        (
            arch_name,
            base_mode,
            bits,
            ptr_size,
            display_name,
            raw_name,
            endian_aware,
            abi,
        ) = spec
        if base_mode is None:
            return None
        cs_mode = _apply_endian_mode(
            base_mode, normalized_endian, allow_big_endian=endian_aware
        )
        resolved_endian = normalized_endian if endian_aware else "little"
        return _arch_info(
            key=kind,
            bits=bits,
            ptr_size=ptr_size,
            abi=abi,
            raw_name=raw_name,
            capstone_arch_name=arch_name,
            capstone_mode=cs_mode,
            format_kind="raw",
            machine=raw_name,
            endian=resolved_endian,
            display_name=display_name,
        )
    return None


def _binary_info_from_raw_profile(
    raw_arch: str,
    *,
    format_kind: str,
    machine: str,
    endian: str = "little",
) -> ArchInfo | None:
    info = get_raw_arch_info(raw_arch, endian)
    if info is None:
        return None
    return ArchInfo(
        key=info.key,
        bits=info.bits,
        ptr_size=info.ptr_size,
        abi=info.abi,
        raw_name=info.raw_name,
        capstone_arch=info.capstone_arch,
        capstone_mode=info.capstone_mode,
        adapter=info.adapter,
        format_kind=format_kind,
        machine=machine,
        endian=info.endian,
    )


def _detect_arch_from_machine_name(
    machine_name: str,
    *,
    format_kind: str,
    endian: str = "little",
    bits: int | None = None,
) -> ArchInfo | None:
    """Fallback LIEF -> Capstone mapping for architectures outside rich analysis support."""
    normalized = re.sub(r"[^A-Z0-9]+", "_", str(machine_name or "").upper()).strip("_")
    if not normalized:
        return None
    candidates: list[str] = []
    if normalized in {"X86_64", "AMD64"}:
        candidates.append("i386:x86-64")
    elif normalized in {"I386", "X86", "CHPE_X86"}:
        candidates.append("i386")
    elif normalized in {"AARCH64", "ARM64", "ARM64EC", "ARM64X"}:
        candidates.append("aarch64")
    elif normalized in {"ARM", "ARMNT", "THUMB"}:
        candidates.append("thumb" if normalized == "THUMB" else "arm")
    elif "MIPS64" in normalized:
        candidates.append("mips64")
    elif "MIPS" in normalized or normalized in {"R4000", "WCEMIPSV2"}:
        candidates.append("mips64" if bits == 64 else "mips32")
    elif normalized in {"PPC64", "POWERPC64"}:
        candidates.append("ppc64")
    elif normalized in {"PPC", "POWERPC", "POWERPCFP", "POWERPCBE"}:
        candidates.append("ppc32")
    elif normalized in {"SPARCV9", "SPARC64"}:
        candidates.append("sparcv9")
    elif normalized in {"SPARC", "SPARC32PLUS"}:
        candidates.append("sparc")
    elif normalized in {"S390", "SYSZ"}:
        candidates.append("sysz")
    elif normalized == "XCORE":
        candidates.append("xcore")
    elif normalized in {"M68K", "COLDFIRE"}:
        candidates.append("m68k")
    elif normalized in {"M68HC05", "M68HC08", "M68HC11", "M68HC12", "M68HC16"}:
        candidates.append("m680x")
    elif normalized in {"TI_C6000", "TMS320C64X"}:
        candidates.append("tms320c64x")
    elif "BPF" in normalized:
        candidates.append("bpf")
    elif normalized == "RISCV":
        candidates.extend(
            ["riscv32", "riscv64"] if bits == 32 else ["riscv64", "riscv32"]
        )
    elif normalized in {"SH", "SH3", "SH3DSP", "SH4", "SH5"}:
        candidates.append("sh4" if "4" in normalized else "sh")
    elif normalized == "TRICORE":
        candidates.append("tricore")
    for candidate in candidates:
        info = _binary_info_from_raw_profile(
            candidate,
            format_kind=format_kind,
            machine=machine_name,
            endian=endian,
        )
        if info is not None and info.capstone_tuple is not None:
            return info
    return None


def _elf_class_bits(binary) -> int | None:
    header = getattr(binary, "header", None)
    identity_class = getattr(header, "identity_class", None)
    text = getattr(identity_class, "name", str(identity_class or "")).upper()
    if "64" in text:
        return 64
    if "32" in text:
        return 32
    return None


def detect_binary_arch(binary) -> ArchInfo | None:
    """Resolution d'un objet binaire LIEF en ArchInfo."""
    if not lief:
        return None

    if isinstance(binary, lief.ELF.Binary):
        machine = binary.header.machine_type
        machine_name = getattr(machine, "name", str(machine))
        if machine == lief.ELF.ARCH.X86_64:
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_X86", None),
                getattr(capstone, "CS_MODE_64", None),
            )
            return ArchInfo(
                "x86_64",
                64,
                8,
                "sysv64",
                "i386:x86-64",
                cs_arch,
                cs_mode,
                X86_ADAPTER,
                "elf",
                machine_name,
            )
        if machine in {
            getattr(lief.ELF.ARCH, "X86", None),
            getattr(lief.ELF.ARCH, "I386", None),
        } - {None}:
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_X86", None),
                getattr(capstone, "CS_MODE_32", None),
            )
            return ArchInfo(
                "x86_32",
                32,
                4,
                "cdecl32",
                "i386",
                cs_arch,
                cs_mode,
                X86_ADAPTER,
                "elf",
                machine_name,
            )
        if machine == lief.ELF.ARCH.AARCH64:
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_ARM64", None),
                getattr(capstone, "CS_MODE_ARM", None),
            )
            return ArchInfo(
                "arm64",
                64,
                8,
                "aapcs64",
                "aarch64",
                cs_arch,
                cs_mode,
                ARM64_ADAPTER,
                "elf",
                machine_name,
            )
        if machine == getattr(lief.ELF.ARCH, "ARM", None):
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_ARM", None),
                getattr(capstone, "CS_MODE_ARM", None),
            )
            return ArchInfo(
                "arm32",
                32,
                4,
                "aapcs32",
                "arm",
                cs_arch,
                cs_mode,
                ARM32_ADAPTER,
                "elf",
                machine_name,
            )
        fallback = _detect_arch_from_machine_name(
            machine_name,
            format_kind="elf",
            bits=_elf_class_bits(binary),
        )
        if fallback is not None:
            return fallback

    if isinstance(binary, lief.MachO.Binary):
        cpu_name = binary.header.cpu_type.name
        if cpu_name == "X86_64":
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_X86", None),
                getattr(capstone, "CS_MODE_64", None),
            )
            return ArchInfo(
                "x86_64",
                64,
                8,
                "sysv64",
                "i386:x86-64",
                cs_arch,
                cs_mode,
                X86_ADAPTER,
                "macho",
                cpu_name,
            )
        if cpu_name == "X86":
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_X86", None),
                getattr(capstone, "CS_MODE_32", None),
            )
            return ArchInfo(
                "x86_32",
                32,
                4,
                "cdecl32",
                "i386",
                cs_arch,
                cs_mode,
                X86_ADAPTER,
                "macho",
                cpu_name,
            )
        if cpu_name == "ARM64":
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_ARM64", None),
                getattr(capstone, "CS_MODE_ARM", None),
            )
            return ArchInfo(
                "arm64",
                64,
                8,
                "aapcs64",
                "aarch64",
                cs_arch,
                cs_mode,
                ARM64_ADAPTER,
                "macho",
                cpu_name,
            )
        if cpu_name == "ARM":
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_ARM", None),
                getattr(capstone, "CS_MODE_ARM", None),
            )
            return ArchInfo(
                "arm32",
                32,
                4,
                "aapcs32",
                "arm",
                cs_arch,
                cs_mode,
                ARM32_ADAPTER,
                "macho",
                cpu_name,
            )
        fallback = _detect_arch_from_machine_name(cpu_name, format_kind="macho")
        if fallback is not None:
            return fallback

    if isinstance(binary, lief.PE.Binary):
        machine = binary.header.machine
        machine_name = getattr(machine, "name", str(machine))
        MT = lief.PE.Header.MACHINE_TYPES
        if machine == MT.AMD64:
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_X86", None),
                getattr(capstone, "CS_MODE_64", None),
            )
            return ArchInfo(
                "x86_64",
                64,
                8,
                "win64",
                "i386:x86-64",
                cs_arch,
                cs_mode,
                X86_ADAPTER,
                "pe",
                machine_name,
            )
        if machine == MT.I386:
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_X86", None),
                getattr(capstone, "CS_MODE_32", None),
            )
            return ArchInfo(
                "x86_32",
                32,
                4,
                "cdecl32",
                "i386",
                cs_arch,
                cs_mode,
                X86_ADAPTER,
                "pe",
                machine_name,
            )
        if machine == MT.ARM64:
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_ARM64", None),
                getattr(capstone, "CS_MODE_ARM", None),
            )
            return ArchInfo(
                "arm64",
                64,
                8,
                "aapcs64",
                "aarch64",
                cs_arch,
                cs_mode,
                ARM64_ADAPTER,
                "pe",
                machine_name,
            )
        if machine == getattr(MT, "ARM", None):
            cs_arch, cs_mode = _capstone_tuple(
                getattr(capstone, "CS_ARCH_ARM", None),
                getattr(capstone, "CS_MODE_ARM", None),
            )
            return ArchInfo(
                "arm32",
                32,
                4,
                "aapcs32",
                "arm",
                cs_arch,
                cs_mode,
                ARM32_ADAPTER,
                "pe",
                machine_name,
            )
        fallback_endian = "big" if machine_name.upper().endswith("BE") else "little"
        fallback = _detect_arch_from_machine_name(
            machine_name,
            format_kind="pe",
            endian=fallback_endian,
        )
        if fallback is not None:
            return fallback

    return None


def detect_binary_arch_from_path(binary_path: str) -> ArchInfo | None:
    """Parse le binaire avec LIEF puis retourne ArchInfo."""
    if not lief:
        return None
    try:
        binary = lief.parse(binary_path)
    except Exception:
        return None
    if binary is None:
        return None
    return detect_binary_arch(binary)
