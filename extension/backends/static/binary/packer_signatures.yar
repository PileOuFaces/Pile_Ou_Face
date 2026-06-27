// SPDX-License-Identifier: AGPL-3.0-only
// Packer byte-pattern signatures for Pile ou Face static analysis.
// Each rule has a `family` meta field used by _scan_with_yara() in headers.py.

rule UPX_PE_x86 {
    meta:
        family = "UPX"
        description = "UPX packed PE x86 — pushad stub + UPX! magic"
    strings:
        $magic   = "UPX!"
        $ep_stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? FF FF 57 83 CD FF }
    condition:
        $magic and $ep_stub
}

rule UPX_PE_x64 {
    meta:
        family = "UPX"
        description = "UPX packed PE x64 — push-sequence stub + UPX! magic"
    strings:
        $magic     = "UPX!"
        $stub_v3   = { 53 56 57 55 48 81 EC ?? ?? 00 00 }
        $stub_v4   = { 41 57 41 56 41 55 41 54 55 57 56 }
    condition:
        $magic and ($stub_v3 or $stub_v4)
}

rule UPX_ELF {
    meta:
        family = "UPX"
        description = "UPX packed ELF — ELF magic + UPX section names + UPX! marker"
    strings:
        $elf_magic   = { 7F 45 4C 46 }
        $upx_magic   = "UPX!"
        $upx_section = "UPX0"
    condition:
        $elf_magic at 0 and $upx_magic and $upx_section
}

rule ASPack {
    meta:
        family      = "ASPack"
        description = "ASPack packer — EP stub + section name"
    strings:
        $ep_stub  = { 60 E8 00 00 00 00 58 83 E8 05 }
        $section1 = ".aspack"
        $section2 = ".adata"
    condition:
        $ep_stub and ($section1 or $section2)
}

rule MPRESS {
    meta:
        family = "MPRESS"
        description = "MPRESS packer — section names or resource marker"
    strings:
        $section1 = ".MPRESS1"
        $section2 = ".MPRESS2"
        $header   = "MRsource"
    condition:
        ($section1 and $section2) or $header
}

rule Petite {
    meta:
        family      = "Petite"
        description = "Petite packer — EP stub and section name"
    strings:
        $ep_stub = { B8 ?? ?? ?? 00 68 ?? ?? ?? 00 64 FF 35 00 00 00 00 }
        $section = ".petite"
    condition:
        $ep_stub and $section
}

rule PECompact {
    meta:
        family      = "PECompact"
        description = "PECompact packer — EP stub with section names or section names alone"
    strings:
        $ep_stub  = { EB 06 68 ?? ?? ?? ?? C3 }
        $section1 = "pec1"
        $section2 = "pec2"
    condition:
        $ep_stub and ($section1 or $section2)
}
