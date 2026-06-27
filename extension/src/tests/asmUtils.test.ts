// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");

const asmUtils = require("../static/hub/asmUtils");

function line(addr, text) {
  return { addr, text };
}

describe("asmUtils", () => {
  describe("literal parsing", () => {
    it("parses signed decimal and hexadecimal numbers", () => {
      expect(asmUtils.parseIntLiteral("42")).to.equal(42);
      expect(asmUtils.parseIntLiteral("+42")).to.equal(42);
      expect(asmUtils.parseIntLiteral("-42")).to.equal(-42);
      expect(asmUtils.parseIntLiteral("0x2a")).to.equal(42);
      expect(asmUtils.parseIntLiteral("-0x2a")).to.equal(-42);
    });

    it("rejects empty and malformed integer literals", () => {
      expect(asmUtils.parseIntLiteral("")).to.equal(null);
      expect(asmUtils.parseIntLiteral("0x")).to.equal(null);
      expect(asmUtils.parseIntLiteral("12px")).to.equal(null);
    });

    it("parses bigint literals without losing precision", () => {
      expect(asmUtils.parseBigIntLiteral("0x10000000000000000")).to.equal(0x10000000000000000n);
      expect(asmUtils.parseBigIntLiteral("-15")).to.equal(-15n);
      expect(asmUtils.parseBigIntLiteral("nope")).to.equal(null);
    });
  });

  describe("ASM normalization", () => {
    it("extracts the instruction after the disassembly tab and collapses spaces", () => {
      expect(asmUtils.extractAsm("00401000:\tcmp    eax,   0x2a")).to.equal("cmp eax, 0x2a");
      expect(asmUtils.extractAsm("  mov   rax, rbx  ")).to.equal("mov rax, rbx");
    });

    it("normalizes hexadecimal addresses", () => {
      expect(asmUtils.normalizeAddress("401000")).to.deep.equal({ norm: "0x401000", value: 0x401000 });
      expect(asmUtils.normalizeAddress("0X401000")).to.deep.equal({ norm: "0x401000", value: 0x401000 });
      expect(asmUtils.normalizeAddress("")).to.equal(null);
      expect(asmUtils.normalizeAddress("not-an-address")).to.equal(null);
    });
  });

  describe("stack and register helpers", () => {
    it("extracts rbp/ebp frame offsets", () => {
      expect(asmUtils.extractFrameOffset("[rbp]")).to.equal(0);
      expect(asmUtils.extractFrameOffset("[rbp - 0x20]")).to.equal(-32);
      expect(asmUtils.extractFrameOffset("[ebp+12]")).to.equal(12);
      expect(asmUtils.extractFrameOffset("[rsp - 0x20]")).to.equal(null);
    });

    it("detects x86 register widths", () => {
      expect(asmUtils.regWidthBytes("al")).to.equal(1);
      expect(asmUtils.regWidthBytes("r9b")).to.equal(1);
      expect(asmUtils.regWidthBytes("ax")).to.equal(2);
      expect(asmUtils.regWidthBytes("r10w")).to.equal(2);
      expect(asmUtils.regWidthBytes("eax")).to.equal(4);
      expect(asmUtils.regWidthBytes("r11d")).to.equal(4);
      expect(asmUtils.regWidthBytes("rax")).to.equal(8);
      expect(asmUtils.regWidthBytes("r12")).to.equal(8);
      expect(asmUtils.regWidthBytes("notareg")).to.equal(null);
    });

    it("tracks register aliases to stack offsets inside a local window", () => {
      const offsets = asmUtils.collectRegOffsets([
        line("0x1", "lea rdi, [rbp - 0x40]"),
        line("0x2", "mov rsi, rdi"),
        line("0x3", "mov rdx, 123"),
        line("0x4", "xor rsi, rsi"),
      ], 0, 3);

      expect(offsets).to.deep.equal({
        rdi: -64,
      });
    });
  });

  describe("cmp parsing", () => {
    it("parses register and memory cmp immediates", () => {
      expect(asmUtils.parseCmpInfo("cmp eax, 0x41424344")).to.include({
        lhs: "eax",
        rhsToken: "0x41424344",
        width: 4,
        lhsReg: "eax",
      });

      expect(asmUtils.parseCmpInfo("cmp byte ptr [rbp - 1], -1")).to.include({
        lhs: "byte ptr [rbp - 1]",
        rhsToken: "-1",
        width: 1,
        lhsReg: null,
      });
    });

    it("rejects unsupported cmp forms", () => {
      expect(asmUtils.parseCmpInfo("test eax, eax")).to.equal(null);
      expect(asmUtils.parseCmpInfo("cmp [rbp-4], eax")).to.equal(null);
      expect(asmUtils.parseCmpInfo("cmp xmm0, 1")).to.equal(null);
    });

    it("normalizes libc callee names", () => {
      expect(asmUtils.normalizeCalleeName("__isoc99_scanf@plt")).to.equal("scanf");
      expect(asmUtils.normalizeCalleeName("__GI_memcpy")).to.equal("memcpy");
      expect(asmUtils.normalizeCalleeName(null)).to.equal(null);
    });
  });

  describe("architecture detection", () => {
    it("detects 64-bit and 32-bit disassembly snippets", () => {
      expect(asmUtils.detectArchBitsFromLines([
        line("0x1", "push rbp"),
        line("0x2", "mov rbp, rsp"),
      ])).to.equal(64);

      expect(asmUtils.detectArchBitsFromLines([
        line("0x1", "push ebp"),
        line("0x2", "mov ebp, esp"),
      ])).to.equal(32);
    });

    it("defaults to 64-bit when no x86 register is found", () => {
      expect(asmUtils.detectArchBitsFromLines([line("0x1", "nop")])).to.equal(64);
    });
  });

  describe("payload suggestion", () => {
    it("builds a payload from a 64-bit vulnerable call and direct stack cmp", () => {
      const suggestion = asmUtils.buildCmpPayloadSuggestion([
        line("0x401000", "push rbp"),
        line("0x401001", "mov rbp, rsp"),
        line("0x401010", "lea rdi, [rbp - 0x40]"),
        line("0x401014", "call <strcpy@plt>"),
        line("0x401020", "cmp dword ptr [rbp - 0x4], 0x41424344"),
      ], "0x401020");

      expect(suggestion).to.include({
        cmpAddr: "0x401020",
        cmpInstr: "cmp dword ptr [rbp - 0x4], 0x41424344",
        sourceCall: "strcpy",
        archBits: 64,
        bufferOffset: -64,
        varOffset: -4,
        padding: 60,
        cmpWidth: 4,
        cmpImmediate: "0x41424344",
        cmpImmediateBytesLe: "44434241",
        suffix: "DCBA",
        payloadExpr: "A*60+DCBA",
        warning: null,
      });
      expect(suggestion.captureBufferOffset).to.equal(-80);
      expect(suggestion.captureBufferSize).to.be.at.least(96);
    });

    it("resolves the compared stack variable through a register load", () => {
      const suggestion = asmUtils.buildCmpPayloadSuggestion([
        line("0x401000", "push rbp"),
        line("0x401001", "mov rbp, rsp"),
        line("0x401010", "lea rdi, [rbp - 0x30]"),
        line("0x401014", "call <gets>"),
        line("0x401018", "mov eax, dword ptr [rbp - 0x8]"),
        line("0x401020", "cmp eax, 0x2a"),
      ], "401020");

      expect(suggestion).to.include({
        cmpAddr: "0x401020",
        sourceCall: "gets",
        bufferOffset: -48,
        varOffset: -8,
        padding: 40,
        cmpWidth: 4,
        cmpImmediate: "0x0000002a",
        cmpImmediateBytesLe: "2a000000",
        suffix: "",
        payloadExpr: "A*40+BBBB",
        warning: "Valeur CMP non printable: suffixe remplacé par des B.",
      });
    });

    it("uses pushed 32-bit call arguments to locate the destination buffer", () => {
      const suggestion = asmUtils.buildCmpPayloadSuggestion([
        line("0x8048000", "push ebp"),
        line("0x8048001", "mov ebp, esp"),
        line("0x8048010", "push [ebp - 0x24]"),
        line("0x8048014", "call <scanf>"),
        line("0x8048020", "cmp word ptr [ebp - 0x2], 0x4f4b"),
      ], "0x8048020");

      expect(suggestion).to.include({
        sourceCall: "scanf",
        archBits: 32,
        bufferOffset: -36,
        varOffset: -2,
        padding: 34,
        cmpWidth: 2,
        cmpImmediate: "0x4f4b",
        cmpImmediateBytesLe: "4b4f",
        suffix: "KO",
        payloadExpr: "A*34+KO",
      });
    });

    it("falls back to the closest prior lea when no vulnerable call is found", () => {
      const suggestion = asmUtils.buildCmpPayloadSuggestion([
        line("0x401000", "push rbp"),
        line("0x401001", "mov rbp, rsp"),
        line("0x401010", "lea rax, [rbp - 0x50]"),
        line("0x401018", "lea rdx, [rbp - 0x20]"),
        line("0x401020", "cmp qword ptr [rbp - 0x8], 0x4141414141414141"),
      ], "0x401020");

      expect(suggestion).to.include({
        sourceCall: null,
        bufferOffset: -80,
        varOffset: -8,
        padding: 72,
        cmpWidth: 8,
        suffix: "AAAAAAAA",
        payloadExpr: "A*72+AAAAAAAA",
      });
    });

    it("reports actionable errors for invalid CMP targets", () => {
      expect(() => asmUtils.buildCmpPayloadSuggestion([], "wat"))
        .to.throw("Adresse CMP invalide");

      expect(() => asmUtils.buildCmpPayloadSuggestion([
        line("0x401000", "nop"),
      ], "0x401020")).to.throw("absente du désassemblage");

      expect(() => asmUtils.buildCmpPayloadSuggestion([
        line("0x401020", "add eax, 1"),
      ], "0x401020")).to.throw("Instruction non supportée");
    });
  });
});
