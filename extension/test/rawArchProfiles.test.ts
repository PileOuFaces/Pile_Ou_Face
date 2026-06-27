const { expect } = require("chai");

const sharedHandlers = require("../src/shared/sharedHandlers");

describe("raw architecture profiles", () => {
  it("offers RISC-V raw profiles in the blob architecture picker", () => {
    const values = sharedHandlers.RAW_ARCH_ITEMS.map((item) => item.value);

    expect(values).to.include("riscv32");
    expect(values).to.include("riscv64");
  });

  it("normalizes riscv64 raw metadata without losing the selected architecture", () => {
    const profile = sharedHandlers.normalizeRawProfile({
      arch: "riscv64",
      endian: "little",
      baseAddr: "0x417000",
    });

    expect(profile).to.deep.equal({
      kind: "raw",
      arch: "riscv64",
      baseAddr: "0x417000",
      endian: "little",
    });
  });

  it("normalizes common architecture aliases used by binaries and users", () => {
    const cases = {
      amd64: "i386:x86-64",
      x64: "i386:x86-64",
      arm64: "aarch64",
      mips: "mips32",
      powerpc64: "ppc64",
      sparc32: "sparc",
      sparc64: "sparcv9",
      riscv: "riscv64",
      ebpf: "bpf",
      "6502": "mos65xx",
    };

    for (const [input, expected] of Object.entries(cases)) {
      expect(sharedHandlers.normalizeRawArchName(input)).to.equal(expected);
    }
  });

  it("exposes bitness for every raw architecture offered in the picker", () => {
    for (const item of sharedHandlers.RAW_ARCH_ITEMS) {
      const descriptor = sharedHandlers.getRawArchDescriptor(item.value);

      expect(descriptor.arch).to.equal(item.value);
      expect(descriptor.bits, item.value).to.be.a("number").and.to.be.greaterThan(0);
      expect(descriptor.pointerSize, item.value).to.be.a("number").and.to.be.greaterThan(0);
      expect(descriptor.displayName, item.value).to.be.a("string").and.not.to.equal("");
    }
  });

  it("forces little-endian for architectures where Capstone has no endian mode", () => {
    const profile = sharedHandlers.normalizeRawProfile({
      arch: "riscv64",
      endian: "big",
      baseAddr: "0x0",
    });

    expect(profile.endian).to.equal("little");
  });
});
