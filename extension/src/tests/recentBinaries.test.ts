const { expect } = require("chai");

const {
  MAX_RECENT_BINARIES,
  getRecentBinaries,
  rememberRecentBinary,
  forgetRecentBinary,
  clearRecentBinaries,
  describeRecentBinaryMeta,
} = require("../shared/recentBinaries");

function makeContext(initialEntries = []) {
  const state = new Map([
    ["reverse-workspace.recent-binaries", initialEntries],
  ]);
  return {
    workspaceState: {
      get(key, fallback) {
        return state.has(key) ? state.get(key) : fallback;
      },
      async update(key, value) {
        state.set(key, value);
      },
    },
  };
}

describe("recentBinaries", () => {
  it("stores recent binaries with newest-first deduplication", async () => {
    const context = makeContext();

    await rememberRecentBinary(context, "/tmp/demo.bin", { kind: "native", format: "ELF", arch: "x86-64" });
    await rememberRecentBinary(context, "/tmp/blob.raw", {
      kind: "raw",
      format: "RAW",
      rawConfig: { arch: "thumb", endian: "little", baseAddr: "0x7000" },
    });
    await rememberRecentBinary(context, "/tmp/demo.bin", { kind: "native", format: "ELF", arch: "x86-64" });

    const recent = getRecentBinaries(context);
    expect(recent.map((entry) => entry.path)).to.deep.equal([
      "/tmp/demo.bin",
      "/tmp/blob.raw",
    ]);
    expect(recent[1].meta.rawConfig).to.deep.include({
      arch: "thumb",
      endian: "little",
      baseAddr: "0x7000",
    });
  });

  it("forgets and clears recent binaries", async () => {
    const context = makeContext();

    for (let index = 0; index < MAX_RECENT_BINARIES + 2; index++) {
      await rememberRecentBinary(context, `/tmp/sample-${index}.bin`, { kind: "native", format: "ELF" });
    }
    expect(getRecentBinaries(context)).to.have.length(MAX_RECENT_BINARIES);

    await forgetRecentBinary(context, "/tmp/sample-3.bin");
    expect(getRecentBinaries(context).map((entry) => entry.path)).to.not.include("/tmp/sample-3.bin");

    await clearRecentBinaries(context);
    expect(getRecentBinaries(context)).to.deep.equal([]);
  });

  it("formats recent metadata for quick-pick descriptions", () => {
    expect(describeRecentBinaryMeta({ kind: "native", format: "PE", arch: "x86-64" })).to.equal("PE · x86-64");
    expect(describeRecentBinaryMeta({
      kind: "raw",
      format: "RAW",
      rawConfig: { arch: "mips32", endian: "big", baseAddr: "0x800000" },
    })).to.equal("blob brut · RAW · mips32");
  });
});
