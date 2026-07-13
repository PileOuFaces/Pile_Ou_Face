const { expect } = require("chai");
const {
  getKnownOciImagePlatform,
  _filterOciVersionTags,
} = require("../static/decompilerCommands");

const PREFIX = "ghcr.io/pileoufaces/pile-ou-face";

describe("getKnownOciImagePlatform", () => {
  it("resolves retdec platform regardless of the tag (pinned or latest)", () => {
    // retdec est amd64-only ; la détection doit marcher quel que soit le tag.
    expect(getKnownOciImagePlatform(`${PREFIX}/decompiler-retdec:1.0.0`)).to.equal(
      "linux/amd64",
    );
    expect(getKnownOciImagePlatform(`${PREFIX}/decompiler-retdec:latest`)).to.equal(
      "linux/amd64",
    );
  });

  it("returns empty for an OCI image without platform pin (ghidra)", () => {
    expect(getKnownOciImagePlatform(`${PREFIX}/decompiler-ghidra:1.0.0`)).to.equal("");
  });

  it("returns empty for a non-PileOuFaces image", () => {
    expect(getKnownOciImagePlatform("registry/other-tool:1.0")).to.equal("");
    expect(getKnownOciImagePlatform("")).to.equal("");
  });
});

describe("_filterOciVersionTags", () => {
  it("keeps only X.Y.Z tags, newest first, dropping latest/develops/sha", () => {
    const tags = ["latest", "1.0.0", "develops", "2.1.0", "sha-abc1234", "1.2.0", "2.0.0"];
    expect(_filterOciVersionTags(tags)).to.deep.equal([
      "2.1.0",
      "2.0.0",
      "1.2.0",
      "1.0.0",
    ]);
  });

  it("sorts numerically, not lexicographically", () => {
    expect(_filterOciVersionTags(["9.0.0", "10.0.0", "2.0.0"])).to.deep.equal([
      "10.0.0",
      "9.0.0",
      "2.0.0",
    ]);
  });

  it("returns [] for empty or non-array input", () => {
    expect(_filterOciVersionTags([])).to.deep.equal([]);
    expect(_filterOciVersionTags(null)).to.deep.equal([]);
    expect(_filterOciVersionTags(undefined)).to.deep.equal([]);
  });
});
