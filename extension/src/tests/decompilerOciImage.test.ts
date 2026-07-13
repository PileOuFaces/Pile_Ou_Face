const { expect } = require("chai");
const { getKnownOciImagePlatform } = require("../static/decompilerCommands");

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
