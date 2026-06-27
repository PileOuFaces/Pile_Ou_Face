const { expect } = require("chai");
const sinon = require("sinon");
const fs = require("fs");

const { resolveProjectRoot } = require("../src/shared/utils");

describe("project root resolution", () => {
  afterEach(() => {
    sinon.restore();
  });

  it("keeps a direct public repo root unchanged", () => {
    const existsSync = sinon.stub(fs, "existsSync").callsFake((targetPath) => (
      targetPath === "/repo/extension/package.json" || targetPath === "/repo/backends"
    ));

    expect(resolveProjectRoot("/repo")).to.equal("/repo");
    expect(existsSync.called).to.equal(true);
  });

  it("resolves the public child repo when the workspace is opened on the umbrella directory", () => {
    sinon.stub(fs, "existsSync").callsFake((targetPath) => (
      targetPath === "/umbrella/Pile_Ou_Face/extension/package.json"
      || targetPath === "/umbrella/Pile_Ou_Face/backends"
    ));
    sinon.stub(fs, "readdirSync").returns([
      { isDirectory: () => true, name: "Pile_Ou_Face" },
      { isDirectory: () => true, name: "Pile_ou_Face_plugins" },
    ]);

    expect(resolveProjectRoot("/umbrella")).to.equal("/umbrella/Pile_Ou_Face");
  });
});
