const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { ensureStorageDir, ensureTempDir, getStorageDir, getTempDir } = require("../shared/utils");

describe("extension storage dir", () => {
  it("uses workspace storage when available", () => {
    const context = {
      storageUri: { fsPath: "/workspace-storage" },
      globalStorageUri: { fsPath: "/global-storage" },
    };

    expect(getStorageDir(context)).to.equal("/workspace-storage");
  });

  it("falls back to global storage when workspace storage is unavailable", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pof-storage-"));
    const globalStorage = path.join(tempRoot, "global-storage");

    const context = {
      globalStorageUri: { fsPath: globalStorage },
    };

    expect(getStorageDir(context)).to.equal(globalStorage);
    expect(ensureStorageDir(context)).to.equal(globalStorage);
    expect(fs.existsSync(globalStorage)).to.equal(true);
  });

  it("keeps temp artifacts out of the workspace project directory", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pof-temp-root-"));

    const tempDir = ensureTempDir(tempRoot);

    expect(tempDir).to.equal(getTempDir(tempRoot));
    expect(tempDir.startsWith(path.join(os.tmpdir(), "pile-ou-face"))).to.equal(true);
    expect(fs.existsSync(tempDir)).to.equal(true);
    expect(fs.existsSync(path.join(tempRoot, ".pile-ou-face"))).to.equal(false);

    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempDir, { recursive: true, force: true });
  });
});
