const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { ensureStorageDir, getStorageDir } = require("../shared/utils");

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
});
