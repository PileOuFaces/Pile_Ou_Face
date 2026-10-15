const { expect } = require("chai");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

describe("patchHistoryBridge", () => {
  function makeBridge(runPython) {
    return proxyquire("../shared/patchHistoryBridge", {
      "./pythonRunner": { makeRunPython: () => runPython },
    }).makePatchHistoryBridge({ root: "/workspace" });
  }

  it("deletes one binary history through the SQLite CLI", async () => {
    const runPython = sinon.stub().resolves({ stdout: '{"ok":true,"removed":1}' });

    const result = await makeBridge(runPython).deleteHistory("/workspace/a.bin");

    expect(result.removed).to.equal(1);
    expect(runPython.calledOnceWithExactly([
      "backends/static/patch/patch_manager.py",
      "delete",
      "--binary",
      "/workspace/a.bin",
    ])).to.equal(true);
  });

  it("purges missing histories only for the requested workspace", async () => {
    const runPython = sinon.stub().resolves({ stdout: '{"ok":true,"removed":2}' });

    const result = await makeBridge(runPython).purgeMissing("/workspace");

    expect(result.removed).to.equal(2);
    expect(runPython.firstCall.args[0]).to.deep.equal([
      "backends/static/patch/patch_manager.py",
      "purge-missing",
      "--workspace",
      "/workspace",
    ]);
  });
});
