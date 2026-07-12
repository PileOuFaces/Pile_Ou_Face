const { expect } = require("chai");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

describe("annotationsBridge", () => {
  function makeBridge(runPythonStub) {
    return proxyquire("../shared/annotationsBridge", {
      "./pythonRunner": { makeRunPython: () => runPythonStub },
    });
  }

  it("loadAnnotations calls list --grouped and parses stdout", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: JSON.stringify({ "0x1": { comment: "hi" } }) });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    const result = await bridge.loadAnnotations("/bin/target");
    expect(result).to.deep.equal({ "0x1": { comment: "hi" } });
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include("list");
    expect(args).to.include("--grouped");
    expect(args).to.include("--binary");
    expect(args).to.include("/bin/target");
  });

  it("saveAnnotation calls annotate with comment and name", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    await bridge.saveAnnotation("/bin/target", "0x1", { comment: "c", name: "n" });
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["annotate", "--addr", "0x1", "--comment", "c", "--name", "n"]);
  });

  it("respects an explicit dbPathOverride for tests", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e", dbPathOverride: "/tmp/test.db" });
    await bridge.loadAnnotations("/bin/target");
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["--cache-db", "/tmp/test.db"]);
  });

  it("saveFunctionReview calls review with status and notes", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    await bridge.saveFunctionReview("/bin/target", "0x1", { reviewStatus: "reviewed", reviewNotes: "n" });
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["review", "--addr", "0x1", "--status", "reviewed", "--notes", "n"]);
  });

  it("saveBookmark calls bookmark with label and color", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    await bridge.saveBookmark("/bin/target", "0x1", { label: "L", color: "#123456" });
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["bookmark", "--addr", "0x1", "--label", "L", "--color", "#123456"]);
  });

  it("deleteBookmark calls delete-bookmark with addr", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    await bridge.deleteBookmark("/bin/target", "0x1");
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["delete-bookmark", "--addr", "0x1"]);
  });

  it("clearBookmarks calls clear-bookmarks", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    await bridge.clearBookmarks("/bin/target");
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include("clear-bookmarks");
  });

  it("deleteAnnotation calls delete with addr", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    await bridge.deleteAnnotation("/bin/target", "0x1");
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["delete", "--addr", "0x1"]);
  });

  it("migrateLegacyJson calls migrate-legacy with JSON-encoded payload", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    const legacy = { "0x1": { comment: "old" } };
    await bridge.migrateLegacyJson("/bin/target", legacy);
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["migrate-legacy", "--json", JSON.stringify(legacy)]);
  });
});
