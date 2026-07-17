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

  it("deleteAnnotation calls delete-annotation with addr", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPythonStub).makeAnnotationsBridge({ root: "/r", extensionPath: "/e" });
    await bridge.deleteAnnotation("/bin/target", "0x1");
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["delete-annotation", "--addr", "0x1"]);
  });

  it("deleteAnnotation against the real CLI preserves bookmark/review (integration)", async function () {
    this.timeout(10000);
    const os = require("os");
    const path = require("path");
    const fs = require("fs");
    // No proxyquire here: this test exercises the real annotations.py CLI
    // through the real pythonRunner, to catch bridge/CLI format mismatches
    // that a fully-mocked runPython would hide (see: delete vs delete-annotation).
    const { makeAnnotationsBridge } = require("../shared/annotationsBridge");

    // extension/src/tests -> extension (same ROOT resolution as
    // backends/static/tests/test_annotations_cli.py's Path(__file__).parent.parent.parent.parent)
    const extensionRoot = path.resolve(__dirname, "..", "..");
    const scriptPath = path.join(extensionRoot, "backends", "static", "annotations", "annotations.py");
    if (!fs.existsSync(scriptPath)) {
      this.skip();
      return;
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "annotations-bridge-it-"));
    const binaryPath = path.join(tmpDir, "target.elf");
    fs.writeFileSync(binaryPath, Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60)]));
    const dbPath = path.join(tmpDir, "annotations.db");

    const bridge = makeAnnotationsBridge({
      root: extensionRoot,
      extensionPath: extensionRoot,
      dbPathOverride: dbPath,
      getPythonExecutable: () => process.env.PYTHON_EXECUTABLE || "python3",
      buildPythonEnv: () => ({ ...process.env, PYTHONPATH: extensionRoot }),
    });

    try {
      await bridge.saveAnnotation(binaryPath, "0x401000", { comment: "c", name: "n" });
      await bridge.saveBookmark(binaryPath, "0x401000", { label: "L", color: "#123456" });
      const { annotations: result } = await bridge.deleteAnnotation(binaryPath, "0x401000");

      expect(result["0x401000"].comment).to.equal(undefined);
      expect(result["0x401000"].name).to.equal(undefined);
      expect(result["0x401000"].bookmark).to.equal(true);
      expect(result["0x401000"].bookmarkLabel).to.equal("L");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
