const { expect } = require("chai");
const path = require("path");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

describe("pythonRunner", () => {
  it("spawns the resolved python executable with the script path and args", async () => {
    const execFileStub = sinon.stub().callsFake((cmd, args, opts, cb) => {
      cb(null, JSON.stringify({ ok: true }), "");
    });
    const pythonRunner = proxyquire("../shared/pythonRunner", {
      child_process: { execFile: execFileStub },
    });
    const runPython = pythonRunner.makeRunPython({ root: "/tmp/root", extensionPath: "/tmp/ext" });
    const { stdout } = await runPython(["backends/foo.py", "--x", "1"]);
    expect(JSON.parse(stdout)).to.deep.equal({ ok: true });
    const [, calledArgs, calledOpts] = execFileStub.firstCall.args;
    expect(calledArgs[0]).to.equal(path.join("/tmp/ext", "backends/foo.py"));
    expect(calledArgs.slice(1)).to.deep.equal(["--x", "1"]);
    expect(calledOpts.cwd).to.equal("/tmp/root");
  });

  it("rejects with stderr attached on non-zero exit", async () => {
    const execFileStub = sinon.stub().callsFake((cmd, args, opts, cb) => {
      cb(new Error("boom"), "", "traceback here");
    });
    const pythonRunner = proxyquire("../shared/pythonRunner", {
      child_process: { execFile: execFileStub },
    });
    const runPython = pythonRunner.makeRunPython({ root: "/tmp/root", extensionPath: "/tmp/ext" });
    try {
      await runPython(["backends/foo.py"]);
      throw new Error("should have rejected");
    } catch (err) {
      expect(err.stderr).to.equal("traceback here");
    }
  });
});
