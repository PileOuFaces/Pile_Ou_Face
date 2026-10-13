const { expect } = require("chai");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

describe("mcpSetupBridge", () => {
  function makeBridge(runPythonStub) {
    return proxyquire("../shared/mcpSetupBridge", {
      "./pythonRunner": { makeRunPython: () => runPythonStub },
    });
  }

  it("preview calls setup_cli.py with --json --dry-run and parses stdout", async () => {
    const payload = { dry_run: true, project_dir: "/proj", actions: [{ agent: "Claude Code", path: "/proj/.mcp.json" }] };
    const runPythonStub = sinon.stub().resolves({ stdout: JSON.stringify(payload) });
    const bridge = makeBridge(runPythonStub).makeMcpSetupBridge({ root: "/r", extensionPath: "/e" });
    const result = await bridge.preview("claude", "/proj", "project");
    expect(result).to.deep.equal(payload);
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members([
      "backends/mcp/setup_cli.py", "--json",
      "--agent", "claude", "--project-dir", "/proj", "--scope", "project", "--dry-run",
    ]);
  });

  it("apply calls setup_cli.py with --json and no --dry-run", async () => {
    const runPythonStub = sinon.stub().resolves({ stdout: JSON.stringify({ dry_run: false, project_dir: "/proj", actions: [] }) });
    const bridge = makeBridge(runPythonStub).makeMcpSetupBridge({ root: "/r", extensionPath: "/e" });
    await bridge.apply("all", "/proj", "project");
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["--agent", "all", "--project-dir", "/proj", "--scope", "project"]);
    expect(args).to.not.include("--dry-run");
  });

  it("rollback calls setup_cli.py with --rollback and parses restored/errors", async () => {
    const payload = { restored: [{ agent: "claude", path: "/proj/.mcp.json" }], errors: [] };
    const runPythonStub = sinon.stub().resolves({ stdout: JSON.stringify(payload) });
    const bridge = makeBridge(runPythonStub).makeMcpSetupBridge({ root: "/r", extensionPath: "/e" });
    const result = await bridge.rollback("claude", "/proj", "project");
    expect(result).to.deep.equal(payload);
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include("--rollback");
  });

  it("doctor calls setup_cli.py with --doctor and parses the diagnosis", async () => {
    const payload = {
      interpreter: "/usr/bin/python3.11", interpreter_version: "3.11", interpreter_is_fallback: false,
      handshake_ok: true, protocol_version: "2024-11-05", error: null,
    };
    const runPythonStub = sinon.stub().resolves({ stdout: JSON.stringify(payload) });
    const bridge = makeBridge(runPythonStub).makeMcpSetupBridge({ root: "/r", extensionPath: "/e" });
    const result = await bridge.doctor("/proj");
    expect(result).to.deep.equal(payload);
    const args = runPythonStub.firstCall.args[0];
    expect(args).to.include.members(["--project-dir", "/proj", "--doctor"]);
    expect(args).to.not.include("--agent");
  });
});
