const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");

describe("autoBuildAtActivation", () => {
  let fakeVscode;
  let fs;
  let child_process;
  let extension;

  beforeEach(() => {
    fs = require("fs");

    fakeVscode = {
      workspace: { workspaceFolders: [{ uri: { fsPath: "/ws" } }] },
      window: { createOutputChannel: () => ({ appendLine: () => {} }) },
    };

    // We'll stub execSync and inject it via proxyquire
    const execSpy = sinon.stub();
    extension = proxyquire("../src/extension", {
      vscode: fakeVscode,
      child_process: { execSync: execSpy },
    });
    this.execSpy = execSpy;
  });

  afterEach(() => {
    sinon.restore();
  });

  it.skip("runs make if Makefile exists and compiles src/sim", async () => {
    // Setup fs.existsSync to return true for Makefile and sim dir and outPath
    const existsStub = sinon.stub(fs, "existsSync").callsFake((p) => {
      // Simulate workspace root and related paths present
      if (typeof p === "string" && p.startsWith("/ws")) return true;
      return false;
    });

    sinon.stub(fs, "readdirSync").callsFake((p) => {
      if (p === "/ws/src/sim") return ["one.c", "two.c"];
      return [];
    });

    // Use injected execSpy to emulate cc --version, make, compile
    this.execSpy.callsFake((cmd, opts) => Buffer.from("ok"));

    await extension.autoBuildAtActivation("/ws", { fsPath: "/ext" });

    // Ensure execSync was called
    expect(this.execSpy.called).to.be.true;

    // Check we attempted cc --version (or equivalent) at least once
    const versionCall = this.execSpy
      .getCalls()
      .some(
        (c) => typeof c.args[0] === "string" && /--version/.test(c.args[0]),
      );
    expect(versionCall).to.be.true;

    // Check we attempted `make` or a compile
    const madeCall = this.execSpy.calledWith("make", sinon.match.object);
    const compiledCall = this.execSpy
      .getCalls()
      .some(
        (c) =>
          typeof c.args[0] === "string" &&
          (/-Wall/.test(c.args[0]) || /asm2json/.test(c.args[0])),
      );
    expect(madeCall || compiledCall).to.be.true;

    existsStub.restore();
  });
});
