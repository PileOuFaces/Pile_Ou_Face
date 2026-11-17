const { expect } = require("chai");
const sinon = require("sinon");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const vscode = require("vscode");

const utils = require("../shared/utils");

const EXT_DIR_WITH_SPACES = path.join(path.sep, "opt", "My Extensions", "pile ou face");
const REQUIREMENTS = path.join(EXT_DIR_WITH_SPACES, "backends", "requirements.txt");
const VENV_PATH = path.join(EXT_DIR_WITH_SPACES, "backends", ".venv");
const VENV_PYTHON = path.join(VENV_PATH, "bin", "python3");
const PYTHON_WITH_SPACES = path.join(path.sep, "Applications", "My Python", "bin", "python3");

function argsOf(call) {
  return { file: call.args[0], args: call.args[1] };
}

describe("ensurePythonDependencies", () => {
  let existing;
  let execStub;

  beforeEach(() => {
    utils.setExtensionPath(EXT_DIR_WITH_SPACES);
    existing = new Set([REQUIREMENTS]);
    sinon.stub(fs, "existsSync").callsFake((p) => existing.has(p));
    execStub = sinon.stub(cp, "exec");
  });

  afterEach(() => {
    sinon.restore();
    utils.setExtensionPath("");
  });

  it("checks imports via execFile with an executable path containing spaces as a single argument", async () => {
    const execFile = sinon.stub(cp, "execFile").callsFake((_file, _args, cb) => cb(null, "", ""));

    await utils.ensurePythonDependencies(PYTHON_WITH_SPACES, EXT_DIR_WITH_SPACES, { quiet: true });

    expect(execStub.called).to.equal(false);
    expect(execFile.callCount).to.equal(2);
    expect(argsOf(execFile.getCall(0))).to.deep.equal({ file: PYTHON_WITH_SPACES, args: ["-c", "import unicorn"] });
    expect(argsOf(execFile.getCall(1))).to.deep.equal({ file: PYTHON_WITH_SPACES, args: ["-c", "import capstone"] });
  });

  it("creates the venv via execFile with a venv path containing spaces, then uses the venv python", async () => {
    const execFile = sinon.stub(cp, "execFile").callsFake((_file, args, cb) => {
      if (args[1] === "venv") existing.add(VENV_PYTHON);
      cb(null, "", "");
    });

    await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

    expect(execStub.called).to.equal(false);
    expect(argsOf(execFile.getCall(0))).to.deep.equal({ file: "python3", args: ["-m", "venv", VENV_PATH] });
    expect(argsOf(execFile.getCall(1))).to.deep.equal({ file: VENV_PYTHON, args: ["-c", "import unicorn"] });
  });

  it("reports venv creation errors with stderr and stops before checking imports", async () => {
    const execFile = sinon.stub(cp, "execFile").callsFake((_file, _args, cb) => cb(new Error("exit 1"), "", "venv boom"));
    const warn = sinon.stub(vscode.window, "showWarningMessage");

    await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES);

    expect(execFile.callCount).to.equal(1);
    expect(warn.calledOnce).to.equal(true);
    expect(warn.firstCall.args[0]).to.contain("venv boom");
  });

  it("installs requirements when a dependency import fails", async () => {
    const execFile = sinon.stub(cp, "execFile").callsFake((_file, args, cb) => {
      if (args[0] === "-c") return cb(new Error("ModuleNotFoundError"), "", "");
      return cb(null, "", "");
    });

    await utils.ensurePythonDependencies(PYTHON_WITH_SPACES, EXT_DIR_WITH_SPACES, { quiet: true });

    expect(execStub.called).to.equal(false);
    expect(execFile.callCount).to.equal(2);
    const install = argsOf(execFile.getCall(1));
    expect(install.file).to.equal(PYTHON_WITH_SPACES);
    expect(install.args.slice(0, 5)).to.deep.equal(["-m", "pip", "install", "-r", REQUIREMENTS]);
  });
});
