const { expect } = require("chai");
const sinon = require("sinon");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const vscode = require("vscode");

const utils = require("../shared/utils");
const {
  INSTALL_ACTION, LOCK_FILE_NAME, BUILD_LOCK_FILE_NAME, manualInstallCommand, redirectingPipOptions,
} = require("../shared/pythonDependencies");

const EXT_DIR_WITH_SPACES = path.join(path.sep, "opt", "My Extensions", "pile ou face");
const LOCK_FILE = path.join(EXT_DIR_WITH_SPACES, "backends", LOCK_FILE_NAME);
const BUILD_LOCK_FILE = path.join(EXT_DIR_WITH_SPACES, "backends", BUILD_LOCK_FILE_NAME);
const VENV_PATH = path.join(EXT_DIR_WITH_SPACES, "backends", ".venv");
const VENV_PYTHON = path.join(VENV_PATH, "bin", "python3");
const PYTHON_WITH_SPACES = path.join(path.sep, "Applications", "My Python", "bin", "python3");
const OFFLINE_STDERR =
  "WARNING: Retrying (Retry(total=4)) after connection broken by 'NewConnectionError(\"Failed to establish a new connection\")'\n"
  + "ERROR: Could not find a version that satisfies the requirement unicorn==2.1.4";

function argsOf(call) {
  return { file: call.args[0], args: call.args[1] };
}

function pipCalls(execFile) {
  return execFile.getCalls().map(argsOf).filter((c) => c.args[0] === "-m" && c.args[1] === "pip" && c.args[2] === "install");
}

/** Imports manquants ; venv et pip répondent selon `pipError` ; `pipConfig` = sortie de `pip config list`. */
function stubPython(existing, pipError = null, pipConfig = "") {
  return sinon.stub(cp, "execFile").callsFake((_file, args, cb) => {
    if (args[0] === "-c") return cb(new Error("ModuleNotFoundError"), "", "");
    if (args[1] === "venv") {
      existing.add(VENV_PYTHON);
      return cb(null, "", "");
    }
    if (args[2] === "config") return cb(null, pipConfig, "");
    return pipError ? cb(new Error("exit 1"), "", pipError) : cb(null, "", "");
  });
}

describe("ensurePythonDependencies", () => {
  let existing;
  let execStub;
  let info;
  let warn;
  let previousExtensionPath;

  beforeEach(() => {
    // Shared singleton: other suites (e.g. staticCache) set it at load time.
    previousExtensionPath = utils.getExtensionPath();
    utils.setExtensionPath(EXT_DIR_WITH_SPACES);
    existing = new Set([LOCK_FILE, BUILD_LOCK_FILE]);
    sinon.stub(fs, "existsSync").callsFake((p) => existing.has(p));
    execStub = sinon.stub(cp, "exec");
    info = sinon.stub(vscode.window, "showInformationMessage").resolves(undefined);
    warn = sinon.stub(vscode.window, "showWarningMessage").resolves(undefined);
  });

  afterEach(() => {
    sinon.restore();
    utils.setExtensionPath(previousExtensionPath);
  });

  it("checks imports via execFile with an executable path containing spaces, without prompting when present", async () => {
    const execFile = sinon.stub(cp, "execFile").callsFake((_file, _args, cb) => cb(null, "", ""));

    const status = await utils.ensurePythonDependencies(PYTHON_WITH_SPACES, EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("ok");
    expect(execStub.called).to.equal(false);
    expect(info.called).to.equal(false);
    expect(execFile.getCalls().map(argsOf)).to.deep.equal([
      { file: PYTHON_WITH_SPACES, args: ["-c", "import unicorn"] },
      { file: PYTHON_WITH_SPACES, args: ["-c", "import capstone"] },
    ]);
  });

  it("never runs pip nor creates the venv when the user declines or dismisses the prompt", async () => {
    const execFile = stubPython(existing);

    for (const answer of [undefined, "Later"]) {
      info.resolves(answer);
      const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });
      expect(status).to.equal("declined");
    }

    expect(info.callCount).to.equal(2);
    expect(pipCalls(execFile)).to.deep.equal([]);
    expect(execFile.getCalls().some((c) => c.args[1][1] === "venv")).to.equal(false);
    expect(warn.called).to.equal(false);
  });

  it("after consent, creates the extension venv and runs pip in it with --require-hashes on both lock files", async () => {
    info.resolves(INSTALL_ACTION);
    const execFile = stubPython(existing);

    const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("installed");
    expect(execStub.called).to.equal(false);
    expect(execFile.getCalls().map(argsOf)).to.deep.include({ file: "python3", args: ["-m", "venv", VENV_PATH] });
    const [buildPip, pip, ...extra] = pipCalls(execFile);
    expect(extra).to.deep.equal([]);
    // Build tools first, from their own lock: the main install then never fetches unpinned ones.
    expect(buildPip.file).to.equal(VENV_PYTHON);
    expect(buildPip.args).to.include("--require-hashes");
    expect(buildPip.args.slice(-2)).to.deep.equal(["-r", BUILD_LOCK_FILE]);
    expect(pip.file).to.equal(VENV_PYTHON);
    expect(pip.args).to.include("--require-hashes");
    expect(pip.args).to.include("--no-build-isolation");
    expect(pip.args.slice(-2)).to.deep.equal(["-r", LOCK_FILE]);
    for (const call of [buildPip, pip]) expect(call.args).to.not.include("--break-system-packages");
  });

  it("refuses to install when the pip configuration redirects outside the venv", async () => {
    info.resolves(INSTALL_ACTION);
    const execFile = stubPython(existing, null, ":env:.target='/elsewhere'\ninstall.index-url='https://mirror.example/simple'\n");

    const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("failed");
    expect(pipCalls(execFile)).to.deep.equal([]);
    expect(warn.firstCall.args[0]).to.contain(":env:.target").and.to.not.contain("index-url");
  });

  it("keeps non-redirecting pip settings such as a mirror index or user=false", async () => {
    info.resolves(INSTALL_ACTION);
    const execFile = stubPython(existing, null, "global.index-url='https://mirror.example/simple'\ninstall.user='false'\n");

    expect(await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true })).to.equal("installed");
    expect(pipCalls(execFile)).to.have.length(2);
  });

  it("reuses an existing extension venv without recreating it", async () => {
    existing.add(VENV_PYTHON);
    info.resolves(INSTALL_ACTION);
    const execFile = stubPython(existing);

    const status = await utils.ensurePythonDependencies(VENV_PYTHON, EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("installed");
    expect(execFile.getCalls().some((c) => c.args[1][1] === "venv")).to.equal(false);
    expect(pipCalls(execFile).map((c) => c.file)).to.deep.equal([VENV_PYTHON, VENV_PYTHON]);
  });

  it("reports an offline failure clearly without throwing", async () => {
    info.resolves(INSTALL_ACTION);
    stubPython(existing, OFFLINE_STDERR);

    const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("offline");
    expect(warn.calledOnce).to.equal(true);
    expect(warn.firstCall.args[0]).to.match(/offline/);
    expect(warn.firstCall.args[0]).to.contain("--require-hashes");
  });

  it("reports other pip failures as failed", async () => {
    info.resolves(INSTALL_ACTION);
    stubPython(existing, "ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE.");

    const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("failed");
    expect(warn.firstCall.args[0]).to.not.match(/offline/);
  });

  it("reports venv creation errors with stderr and does not run pip", async () => {
    info.resolves(INSTALL_ACTION);
    const execFile = sinon.stub(cp, "execFile").callsFake((_file, args, cb) =>
      args[0] === "-c" ? cb(new Error("ModuleNotFoundError"), "", "") : cb(new Error("exit 1"), "", "venv boom"));

    const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES);

    expect(status).to.equal("failed");
    expect(pipCalls(execFile)).to.deep.equal([]);
    expect(warn.calledOnce).to.equal(true);
    expect(warn.firstCall.args[0]).to.contain("venv boom");
  });

  it("never installs into a configured interpreter outside the extension venv", async () => {
    const execFile = stubPython(existing);

    const status = await utils.ensurePythonDependencies(PYTHON_WITH_SPACES, EXT_DIR_WITH_SPACES);

    expect(status).to.equal("unavailable");
    expect(info.called).to.equal(false);
    expect(pipCalls(execFile)).to.deep.equal([]);
    expect(warn.firstCall.args[0]).to.contain(LOCK_FILE);
  });

  for (const [label, missing] of [["hash lock file", LOCK_FILE], ["build tools lock file", BUILD_LOCK_FILE]]) {
    it(`does not prompt nor install when the ${label} is missing, and says so even when quiet`, async () => {
      existing.delete(missing);
      const execFile = stubPython(existing);

      const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

      expect(status).to.equal("unavailable");
      expect(info.called).to.equal(false);
      expect(warn.calledOnce).to.equal(true);
      expect(warn.firstCall.args[0]).to.contain(missing);
      expect(pipCalls(execFile)).to.deep.equal([]);
    });
  }

  it("stops before the main install when the build tools cannot be installed", async () => {
    info.resolves(INSTALL_ACTION);
    const execFile = stubPython(existing, OFFLINE_STDERR);

    const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("offline");
    expect(pipCalls(execFile).map((c) => c.args.slice(-1)[0])).to.deep.equal([BUILD_LOCK_FILE]);
  });

  it("ignores a partial system Python and offers the full install when the extension venv is missing", async () => {
    // Python système avec unicorn et capstone, mais sans lief : il ne doit pas suffire.
    const execFile = sinon.stub(cp, "execFile").callsFake((_file, _args, cb) => cb(null, "", ""));

    const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("declined");
    expect(info.calledOnce).to.equal(true);
    expect(execFile.getCalls().some((c) => c.args[0] === "python3" && c.args[1][0] === "-c")).to.equal(false);
  });

  it("checks the extension venv, not the system Python, for a default interpreter name", async () => {
    existing.add(VENV_PYTHON);
    const execFile = sinon.stub(cp, "execFile").callsFake((_file, _args, cb) => cb(null, "", ""));

    const status = await utils.ensurePythonDependencies("python3", EXT_DIR_WITH_SPACES, { quiet: true });

    expect(status).to.equal("ok");
    expect(info.called).to.equal(false);
    expect(execFile.getCalls().map((c) => c.args[0])).to.deep.equal([VENV_PYTHON, VENV_PYTHON]);
  });
});

for (const [lockName, sourceName] of [[LOCK_FILE_NAME, "requirements.txt"], [BUILD_LOCK_FILE_NAME, "requirements-build.txt"]]) describe(`backends/${lockName} (versioned)`, () => {
  const backendsDir = path.resolve(__dirname, "..", "..", "backends");
  const lockPath = path.join(backendsDir, lockName);

  it("is shipped with the extension so the consented install can run", () => {
    expect(fs.existsSync(lockPath), `${lockPath} manquant : voir « Versions vérifiées » dans extension/README.md`)
      .to.equal(true);
  });

  it("pins every package with == and at least one sha256 hash", () => {
    const text = fs.readFileSync(lockPath, "utf8").replace(/\\\r?\n/g, " ");
    const requirements = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    expect(requirements).to.not.be.empty;
    for (const line of requirements) {
      expect(line, line).to.match(/^[A-Za-z0-9._-]+(\[[^\]]+\])?==\S+/);
      expect(line, line).to.match(/--hash=sha256:[0-9a-f]{64}/);
    }
  });

  it(`covers every direct dependency of ${sourceName}`, () => {
    const normalize = (name) => name.toLowerCase().replace(/[-_.]+/g, "-");
    const lockText = fs.readFileSync(lockPath, "utf8");
    const pinned = new Set(Array.from(lockText.matchAll(/^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?==/gm), (m) => normalize(m[1])));
    const direct = fs.readFileSync(path.join(backendsDir, sourceName), "utf8")
      .split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
      .map((l) => normalize(l.split(/[<>=!~;[\s]/)[0]));
    for (const name of direct) expect(pinned.has(name), name).to.equal(true);
  });
});

describe("pip helpers", () => {
  it("detects every option that moves the install destination, from files or PIP_* variables", () => {
    const list = [
      "global.prefix='/a'", "install.target='/b'", ":env:.root='/c'", ":env:.user='1'",
      "install.user='off'", "global.index-url='https://mirror.example/simple'", "global.cert='/ca.pem'",
    ].join("\n");
    expect(redirectingPipOptions(list)).to.deep.equal(["global.prefix", "install.target", ":env:.root", ":env:.user"]);
  });

  it("gives two separate commands, with the PowerShell call operator on Windows", () => {
    const locks = { build: "C:\\ext\\build.lock", main: "C:\\ext\\main.lock" };
    const win = manualInstallCommand("C:\\ext\\.venv\\Scripts\\python.exe", locks, "win32");
    expect(win).to.not.contain("&&");
    expect(win.match(/& "C:\\ext\\.venv\\Scripts\\python.exe" -m pip install --require-hashes/g)).to.have.length(2);
    expect(manualInstallCommand("/v/bin/python3", locks, "linux")).to.not.contain("&");
  });
});
