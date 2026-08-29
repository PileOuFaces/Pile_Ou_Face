const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");

describe("staticHandlers functions radar", () => {
  it("loads symbols, calling conventions and radar together", async () => {
    const posted = [];
    const execFile = (pythonExe, args, opts, cb) => {
      const script = args[0];
      if (script.endsWith("backends/static/binary/symbols.py")) {
        cb(null, JSON.stringify({ symbols: [{ addr: "0x401000", name: "entry", type: "T", size: 32 }] }), "");
        return;
      }
      if (script.endsWith("backends/static/disasm/calling_convention.py")) {
        cb(null, JSON.stringify({ conventions: { "0x401000": { convention: "sysv" } } }), "");
        return;
      }
      if (script.endsWith("backends/static/analysis/function_radar.py")) {
        cb(null, JSON.stringify({ summary: { function_count: 1 }, functions: [{ addr: "0x401000", priority_score: 61 }] }), "");
        return;
      }
      cb(new Error(`unexpected script: ${script}`));
    };

    const staticHandlers = proxyquire("../static/staticHandlers", {
      vscode: {},
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({ PATH: process.env.PATH || "" }),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
      "./pluginState": {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (value) => value,
      },
    });

    const handlers = staticHandlers({
      root: "/repo",
      panel: { webview: { postMessage: (msg) => posted.push(msg) } },
      context: { globalState: { get: () => ({}) } },
    });

    await handlers.hubLoadFunctions({ binaryPath: "/tmp/demo.bin" });

    expect(posted).to.have.length(1);
    expect(posted[0].type).to.equal("hubFunctionsDone");
    expect(posted[0].data.symbols).to.deep.equal({
      symbols: [{ addr: "0x401000", name: "entry", type: "T", size: 32 }],
    });
    expect(posted[0].data.cc).to.deep.equal({
      conventions: { "0x401000": { convention: "sysv" } },
    });
    expect(posted[0].data.radar).to.deep.equal({
      summary: { function_count: 1 },
      functions: [{ addr: "0x401000", priority_score: 61 }],
    });
    expect(posted[0].data.diagnostics.map((entry) => entry.name)).to.deep.equal([
      "symbols",
      "calling_convention",
      "function_radar",
    ]);
    expect(posted[0].data.diagnostics.every((entry) => entry.ok)).to.equal(true);
    expect(posted[0].data.diagnostics[2].stdoutBytes).to.be.greaterThan(0);
  });

  it("surfaces radar subprocess stderr and metadata on failure", async () => {
    const posted = [];
    const execFile = (pythonExe, args, opts, cb) => {
      const script = args[0];
      if (script.endsWith("backends/static/binary/symbols.py")) {
        cb(null, JSON.stringify({ symbols: [] }), "");
        return;
      }
      if (script.endsWith("backends/static/disasm/calling_convention.py")) {
        cb(null, JSON.stringify({ conventions: {} }), "");
        return;
      }
      if (script.endsWith("backends/static/analysis/function_radar.py")) {
        const err = new Error("Command failed: function_radar.py");
        err.code = 1;
        cb(err, "", "Traceback: Cannot open cache database");
        return;
      }
      cb(new Error(`unexpected script: ${script}`));
    };

    const staticHandlers = proxyquire("../static/staticHandlers", {
      vscode: {},
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({ PATH: process.env.PATH || "" }),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
      "./pluginState": {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (value) => value,
      },
    });

    const handlers = staticHandlers({
      root: "/repo",
      panel: { webview: { postMessage: (msg) => posted.push(msg) } },
      context: { globalState: { get: () => ({}) } },
    });

    await handlers.hubLoadFunctions({ binaryPath: "/tmp/demo.bin" });

    expect(posted).to.have.length(1);
    expect(posted[0].type).to.equal("hubFunctionsDone");
    expect(posted[0].data.error).to.include("function_radar");
    expect(posted[0].data.error).to.include("Cannot open cache database");
    expect(posted[0].data.diagnostics).to.have.length(3);
    const radarDiagnostic = posted[0].data.diagnostics.find((entry) => entry.name === "function_radar");
    expect(radarDiagnostic.ok).to.equal(false);
    expect(radarDiagnostic.code).to.equal(1);
    expect(radarDiagnostic.stderrTail).to.include("Cannot open cache database");
  });
});

describe("staticHandlers natural-language function search", () => {
  afterEach(() => sinon.restore());

  function makeHandlers(execFile, posted, warningChoice = "Autoriser") {
    const staticHandlers = proxyquire("../static/staticHandlers", {
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => undefined }) },
        window: { showWarningMessage: async () => warningChoice },
      },
      fs: { existsSync: () => true },
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": { normalizeRawArchName: (value) => value },
      "./pluginState": {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (value) => value,
      },
    });
    return staticHandlers({
      root: "/repo",
      panel: { webview: { postMessage: (message) => posted.push(message) } },
      context: { globalState: { get: () => ({}) } },
    });
  }

  it("checks consent then returns grounded function results", async () => {
    const calls = [];
    const execFile = sinon.stub().callsFake((_python, args, _opts, callback) => {
      calls.push(args);
      if (args[0].endsWith("ai_consent.py")) {
        callback(null, JSON.stringify({ consented: true }), "");
        return;
      }
      callback(null, JSON.stringify({
        ok: true,
        candidate_count: 12,
        results: [{ addr: "0x401000", name: "read_config", score: 93 }],
      }), "");
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted);

    await handlers.hubNaturalLanguageSearch({
      binaryPath: "/tmp/demo.bin",
      query: "où est lue la configuration ?",
    });

    expect(calls[0]).to.include("--check");
    expect(calls[1][0]).to.match(/natural_language_search\.py$/);
    expect(calls[1]).to.include.members(["--query", "où est lue la configuration ?"]);
    expect(posted.at(-1)).to.deep.include({
      type: "hubNaturalLanguageSearchDone",
      binaryPath: "/tmp/demo.bin",
      ok: true,
    });
    expect(posted.at(-1).result.results[0].addr).to.equal("0x401000");
  });

  it("does not contact the search provider when consent is refused", async () => {
    const calls = [];
    const execFile = sinon.stub().callsFake((_python, args, _opts, callback) => {
      calls.push(args);
      callback(null, JSON.stringify({ consented: false }), "");
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted, null);

    await handlers.hubNaturalLanguageSearch({
      binaryPath: "/tmp/demo.bin",
      query: "crypto",
    });

    expect(calls).to.have.length(1);
    expect(posted.at(-1)).to.deep.include({
      type: "hubNaturalLanguageSearchDone",
      ok: false,
      error: "Recherche annulée : consentement refusé.",
    });
  });
});

describe("staticHandlers typed struct preview stale guards", () => {
  function loadHandlers(execFile, posted) {
    const staticHandlers = proxyquire("../static/staticHandlers", {
      vscode: {},
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({ PATH: process.env.PATH || "" }),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
      "./pluginState": {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (value) => value,
      },
    });

    return staticHandlers({
      root: "/repo",
      panel: { webview: { postMessage: (msg) => posted.push(msg) } },
      context: { globalState: { get: () => ({}) } },
    });
  }

  it("posts binaryPath on typed struct preview success", async () => {
    const posted = [];
    const execFile = (_pythonExe, args, _opts, cb) => {
      const script = args[0];
      if (script.endsWith("backends/static/annotations/typed_data.py")) {
        cb(null, JSON.stringify({ entries: [{ name: "field_0" }], sections: [".data"] }), "");
        return;
      }
      cb(new Error(`unexpected script: ${script}`));
    };
    const handlers = loadHandlers(execFile, posted);

    await handlers.hubPreviewTypedStruct({
      binaryPath: "/tmp/current.bin",
      structName: "Elf64_Ehdr",
      structAddr: "0x400000",
    });

    expect(posted).to.have.length(1);
    expect(posted[0]).to.deep.equal({
      type: "hubTypedStructPreviewDone",
      binaryPath: "/tmp/current.bin",
      data: { entries: [{ name: "field_0" }], sections: [".data"] },
      request: {
        structName: "Elf64_Ehdr",
        structAddr: "0x400000",
        binaryPath: "/tmp/current.bin",
      },
    });
  });

  it("posts binaryPath on typed struct preview failure", async () => {
    const posted = [];
    const execFile = (_pythonExe, args, _opts, cb) => {
      const script = args[0];
      if (script.endsWith("backends/static/annotations/typed_data.py")) {
        cb(new Error("typed data crashed"), "", "boom");
        return;
      }
      cb(new Error(`unexpected script: ${script}`));
    };
    const handlers = loadHandlers(execFile, posted);

    await handlers.hubPreviewTypedStruct({
      binaryPath: "/tmp/current.bin",
      structName: "Elf64_Ehdr",
      structAddr: "0x400000",
    });

    expect(posted).to.have.length(1);
    expect(posted[0].type).to.equal("hubTypedStructPreviewDone");
    expect(posted[0].binaryPath).to.equal("/tmp/current.bin");
    expect(posted[0].request).to.deep.equal({
      structName: "Elf64_Ehdr",
      structAddr: "0x400000",
      binaryPath: "/tmp/current.bin",
    });
    expect(posted[0].data.entries).to.deep.equal([]);
    expect(posted[0].data.sections).to.deep.equal([]);
    expect(posted[0].data.error).to.include("typed data crashed");
  });
});
